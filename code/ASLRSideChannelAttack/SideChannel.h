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

#pragma once
#include "stdafx.h"
#include <Windows.h>
#include <intrin.h>
#include <vector>  
#include <algorithm>

// Included /FORCE:MULTIPLE as a LINKER OPTION

UINT DIFFERENCE_THRESHOLD;
#define MEDIAN_SAMPLES 20
#define ITERATIONS 100000
#define NUMBER_OF_PAGE_PROBES 5
#define PAGE_SIZE 0x1000
#define MAX_UNMAPPED_TRIES 3
#define MAX_MISTAKES 7 // Number of gods (of the new ones)
//#define KNOWN_MAPPED 0xffffffffffd00000
#define KNOWN_UNMAPPED 0x0000000000000000
#define MAGIC_ADDRESS 0x100804020000
#define MAGIC_UNMAPPED 0xFFFFFFFFFFFFF000


PVOID KNOWN_MAPPED = NULL;
std::vector<PVOID> v_pages;

typedef struct _PML4_SELF_REF {
	UINT64 VirtualAddress;
	UINT32 Index;
	UINT32 UnamppedCount;
} PML4_SELF_REF, *PPML4_SELF_REF;

std::vector<PPML4_SELF_REF> pml4_self_ref_potential_array;
std::vector<PPML4_SELF_REF> pml4_self_ref_final_array;
//UINT64 auto_ref_pml4_array[0x100];
UINT32 ConsistencyCounter = 0;

// The idea of the next two is to accelerate the algorithm in the case of consistencies
// If a lot of errors happens AFTER a PML4 was already found, the result is saved for
// the next iteration

typedef UINT64(*_PFN_SIDE_CHANNEL)(PVOID);
_PFN_SIDE_CHANNEL pfn_side_channel = NULL;

float get_average(PVOID lpAddress, UINT iterations);
bool comp_function(int i, int j);
float get_median(PVOID lpAddress);
BOOL veryfy_pml4_entries_forwards(float unmapped_time, float mapped_time);
void test_get_median(void);