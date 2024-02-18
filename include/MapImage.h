#pragma once

#include <Windows.h>

// lets make a hex macro cause printing to hex is fucky :/
#define HEX(x) std::hex << int(x)

// DOS header for Windows DOS version & PE Header for more modern Windows Version

typedef struct _DOS_HEADER_Reference
{
	// WORD = 0x2 Bytes
	// http://stixproject.github.io/data-model/1.2/WinExecutableFileObj/DOSHeaderType/
	// https://chuongdong.com/reverse%20engineering/2020/08/15/PE-Parser/
	// http://www.tavi.co.uk/phobos/exeformat.html#checksum.
	WORD e_magic; // PE Magic Bytes // 0x0
	WORD e_cblp; // Bytes to Align each section in the PE File // 0x2
	WORD e_cp; // Number of Memory Pages to hold the file, Equals TotalFile/Pagesize Rounding Up // 0x4
	WORD c_cric; // Number of Relocation Items // 0x6
	WORD e_cparhdr; // size of the executable header in paragraphs (blocks of memory which are 16 bytes long) // 0x8
	WORD e_minialloc; // Minimum size of Paragraphs needed to begin execution // 0xA
	WORD e_maxalloc; // Maximum size of Paragraphs needed to begin execution // 0xC
	WORD e_ss; // Specifies what the initial SS (Stack Segment) offset value should start at // 0xE
	WORD e_sp; // Species what the intial SP (Stack Pointer) offset value should start at // 0x10
	WORD e_csum; // Specifies the checksum of the executable file // 0x12
	WORD e_ip; // Specifies what the initial IP (Index Pointer) value needs to be // 0x14
	WORD e_cs; // Specifies the pre-located initial CS (Code Segment) Value, relative to address of start segment // 0x16
	WORD e_lfarlc; // Relative Start Address of the Relocation Table from start of file to relocation pointer table // 0x18
	WORD e_ovrol; // Specifies the overlay number, normally set to 0 // 0x1A
	WORD Resevered1[4]; // Reserved Value // 0x1C
	WORD e_oemid; // Specifies the identier for the OEM for e_oeminfo // 0x1E
	WORD e_oeminfo; // Specifies the OEM information for a specific value of e_oeminfo // 0x20
	WORD Reserved2[10]; // Reserved Value // 0x34
	LONG e_lfanew; // Specifies the start address of the PE Header // 0x36
} DOS_HEADER, *PDOS_HEADER; // size of DOS header is 0x40

/*
 * PE Structure Summarised
 *
 * - DOS Header - IMAGE_DOS_HEADER
 * - DOS String
 * - PE Signature - NT_HEADER->SIGNATURE
 * - File Header - NT_HEADER->IMAGE_FILE_HEADER
 * - Optional Header - NT_HEADER->IMAGE_OPTIONAL_HEADER
 * - Directory Section Header - IMAGE_SECTION_HEADER
 * - CODE EXECUTION SECTION
 */


class PEStructure
{
private:
	BYTE* FileBuffer;

public:
	/*
	 * NT Headers is a struct which contains the following values in top to bottom order
	 * PE Signature // 0x4 Bytes (PE) String
	 * Image File Header // 0x16 Bytes
	 * Optional Header // The Rest...
	 *
	 */
	DOS_HEADER* DOSHeader = nullptr;
	IMAGE_SECTION_HEADER* SectionHeader = nullptr;
	IMAGE_NT_HEADERS* NTHeader = nullptr;

	// Map the Image File Header & Optional Header into its own variable for convinience
	IMAGE_FILE_HEADER* FileHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* OptionalHeader = nullptr;


	PEStructure(BYTE* FBuffer)
	{
		FileBuffer = FBuffer;
		// File Base + e_lfanew value ie offset to the PE Section
		DOSHeader = reinterpret_cast<DOS_HEADER*>(FileBuffer);


		NTHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<DOS_HEADER*>(FileBuffer)->e_lfanew + FileBuffer);
		FileHeader = &NTHeader->FileHeader;
		OptionalHeader = &NTHeader->OptionalHeader;

		// Time to find the Directory Section :) FUck me life
		SectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			reinterpret_cast<DOS_HEADER*>(FileBuffer)->e_lfanew + FileBuffer // Location of PE Section
			+ sizeof(NTHeader->Signature) // Past the PE Symbol
			+ sizeof(NTHeader->FileHeader) // Past the File Header Section
			+ sizeof(FileHeader->SizeOfOptionalHeader) // Past the Optional Section
		);


		SectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			reinterpret_cast<DOS_HEADER*>(FileBuffer)->e_lfanew + FileBuffer // up to PE
			+ sizeof(NTHeader->FileHeader) + sizeof(NTHeader->Signature) // Up to Optional
			+ FileHeader->SizeOfOptionalHeader);
	}

	~PEStructure()
	{
		delete[] FileBuffer;
	}
};
