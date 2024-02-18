#include <iostream>


#include <Windows.h>

#include "MapImage.h"
#include "StringFormatting.h"
#include "Utils.h"

// lets learn the windows PE Structure

int main(int argc, char* argv[])
{
	// Check args
	if (argc < 2)
	{
		std::cout << "Missing Path Argument" << "\n";
		return 1;
	}

	std::string FilePath = argv[1];

	printf(Title, FilePath.c_str());

	if (!PEUtils::ValidateExecutable(FilePath.c_str()))
	{
		return 1;
	}

	BYTE* PEBuffer = nullptr;
	PEUtils::StoreFileInMemory(FilePath.c_str(), PEBuffer);

	if (!PEBuffer)
	{
		return 1;
	}

	PEStructure PEInfo(PEBuffer);

	// Lets Start Printing Binary Info
	printf(DosHeader,
		PEInfo.DOSHeader->e_magic,
		PEInfo.DOSHeader->e_lfanew);

	printf(FileHeader,
		PEUtils::CheckArchitecture(PEInfo.FileHeader->Machine),
		PEInfo.FileHeader->NumberOfSections,
		PEInfo.FileHeader->Characteristics,
		PEInfo.FileHeader->SizeOfOptionalHeader);

	printf(OptionalHeader,
		PEInfo.OptionalHeader->SizeOfCode,
		PEInfo.OptionalHeader->BaseOfCode,
		PEInfo.OptionalHeader->BaseOfData,
		PEInfo.OptionalHeader->AddressOfEntryPoint,
		PEInfo.OptionalHeader->ImageBase,
		PEInfo.OptionalHeader->SizeOfImage,
		PEInfo.OptionalHeader->DllCharacteristics);

	PEUtils::PrintSections(&PEInfo);

	// Lets Get Section Header i guessch

	/*
	 * IMAGE_DOS_HEADER
	 * IMAGE_OPTIONAL_HEADER
	 * IMAGE_FILE_HEADER
	 */

	delete[] PEBuffer;

	return 0;
}
