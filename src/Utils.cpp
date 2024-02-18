#include "Utils.h"

#include <iostream>
#include <fstream>
#include <Windows.h>


bool PEUtils::ValidateExecutable(const char* PELocation)
{
	const unsigned char MagicByteStorage[2] = {};
	const unsigned char WindowsMagicByte[2] = { 0x4D, 0x5A };

	// Read first two bytes in file and validate MZ / ELF Header... Linux eventually?
	std::ifstream File(PELocation, std::ios::binary);

	if (File.fail())
	{
		std::cout << "Error opening " << PELocation << ", Exiting!!" << "\n";
		exit(1);
	}

	File.seekg(0, std::ios::beg);

	// Store two first bytes into Byte Storage & Compare
	File.read((char*)MagicByteStorage, sizeof(MagicByteStorage));

	int WindowsResult = memcmp(MagicByteStorage, WindowsMagicByte, sizeof(MagicByteStorage));

	if (WindowsResult)
	{
		std::cout << "Invalid PE File... Exiting" << "\n";
		File.close();
		return false;
	}

	File.close();
	return true;
}

bool PEUtils::StoreFileInMemory(const char* PELocation, BYTE* & PEBuffer)
{
	unsigned char* FileStorage;

	std::ifstream File(PELocation, std::ios::binary | std::ios::ate);

	if (File.fail())
		return false;

	// Setup Buffer for FileStorage & store info in said buffer
	int FileSize = File.tellg();
	PEBuffer = new BYTE[static_cast<UINT_PTR>(FileSize)];

	ZeroMemory(PEBuffer, sizeof(PEBuffer));

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(PEBuffer), FileSize);
	File.close();

	return true;
}

const char* PEUtils::CheckArchitecture(WORD MachineID)
{
	const char* Name = "Unknown";

	switch (MachineID)
	{
	case IMAGE_FILE_MACHINE_I386:
		Name = "X86 Binary";
		break;
	case IMAGE_FILE_MACHINE_IA64:
		Name = "X64 Binary";
		break;
	}

	return Name;
}

void PEUtils::PrintSections(PEStructure* PEInfo)
{
	const char* SectionInfo = "------- Section Information -------\n";
	const char* SectionFormat =
			"Section Name    > %s\n"
			"Virtual Address > 0x%x\n"
			"Section Size    > %d\n"
			"\n\n";

	printf(SectionInfo);
	for (unsigned int i = 0; i < PEInfo->FileHeader->NumberOfSections; i++)
	{
		printf(SectionFormat,
			PEInfo->SectionHeader[i].Name,
			PEInfo->SectionHeader[i].VirtualAddress,
			PEInfo->SectionHeader[i].SizeOfRawData);
	}
}
