#pragma once

#include <Windows.h>

#include "MapImage.h"


namespace PEUtils
{
	bool ValidateExecutable(const char* PELocation);

	bool StoreFileInMemory(const char* PELocation, BYTE* & PEBuffer);

	const char* CheckArchitecture(WORD MachineID);

	void PrintSections(PEStructure* PEInfo);
}
