#pragma once

const char* Title = "------- %s -------\n";

const char* DosHeader =
		"------- DOS Header ------- \n"
		"Magic Byte		> %X\n"
		"PE Section Offset	> 0x%x\n\n";

const char* FileHeader =
		"------- File Header -------\n"
		"Binary Architecture > %s\n"
		"Number of Sections  > %d\n\n";
//"Optional Header Size > %d\n";

const char* OptionalHeader =
		"------- Optional Header -------\n"
		//"Linker Version > %d.%d\n"
		"Size Of Code	> %d\n"
		".Text Base	> 0x%X\n"
		".Data Base	> 0x%X\n"
		"Entry Point	> 0x%X\n"
		"Image Base	> 0x%X\n"
		"Image Size	> %d\n"
		"DLL Characteristics > %x\n\n";
