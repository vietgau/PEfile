
#include <stdio.h>
#include <Windows.h>
#include "Header.h"


int main(/*char argc,LPCWCH argv[]*/)
{
	HANDLE hFile, hMap;
	LPVOID fileData;
	DWORD fileSize, byteRead;
	PIMAGE_DOS_HEADER dosHeader;
	//if (argc != 2)
	//	Error("nhap vao: PEfile <PE file>", FALSE, TRUE, 1);
	//L"C:\\Users\\vietvh4\\OneDrive - actvn.edu.vn\\works\\PEfille\\PEfile\\x64\\Debug\\Utility_4_0_64.dll"
	hFile = CreateFile(L"C:\\Users\\vietvh4\\OneDrive - actvn.edu.vn\\works\\PEfille\\PEfile\\x64\\Debug\\Utility_4_0_64.dll", GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		Error("khong tao duoc file", TRUE, TRUE, 1);
	//fileSize = GetFileSize(hFile, NULL);
	//fileData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	//if (!ReadFile(hFile, fileData, fileSize, &byteRead, NULL)) {
	//	Error("khong lay duoc data file", TRUE, TRUE, 1);
	//}

	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	fileData = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	dosHeader = (PIMAGE_DOS_HEADER)fileData;

	printDosHeader(dosHeader);
	printNTHeader(dosHeader);
	printDataDirectory(dosHeader);
	printSectionHeader(dosHeader);
	printExportDir(dosHeader, TRUE);
	PrintInportDir( dosHeader, TRUE);

	CloseHandle(hFile);
	UnmapViewOfFile(fileData);
	CloseHandle(hMap);
	getchar();
}
void Error(const char* ErrorMessage, BOOL printErrorCode, BOOL isReturn, int exitCode) {
	printf(ErrorMessage);
	if (printErrorCode)
		printf(" \n Error: %d \n", GetLastError());
	getchar();
	if (isReturn)
		ExitProcess(exitCode);
}
VOID printDosHeader(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset = 0;
	printf("\nDOS_HEADER\n");
	printf("e_magic | offset: %4X | valua: %4X \n", offset, dosHeader->e_magic);
	offset = (sizeof(IMAGE_DOS_HEADER) - sizeof(dosHeader->e_lfanew));
	printf("e_lfanew| offset: %4X | valua: %4X \n", offset, dosHeader->e_lfanew);
}
VOID printNTHeader(IMAGE_DOS_HEADER* dosHeader) {
	printf("\nNT_HEADER\n");
	printNTSignature(dosHeader);
	printFileHeader(dosHeader);
	printOptionHeader(dosHeader);
}
VOID printNTSignature(IMAGE_DOS_HEADER* dosHeader) {
	int offset;
	PIMAGE_NT_HEADERS ntHeader;
	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	offset = dosHeader->e_lfanew;
	printf("\nNT_Signature\n");
	printf("Signature | offset: %4X | valua: %4X \n", offset, ntHeader->Signature);
}
VOID printFileHeader(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset;
	IMAGE_FILE_HEADER fileHeader;
	PIMAGE_NT_HEADERS ntHeader;
	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	fileHeader = ntHeader->FileHeader;
	printf("\nFile_Header\n");
	offset = dosHeader->e_lfanew + sizeof(ntHeader->Signature);
	printf("File header Machine | ofset: %4X | valua: %4X \n", offset, fileHeader.Machine);
	offset += sizeof(fileHeader.Machine);
	printf("File header NumberOfSections | offset: %4X | valua: %4X \n", offset, fileHeader.NumberOfSections);
	offset += sizeof(fileHeader.NumberOfSections);
	printf("File header TimeDateStamp | offset: %4X | valua: %4X \n", offset, fileHeader.TimeDateStamp);
	offset += sizeof(fileHeader.TimeDateStamp);
	printf("File header PointerToSymbolTable | offset: %4X | valua: %4X \n", offset, fileHeader.PointerToSymbolTable);
	offset += sizeof(fileHeader.PointerToSymbolTable);
	printf("File header NumberOfSymbols | offset: %4X | valua: %4X \n", offset, fileHeader.NumberOfSymbols);
	offset += sizeof(fileHeader.NumberOfSymbols);
	printf("File header SizeOfOptionalHeader | offset: %4X | valua: %4X \n", offset, fileHeader.SizeOfOptionalHeader);
	offset += sizeof(fileHeader.SizeOfOptionalHeader);
	printf("File header Characteristics | offset: %4X | valua: %4X \n", offset, fileHeader.Characteristics);
	

}
VOID printOptionHeader(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset;
	IMAGE_OPTIONAL_HEADER optionHeader;
	PIMAGE_NT_HEADERS ntHeader;
	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	optionHeader = ntHeader->OptionalHeader;
	printf("\nOption_Header\n");
	offset = dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER);
	printf("Magic | offset: %4X | valua: %4X \n", offset, optionHeader.Magic);
	offset += sizeof(optionHeader.Magic);
	printf("MajorLinkerVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MajorLinkerVersion);
	offset += sizeof(optionHeader.MajorLinkerVersion);
	printf("MinorLinkerVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MinorLinkerVersion);
	offset += sizeof(optionHeader.MinorLinkerVersion) ;
	printf("SizeOfCode | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfCode);
	offset += sizeof(optionHeader.SizeOfCode);
	printf("SizeOfInitializedData | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfInitializedData);
	offset += sizeof(optionHeader.SizeOfInitializedData);
	printf("SizeOfUninitializedData | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfUninitializedData);
	offset += sizeof(optionHeader.SizeOfUninitializedData);
	printf("AddressOfEntryPoint | offset: %4X | valua: %4X \n", offset, optionHeader.AddressOfEntryPoint);
	offset += sizeof(optionHeader.AddressOfEntryPoint);
	printf("BaseOfCode | ofset: %4X | valua: %4X \n", offset, optionHeader.BaseOfCode);
	offset += sizeof(optionHeader.BaseOfCode);
	printf("ImageBase | offset: %4X | valua: %4X \n", offset, optionHeader.ImageBase);
	offset += sizeof(optionHeader.ImageBase);
	printf("SectionAlignment | offset: %4X | valua: %4X \n", offset, optionHeader.SectionAlignment);
	offset += sizeof(optionHeader.SectionAlignment);
	printf("FileAlignment | offset: %4X | valua: %4X \n", offset, optionHeader.FileAlignment);
	offset += sizeof(optionHeader.FileAlignment);
	printf("MajorOperatingSystemVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MajorOperatingSystemVersion);
	offset += sizeof(optionHeader.MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MinorOperatingSystemVersion);
	offset += sizeof(optionHeader.MinorOperatingSystemVersion);
	printf("MajorImageVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MajorImageVersion);
	offset += sizeof(optionHeader.MajorImageVersion);
	printf("MinorImageVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MinorImageVersion);
	offset += sizeof(optionHeader.MinorImageVersion);
	printf("MajorSubsystemVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MajorSubsystemVersion);
	offset += sizeof(optionHeader.MajorSubsystemVersion);
	printf("MinorSubsystemVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MinorSubsystemVersion);
	offset += sizeof(optionHeader.MinorSubsystemVersion);
	printf("Win32VersionValue | offset: %4X | valua: %4X \n", offset, optionHeader.Win32VersionValue);
	offset += sizeof(optionHeader.Win32VersionValue);
	printf("SizeOfImage | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfImage);
	offset += sizeof(optionHeader.SizeOfImage);
	printf("SizeOfHeaders | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfHeaders);
	offset += sizeof(optionHeader.SizeOfHeaders);
	printf("CheckSum | offset: %4X | valua: %4X \n", offset, optionHeader.CheckSum);
	offset += sizeof(optionHeader.CheckSum);
	printf("Subsystem | offset: %4X | valua: %4X \n", offset, optionHeader.Subsystem);
	offset += sizeof(optionHeader.Subsystem);
	printf("DllCharacteristics | offset: %4X | valua: %4X \n", offset, optionHeader.DllCharacteristics);
	offset += sizeof(optionHeader.DllCharacteristics);
	printf("SizeOfStackReserve | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfStackReserve);
	offset += sizeof(optionHeader.SizeOfStackReserve);
	printf("SizeOfStackCommit | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfStackCommit);
	offset += sizeof(optionHeader.SizeOfStackCommit);
	printf("SizeOfHeapReserve | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfHeapReserve);
	offset += sizeof(optionHeader.SizeOfHeapReserve);
	printf("SizeOfHeapCommit | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfHeapCommit);
	offset += sizeof(optionHeader.SizeOfHeapCommit);
	printf("LoaderFlags | offset: %4X | valua: %4X \n", offset, optionHeader.LoaderFlags);
	offset += sizeof(optionHeader.LoaderFlags);
	printf("NumberOfRvaAndSizes | offset: %4X | valua: %4X \n", offset, optionHeader.NumberOfRvaAndSizes);
	offset += sizeof(optionHeader.NumberOfRvaAndSizes);

	//printf("DataDirectory | offset: %4X | valua: %4X \n", offset, optionHeader.DataDirectory);
	//offset += sizeof(optionHeader.DataDirectory);

}
VOID printDataDirectory(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_DATA_DIRECTORY dataDir;
	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	dataDir = ntHeader->OptionalHeader.DataDirectory;
	printf("\nDataDirectory\n");
	offset = dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + (ntHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_DATA_DIRECTORY) * 16);
	for (int i = 0;i < 16; i++)
	{
		printf("VirtualAddress [%d] | offset: %4X | valua: %4X \n", i, offset, dataDir[i].VirtualAddress);
		offset += sizeof(dataDir[i].VirtualAddress);
		printf("Size [%d] | offset: %4X | valua: %4X \n",i, offset, dataDir[i].Size);
		offset += sizeof(dataDir[i].Size);
		printf("\n");
	}
}
VOID printSectionHeader(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset, numberOfSection;
	IMAGE_FILE_HEADER fileHeader;
	PIMAGE_SECTION_HEADER sectionHeader;
	PIMAGE_NT_HEADERS ntHeader;

	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)ntHeader + sizeof(IMAGE_NT_HEADERS));
	fileHeader = ntHeader->FileHeader;
	numberOfSection = fileHeader.NumberOfSections;
	offset = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	printf("\nSectionHeader\n ");
	for (int i = 0 ; i < numberOfSection; i++) {
		printf(" Name of section : %4X\n ", sectionHeader[i].Name);
		offset += sizeof(sectionHeader[i].Name);
		printf("VirtualSize[%d] | offset: %4X | valua: %4X \n ",i,  offset,  sectionHeader[i].Misc.VirtualSize);
		offset += sizeof(sectionHeader[i].Misc.VirtualSize);
		printf("VirtualAddress[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].VirtualAddress);
		offset += sizeof(sectionHeader[i].VirtualAddress);
		printf("SizeOfRawData[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].SizeOfRawData);
		offset += sizeof(sectionHeader[i].SizeOfRawData);
		printf("PointerToRawData[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].PointerToRawData);
		offset += sizeof(sectionHeader[i].PointerToRawData);
		printf("PointerToRelocations[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].PointerToRelocations);
		offset += sizeof(sectionHeader[i].PointerToRelocations);
		printf("PointerToLinenumbers[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].PointerToLinenumbers);
		offset += sizeof(sectionHeader[i].PointerToLinenumbers);
		printf("NumberOfRelocations[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].NumberOfRelocations);
		offset += sizeof(sectionHeader[i].NumberOfRelocations);
		printf("NumberOfLinenumbers[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].NumberOfLinenumbers);
		offset += sizeof(sectionHeader[i].NumberOfLinenumbers);
		printf("Characteristics[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].Characteristics);
		offset += sizeof(sectionHeader[i].Characteristics);
		printf("\n");

	}
	
}
	

VOID printExportDir(IMAGE_DOS_HEADER* dosHeader, BOOL isPrint) {
	DWORD offset;
	PIMAGE_DATA_DIRECTORY dataDirectory;
	PIMAGE_EXPORT_DIRECTORY exportDirectory;
	PIMAGE_SECTION_HEADER sectionHeader;
	PIMAGE_NT_HEADERS ntHeader = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	dataDirectory = ntHeader->OptionalHeader.DataDirectory;
	exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(RVAToOffset(dosHeader,dataDirectory[0].VirtualAddress)  + (DWORD64)dosHeader);
	offset = (DWORD)exportDirectory - (DWORD)dosHeader;

	printf("\nExportDir\n");
	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0) {

		printf("Characteristics | offset: %4X | valua: %4X \n",offset, exportDirectory->Characteristics);
		offset += sizeof(exportDirectory->Characteristics);
		printf("TimeDateStamp | offset: %4X | valua: %4X \n",offset, exportDirectory->TimeDateStamp);
		offset += sizeof(exportDirectory->TimeDateStamp);
		printf("MajorVersion | offset: %4X | valua: %4X \n",offset , exportDirectory->MajorVersion);
		offset += sizeof(exportDirectory->MajorVersion);
		printf("MinorVersion | offset: %4X | valua: %4X \n",offset , exportDirectory->MinorVersion);
		offset += sizeof(exportDirectory->MinorVersion);
		printf("Name | offset: %4X | valua: %4X \n",offset , exportDirectory->Name);
		offset += sizeof(exportDirectory->Name);
		printf("Base | offset: %4X | valua: %4X \n",offset , exportDirectory->Base);
		offset += sizeof(exportDirectory->Base);
		printf("NumberOfFunctions | offset: %4X | valua: %4X \n",offset , exportDirectory->NumberOfFunctions);
		offset += sizeof(exportDirectory->NumberOfFunctions);
		printf("NumberOfNames | offset: %4X | valua: %4X \n",offset , exportDirectory->NumberOfNames);
		offset += sizeof(exportDirectory->NumberOfNames);
		printf("AddressOfFunctions | offset: %4X | valua: %4X \n",offset , exportDirectory->AddressOfFunctions);
		offset += sizeof(exportDirectory->AddressOfFunctions);
		printf("AddressOfNames | offset: %4X | valua: %4X \n",offset , exportDirectory->AddressOfNames);
		offset += sizeof(exportDirectory->AddressOfNames);
		printf("AddressOfNameOrdinals | offset: %4X | valua: %4X \n",offset , exportDirectory->AddressOfNameOrdinals);
		offset += sizeof(exportDirectory->AddressOfNameOrdinals);

		if (isPrint) {
			DWORD* addressFunction = (DWORD*)(RVAToOffset( dosHeader, exportDirectory->AddressOfFunctions) + (DWORD64)dosHeader);
			DWORD* addressName = (DWORD*)(RVAToOffset(dosHeader, exportDirectory->AddressOfNames) + (DWORD64)dosHeader);
			WORD* addressNameOrdinal = (WORD*)(RVAToOffset( dosHeader, exportDirectory->AddressOfNameOrdinals) + (DWORD64)dosHeader);

			printf("\n%-41s%-11s%-10s\n", "  EXPORT FUNCTION", "FuncRVA", "NameRVA");
			for (int i = 0; i < exportDirectory->NumberOfFunctions; i++) {
				if (addressFunction[i] == 0)continue;
				BOOL named = FALSE;
				for (int j = 0; j < exportDirectory->NumberOfNames; j++) {
					if (addressNameOrdinal[j] == i) {
						named = TRUE;
						char* name = (char*)(RVAToOffset(dosHeader, addressName[j]) + (DWORD64)dosHeader);
						printf("  %-5x%-33s|%-8X|%-8X\n", i + exportDirectory->Base, name, addressFunction[i], addressName[j]);
						break;
					}
				}
				if (!named) {
					printf("  %-5x%-33s|%-8X\n", i + exportDirectory->Base, "", addressFunction[i]);
				}
			}
		}
	}
}


VOID PrintInportDir(IMAGE_DOS_HEADER* dosHeader, BOOL isPrint) {
	PIMAGE_IMPORT_DESCRIPTOR importDirectory;
	PIMAGE_DATA_DIRECTORY dataDirectory;
	PIMAGE_NT_HEADERS64 ntHeader = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	DWORD offset;
	dataDirectory = ntHeader->OptionalHeader.DataDirectory;
	importDirectory = (IMAGE_IMPORT_DESCRIPTOR*)(RVAToOffset( dosHeader,dataDirectory[1].VirtualAddress) + (DWORD64)dosHeader);
	offset = (DWORD64)importDirectory - (DWORD64)dosHeader;
	printf("\nInportDir\n");
	
	while (importDirectory->Name != 0) {
		printf("\n\n");
		printf("%-40s|%-8llX\n", (char*)RVAToOffset( dosHeader,importDirectory->Name) + (DWORD64)dosHeader, RVAToOffset(dosHeader,importDirectory->Name));
		printf("OriginalFirstThunk | offset: %4X | valua: %4X \n", offset, importDirectory->OriginalFirstThunk);
		offset += sizeof(importDirectory->OriginalFirstThunk);
		printf("TimeDateStamp | offset: %4X | valua: %4X \n", offset, importDirectory->TimeDateStamp);
		offset += sizeof(importDirectory->TimeDateStamp);
		printf("ForwarderChain | offset: %4X | valua: %4X \n", offset, importDirectory->ForwarderChain);
		offset += sizeof(importDirectory->ForwarderChain);
		printf("Name | offset: %4X | valua: %4X \n", offset, importDirectory->Name);
		offset += sizeof(importDirectory->Name);
		printf("FirstThunk | offset: %4X | valua: %4X \n", offset, importDirectory->FirstThunk);
		offset += sizeof(importDirectory->FirstThunk);

		DWORD64 thunkRVA = importDirectory->OriginalFirstThunk == 0 ? importDirectory->FirstThunk : importDirectory->OriginalFirstThunk;
		IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(RVAToOffset(dosHeader,thunkRVA) + (DWORD64)dosHeader);
		if (isPrint) {
			printf("%-41s%-9s%-9s%-10s\n", "   IMPORT FUNCTION", "Offset", "Hint", "OFTs");
			while (thunk->u1.AddressOfData != 0) {

				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
					printf("    %-36s|%-8llX|%-8llX\n", "", thunk->u1.Ordinal, thunk->u1.Function);
				}
				else {
					DWORD nameImportOffset = RVAToOffset(dosHeader,thunk->u1.AddressOfData);
					IMAGE_IMPORT_BY_NAME* nameImport = (IMAGE_IMPORT_BY_NAME*)(nameImportOffset + (DWORD64)dosHeader);
					printf("    %-36s|%-8X|%-8X|%-8llX\n", nameImport->Name, nameImportOffset, nameImport->Hint, thunk->u1.Ordinal);
				}
				thunk++;
			}
		}
		importDirectory++;
	}
}

DWORD RVAToOffset(IMAGE_DOS_HEADER* dosHeader, DWORD dwRVA)
{
	int i;
	WORD wSections;
	PIMAGE_SECTION_HEADER pSectionHdr;
	IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((DWORD64)dosHeader + dosHeader->e_lfanew);
	/* Map first section */
	pSectionHdr = IMAGE_FIRST_SECTION(ntHeader);
	wSections = ntHeader->FileHeader.NumberOfSections;

	for (i = 0; i < wSections; i++)
	{
		if (pSectionHdr->VirtualAddress <= dwRVA)
			if ((pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize) > dwRVA)
			{
				dwRVA -= pSectionHdr->VirtualAddress;
				dwRVA += pSectionHdr->PointerToRawData;

				return (dwRVA);
			}

		pSectionHdr++;
	}
	return (0);
}