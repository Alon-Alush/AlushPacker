
/**
 * @file loader.c
 *
 * Purpose: Reflectively loading our payload after decryption and decompression
 *
 * Description is available at https://github.com/Alon-Alush/AlushPacker
 *
 * E-mail: alonalush5@gmail.com
 *
 * LICENSE:
 *
 * Copyright (c) 2025 Alon Alush
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */


#define _CRT_SECURE_NO_WARNINGS	
#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <winternl.h>
#include "lzav.h"
#include "decrypt.h"
#include "payload.h"
#include "structs.h"
#include <Wtsapi32.h>
#include <winnt.h>
#include <CRTDBG.H>
#define ROTATE_BITS 3
 // For debugging the unpacker with a static payload
 //#define DEBUG_STUB
typedef NTSTATUS(__stdcall* pZwAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);
typedef NTSTATUS(__stdcall* pLdrLoadDll) (
	PWCHAR PathToFile,
	ULONG Flags,
	PUNICODE_STRING ModuleFileName,
	PHANDLE ModuleHandle
	);
typedef void(__stdcall* pRtlInitUnicodeString) (
	PUNICODE_STRING	DestinationString,
	PCWSTR SourceString
	);
#ifdef _WIN64
typedef BOOLEAN(__stdcall* pRtlAddFunctionTable) (
	PRUNTIME_FUNCTION FunctionTable,
	DWORD EntryCount,
	DWORD64 BaseAddress
	);
#endif

/*void __stdcall RtlInitAnsiString(ANSI_STRING* DestinationString, PCSZ SourceString) {

	int i = 0;
	DestinationString->Length = i;

	if (SourceString == NULL) {
		return;
	}
	DestinationString->Buffer = SourceString;
	while (SourceString[i] != '\0') {
		i++;
	}
	DestinationString->Length = i;
	DestinationString->MaximumLength = i + 1;
}*/


NTSTATUS __fastcall LdrpParseForwarderDescription(LPCSTR forwarderString, LPCSTR* forwardedDllName, PCHAR* forwardedFunctionName, PWORD Ordinal) {
	const char* localForwarder = _strdup(forwarderString);
	char* dot = strrchr(localForwarder, '.');
	if (dot != NULL) {

		DWORD_PTR length = (DWORD_PTR)dot - (DWORD_PTR)localForwarder;
		// USHORT_MAX
		if (length <= (WORD)0xffff) {
			*dot = '\0';

			*forwardedDllName = localForwarder;
			if (*(dot + 1) == '#') {
				*Ordinal = (WORD)strtoul(dot + 2, 0, 10);
			}
			else {
				*forwardedFunctionName = dot + 1;
			}


			// STATUS_SUCCESS
			return 0;
		}
	}
	// STATUS_INVALID_IMAGE_FORMAT
	return 3221225595LL;
}


void* mymemcpy(void* dst, const void* src, size_t len)
{
	char* ds = (char*)dst;
	const char* sr = (const char*)src;
	while (len--)
	{
		*ds++ = *sr++;
	}
	return dst;
}

HMODULE myGetModuleHandle(LPCSTR ModuleName) {
#ifdef _WIN64
	MYPEB* pPeb = (MYPEB*)__readgsqword(0x60);

#else
	MYPEB* pPeb = (MYPEB*)__readfsdword(0x30);
#endif

	if (ModuleName == NULL) {
		return pPeb->ImageBaseAddress;
	}
	PEB_LDR_DATA* loaderData = (PEB_LDR_DATA*)pPeb->Ldr;
	LIST_ENTRY* ModuleListHead = &loaderData->InMemoryOrderModuleList;
	LIST_ENTRY* ModuleEntry = ModuleListHead->Flink;
	char inputModule[MAX_PATH] = { 0 };
	strcpy(inputModule, ModuleName);
	if (strncmp(inputModule, "api-", 4) == 0 || strncmp(inputModule, "ext-", 4) == 0) {
		// input module is an API set, let's resolve it

		API_SET_NAMESPACE_ARRAY* apiSetMap = (API_SET_NAMESPACE_ARRAY*)pPeb->ApiSetMap;
		for (size_t i = 0; i < apiSetMap->Count; i++) {
			char apiSetName[MAX_PATH] = { 0 };
			char dllName[MAX_PATH] = { 0 };
			size_t oldValueLen = 0;
			API_SET_NAMESPACE_ENTRY* Entry = (API_SET_NAMESPACE_ENTRY*)apiSetMap + apiSetMap->Start;

			// So there's a Count numbers of descriptor arrays


		}

	}
	if (strrchr(inputModule, '.') == NULL) {
		// add .dll extension
		strcat(inputModule, ".dll");
	}

	wchar_t wideInputModule[MAX_PATH] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, inputModule, MAX_PATH, wideInputModule, MAX_PATH);
	for (LIST_ENTRY* ListEntry = ModuleEntry; ListEntry != ModuleListHead; ListEntry = ListEntry->Flink) {
		MYLDR_DATA_TABLE_ENTRY* dataTableEntry = CONTAINING_RECORD(ListEntry, MYLDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		PWCHAR wideTargetModule = dataTableEntry->BaseDllName.Buffer;
		if (_wcsicmp(wideInputModule, wideTargetModule) == 0) {
			return (HMODULE)dataTableEntry->DllBase;
		}
	}

	return NULL;
}
#ifndef DEBUG_STUB
packed_section* findPackedSection() {
	// located our packed section
	HMODULE myModule = myGetModuleHandle(NULL);
	if (myModule == NULL) {
		return NULL;
	}
	const char* sectionName = ".packed";
	IMAGE_DOS_HEADER* selfDosHeader = (IMAGE_DOS_HEADER*)myModule;
	IMAGE_NT_HEADERS* selfNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)myModule + selfDosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* selfSection = IMAGE_FIRST_SECTION(selfNtHeaders);
	for (int i = 0; i < selfNtHeaders->FileHeader.NumberOfSections; i++, selfSection++) {
		if (strcmp(selfSection->Name, sectionName) == 0) {
			// found the packed section containing the encrypted + compressed data
			return (packed_section*)((DWORD_PTR)myModule + selfSection->VirtualAddress);
		}
	}
	return NULL;
}
#endif

WORD __stdcall LdrpNameToOrdinal(LPCSTR importName, LPVOID imageBase, PIMAGE_EXPORT_DIRECTORY exportDir) {
	DWORD NumberOfNames = exportDir->NumberOfNames;
	WORD ordinal = 0;
	PDWORD nameTable = (PDWORD)((unsigned char*)imageBase + exportDir->AddressOfNames); // Export Name Table
	PWORD namesOrdinal = (PWORD)((unsigned char*)imageBase + exportDir->AddressOfNameOrdinals);
	// let's do binary search
	const char* name = NULL;
	LONG low, high, middle, result;

	middle = 0;
	low = 0;
	high = NumberOfNames;
	WORD ordinal = 0;
	while (low <= high) {
		middle = low + ((high - low) / 2);
		name = (unsigned char*)imageBase + nameTable[middle];
		result = strcmp(name, importName);
		if (result > 0) {
			high = middle - 1;
		}
		else if (result < 0) {
			low = middle + 1;
		}
		else {
			// found it
			ordinal = namesOrdinal[middle];
			return ordinal;
		}

	}
	return 0;
}

FARPROC LdrpResolveProcedureAddress(HMODULE hModule, LPCSTR lpProcName, PWORD Ordinal) {

	LPVOID dllBase = (LPVOID)hModule;

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((unsigned char*)dllBase);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((unsigned char*)dllBase + dosHeader->e_lfanew);

	IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((DWORD_PTR)dosHeader + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // Export Address Table

	PDWORD exportAddr = (PDWORD)((unsigned char*)dllBase + exportDir->AddressOfFunctions);
	FARPROC functionAddr = NULL;
	DWORD functionRVA = 0;
	DWORD ordinal;
	if (lpProcName) {
		// import by name
		ordinal = LdrpNameToOrdinal(lpProcName, dllBase, exportDir);
	}
	else {
		// import by ordinal
		ordinal = *Ordinal;
	}
	if (ordinal == 0) {
		return NULL;
		// ordinal was not found
	}
	functionRVA = exportAddr[ordinal];
	if (functionRVA > ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && functionRVA < ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
		// parse, call ourselves with the new values
		LPCSTR forwardedDllName, forwardedFunctionName = NULL;
		NTSTATUS status = LdrpParseForwarderDescription((const char*)dllBase + functionRVA, &forwardedDllName, &forwardedFunctionName, &ordinal);
		if (status) {
			return NULL;
		}
		functionAddr = LdrpResolveProcedureAddress(GetModuleHandleA(forwardedDllName), forwardedFunctionName, &ordinal);
	}

	else {
		functionAddr = (FARPROC)((unsigned char*)dllBase + functionRVA);
	}
	return functionAddr;

}
FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	if (lpProcName == NULL || hModule == NULL) {
		return NULL;
	}
	if (HIWORD(lpProcName) == 0) {
		// ordinal
		WORD ordinal = HIWORD(lpProcName);
		return LdrpResolveProcedureAddress(hModule, NULL, &ordinal);
	}
	else {
		return LdrpResolveProcedureAddress(hModule, lpProcName, NULL);
	}

}

HMODULE MyLoadLibrary(LPCSTR lpFileName) {
	WCHAR lpFileNameWide[MAX_PATH];
	MultiByteToWideChar(CP_ACP, 0, lpFileName, MAX_PATH, lpFileNameWide, MAX_PATH);
	UNICODE_STRING unicodeModule;
	HANDLE hModule = NULL;
	HMODULE ntdll = myGetModuleHandle("ntdll.dll");

	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)myGetProcAddress(ntdll, "RtlInitUnicodeString");
	RtlInitUnicodeString(&unicodeModule, lpFileNameWide);

	pLdrLoadDll myLdrLoadDll = (pLdrLoadDll)myGetProcAddress(ntdll, "LdrLoadDll");
	if (myLdrLoadDll == NULL) {
		return NULL;
	}

	NTSTATUS status = myLdrLoadDll(NULL, 0, &unicodeModule, &hModule);
	return (HMODULE)hModule;
}

LPVOID myVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	HMODULE ntdll = myGetModuleHandle("ntdll.dll");
	if (ntdll == NULL) {
		return NULL;
	}
	pZwAllocateVirtualMemory myAllocateVirtualMemory = (pZwAllocateVirtualMemory)myGetProcAddress(ntdll, "ZwAllocateVirtualMemory");
	if (myAllocateVirtualMemory == NULL) {
		return NULL;
	}
	NTSTATUS status = myAllocateVirtualMemory(GetCurrentProcess(), &lpAddress, 0, &dwSize, flAllocationType, flProtect);
	if (status < 0) {
		return NULL;
	}
	return lpAddress;

}
#ifdef DEBUG_STUB
unsigned char* decompressPayload(size_t unpacked_size) {

#else
unsigned char* decompressPayload(unsigned char* packed_payload, size_t unpacked_size, size_t packed_size) {
#endif

	unsigned char* decomp_buf = myVirtualAlloc(NULL, unpacked_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (decomp_buf == NULL) {
		fprintf(stderr, "Could not allocate memory for decompressed buffer!\n");
		return NULL;
	}
	uint32_t key[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 }; // 128 bit key
	decrypt_payload(packed_payload, packed_size, key);
	lzav_decompress(packed_payload, decomp_buf, (const int)packed_size, (const int)unpacked_size);
	return decomp_buf;
}

IMAGE_TLS_DIRECTORY* GetTlsDirectory(LPVOID imageBase) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)imageBase);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDir.Size) {

		IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)((DWORD_PTR)imageBase + tlsDir.VirtualAddress);
		return tlsDirectory;
	}
	return NULL;

}


DWORD GetTlsIndex(LPVOID imageBase) {

	
	IMAGE_TLS_DIRECTORY* tlsDirectory = GetTlsDirectory(imageBase);
	DWORD* tlsIndexAddress = (DWORD*)(tlsDirectory->AddressOfIndex); // This is an absolute VA
	if (tlsIndexAddress == NULL) {
		return 0;
	}
	return *tlsIndexAddress;
}

LPVOID CreateTlsData(IMAGE_TLS_DIRECTORY* tlsDirectory) {

	size_t rawSize = tlsDirectory->EndAddressOfRawData - tlsDirectory->StartAddressOfRawData;
	size_t virtualSize = rawSize + tlsDirectory->SizeOfZeroFill;
	LPVOID dataBlock = myVirtualAlloc(NULL, virtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!dataBlock) {
		return NULL;
	}
	if (rawSize > 0 && tlsDirectory->StartAddressOfRawData != 0) {
		memcpy(dataBlock, (LPVOID)tlsDirectory->StartAddressOfRawData, rawSize);

		if (tlsDirectory->SizeOfZeroFill > 0) {
			memset((LPVOID)((DWORD_PTR)dataBlock + rawSize), 0, tlsDirectory->SizeOfZeroFill);
		}
	}
	return dataBlock;

}

void SetTlsData(LPVOID tlsData, DWORD tlsIndex) {
	MYTEB* pTeb = (MYTEB*)NtCurrentTeb();
	if (pTeb) {
		if (tlsIndex < 64) {
			//return (LPVOID)((DWORD_PTR*)pTeb->ThreadLocalStoragePointer)[tlsIndex];
			((DWORD_PTR*)pTeb->ThreadLocalStoragePointer)[tlsIndex] = (DWORD_PTR)tlsData;

		}
		else if (pTeb->TlsExpansionSlots) {
			pTeb->TlsExpansionSlots[tlsIndex - 64] = tlsData;
		}

		else {
			pTeb->TlsExpansionSlots = (PVOID*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DWORD_PTR) * 1024);
		}
	}
}

LPVOID GetTlsData(DWORD tlsIndex) {

	MYTEB* pTeb = (MYTEB*)NtCurrentTeb();

	if (pTeb) {
		if (tlsIndex < 64) {
			return (LPVOID)((DWORD_PTR*)pTeb->ThreadLocalStoragePointer)[tlsIndex];
		}
		else if (pTeb->TlsExpansionSlots) {
			return pTeb->TlsExpansionSlots[tlsIndex - 64];
		}
	}
	return NULL;
}

void SetTlsIndex(PIMAGE_TLS_DIRECTORY tlsDirectory, DWORD index) {
	DWORD* targetIndex = (PDWORD)tlsDirectory->AddressOfIndex;
	if (targetIndex) {
		return;
	}
	*targetIndex = index;

}

void InitializeTlsIndex(LPVOID imageBase, DWORD index) {

	IMAGE_TLS_DIRECTORY* tlsDirectory = GetTlsDirectory(imageBase);
	SetTlsIndex(tlsDirectory, index);
}

void InitializeTlsData(LPVOID imageBase, DWORD index) {

	IMAGE_TLS_DIRECTORY* tlsDirectory = GetTlsDirectory(imageBase);
	LPVOID tlsData = CreateTlsData(tlsDirectory);
	if (!tlsData) {
		SetTlsData(tlsData, index);
	}
}


void executeCallbacks(LPVOID imageBase, DWORD Reason, PVOID Context) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)imageBase);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDir.Size) {

		IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)((DWORD_PTR)imageBase + tlsDir.VirtualAddress);
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tlsDirectory->AddressOfCallBacks;

		IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)((DWORD_PTR)imageBase + tlsDir.VirtualAddress);
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tlsDirectory->AddressOfCallBacks;

		if (callback) {
			while (*callback) {
				// Execute each TLS callback with DLL_PROCESS_ATTACH
				(*callback)(imageBase, Reason, Context);
				callback++;
			}
		}
	}
}

void ClearTlsData(DWORD tlsIndex) {
	if (tlsIndex == TLS_OUT_OF_INDEXES) {
		return;
	}
	LPVOID tlsData = GetTlsData(tlsIndex);
	if (!tlsData) {
		VirtualFree(tlsData, 0, MEM_RELEASE);
	}
	SetTlsData(tlsIndex, NULL);
}


/*void __stdcall TlsProxy(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
	if (Reason == DLL_THREAD_DETACH)
	{
		ExecuteCallbacks(DllHandle, Reason, Reserved);
		ClearTlsData();
	}
	else if (dwReason == DLL_THREAD_ATTACH)
	{
		_tlsResolver->InitializeTlsData(_peImage);
		_tlsResolver->ExecuteCallbacks(_peImage, dwReason, pContext);
	}
	else if (dwReason == DLL_PROCESS_ATTACH)
	{
		ExecuteCallbacks(DllHandle, Reason, Reserved);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		_tlsResolver->ExecuteCallbacks(_peImage, dwReason, pContext);
	}
}*/

int mapSections(LPVOID imageBase, BYTE* decryptedPE, IMAGE_NT_HEADERS* ntHeaders) {
	
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
	LPVOID sectionVA = NULL;
	mymemcpy(imageBase, decryptedPE, ntHeaders->OptionalHeader.SizeOfHeaders);
	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
		sectionVA = (LPVOID)((DWORD_PTR)imageBase + section->VirtualAddress);
		mymemcpy(sectionVA, (LPVOID)((DWORD_PTR)decryptedPE + section->PointerToRawData), section->SizeOfRawData);

		if (section->Misc.VirtualSize > section->SizeOfRawData) {
			DWORD zeroPadSize = section->Misc.VirtualSize - section->SizeOfRawData;
			memset((LPVOID)(((DWORD_PTR)sectionVA + section->SizeOfRawData)), 0, zeroPadSize);
		}
	}
}

int memoryProtection(LPVOID imageBase, IMAGE_NT_HEADERS* ntHeaders) {

	DWORD characteristic = 0;
	DWORD permission = 0;
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {

		LPVOID sectionVA = (LPVOID)((DWORD_PTR)imageBase + section->VirtualAddress);
		DWORD protect = section->Characteristics;

		BOOL executable = (protect & IMAGE_SCN_MEM_EXECUTE) != 0;
		BOOL readable = (protect & IMAGE_SCN_MEM_READ) != 0;
		BOOL writeable = (protect & IMAGE_SCN_MEM_WRITE) != 0;
		if (!executable && !readable && !writeable)
			protect = PAGE_NOACCESS;
		else if (!executable && !readable && writeable)
			protect = PAGE_WRITECOPY;
		else if (!executable && readable && !writeable)
			protect = PAGE_READONLY;
		else if (!executable && readable && writeable)
			protect = PAGE_READWRITE;
		else if (executable && !readable && !writeable)
			protect = PAGE_EXECUTE;
		else if (executable && !readable && writeable)
			protect = PAGE_EXECUTE_WRITECOPY;
		else if (executable && readable && !writeable)
			protect = PAGE_EXECUTE_READ;
		else if (executable && readable && writeable)
			protect = PAGE_EXECUTE_READWRITE;

		if (protect & IMAGE_SCN_MEM_NOT_CACHED)
			protect |= PAGE_NOCACHE;

		VirtualProtect(sectionVA, section->SizeOfRawData, protect, &protect);
	}
	return 0;

}

LPVOID imageBaseAlloc(BYTE* sourceBase, IMAGE_NT_HEADERS* ntHeaders) {

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->OptionalHeader.SectionAlignment & 1) {
		return NULL;
	}
	LPVOID imageBase = myVirtualAlloc((LPVOID)(ntHeaders->OptionalHeader.ImageBase), ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (imageBase == NULL) {
		// Allocation at preferred base address failed. Let's try to allocate to an OS-chosen location.
		imageBase = myVirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (imageBase == NULL) {
			return NULL;
		}
	}
}

int applyRelocations(LPVOID imageBase, IMAGE_NT_HEADERS* ntHeaders) {

	DWORD_PTR delta = (DWORD_PTR)imageBase - ntHeaders->OptionalHeader.ImageBase;
	if (delta) {
		IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (reloc->VirtualAddress) {
			WORD* relocEntries = (WORD*)((DWORD_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION));
			DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (DWORD i = 0; i < numEntries; i++) {
				WORD type = relocEntries[i] >> 12;
				WORD offset = relocEntries[i] & 0xFFF;
				switch (type) {

				case IMAGE_REL_BASED_ABSOLUTE: {
					break;
				}

				case IMAGE_REL_BASED_DIR64: {
					// 64 bit addresses
					ULONGLONG* patchAddr = (ULONGLONG*)((DWORD_PTR)imageBase + reloc->VirtualAddress + offset);
					*patchAddr += delta;
					break;
				}
				case IMAGE_REL_BASED_HIGHLOW: {
					DWORD* patchAddr = (DWORD*)((DWORD_PTR)imageBase + reloc->VirtualAddress + offset);
					*patchAddr += (DWORD)delta;
					break;
				}
				case IMAGE_REL_BASED_HIGH: {
					WORD* patchAddr = (WORD*)((DWORD_PTR)imageBase + reloc->VirtualAddress + offset);
					*patchAddr += HIWORD((DWORD)delta);
					break;
				}
				case IMAGE_REL_BASED_LOW: {
					WORD* patchAddr = (WORD*)((DWORD_PTR)imageBase + reloc->VirtualAddress + offset);
					*patchAddr += LOWORD((DWORD)delta);
					break;
				}
				default: {
					break;
				}
				}
			}
			reloc = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)reloc + reloc->SizeOfBlock);
		}
		return 0;
	}
}

LPVOID executePE(BYTE* decryptedPE) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)decryptedPE;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(decryptedPE + dosHeader->e_lfanew);

	LPVOID imageBase = imageBaseAlloc(decryptedPE, ntHeaders);

	if (imageBase == NULL) {
		fprintf(stderr, "Failed to allocate memory for PE image\n");
	}

	printf("Allocation success! allocated image: %p\n", imageBase);
	mapSections(imageBase, decryptedPE, ntHeaders);
	// Handle relocations if not loaded at preferred base address
	if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) { // If Relocation Directory exists
		applyRelocations(imageBase, ntHeaders);

	}

	IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (importDesc->Name) {
		const char* ModuleName = (const char*)((DWORD_PTR)imageBase + importDesc->Name);
		printf("\nModule: %s\n\n", ModuleName);
		IMAGE_THUNK_DATA* origFirstThunk = (IMAGE_THUNK_DATA*)((DWORD_PTR)imageBase + importDesc->OriginalFirstThunk); // Locate Import Lookup Table 
		IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)((DWORD_PTR)imageBase + importDesc->FirstThunk); // Locate IAT
		HANDLE hDll = MyLoadLibrary(ModuleName);
		if (!hDll) {
			fprintf(stderr, "Failed to load dependency: %s\n", (LPCSTR)((DWORD_PTR)imageBase + importDesc->Name));
			return NULL;
		}
		if (origFirstThunk == NULL) {
			// Handle cases where the Import Address Table serves as the Import Lookup Table
			origFirstThunk = firstThunk;
		}


		while (origFirstThunk->u1.AddressOfData) {
			BYTE* dllBase = (BYTE*)hDll;

			IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)dllBase);
			IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)dllBase + dosHeader->e_lfanew);
			IMAGE_IMPORT_BY_NAME* importName = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)imageBase + origFirstThunk->u1.AddressOfData);
			IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((DWORD_PTR)dosHeader + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // Export Address Table
			PDWORD nameTable = (PDWORD)((DWORD_PTR)dllBase + exportDir->AddressOfNames); // Export Name Table
			PWORD namesOrdinal = (PWORD)((DWORD_PTR)(dllBase + exportDir->AddressOfNameOrdinals));
			FARPROC functionAddr = NULL;

			WORD ordinal = 0;
			const char* name = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(firstThunk->u1.Ordinal)) {
				// Function is imported by ordinal
				ordinal = (WORD)(IMAGE_ORDINAL(firstThunk->u1.Ordinal) - exportDir->Base);

			}

			else {
				// Function is imported by name, but Hint might give us an index to get the ordinal more easily without binary search
				WORD Hint = importName->Hint;
				name = dllBase + nameTable[Hint];
				if (Hint < exportDir->NumberOfNames && strcmp(name, importName->Name) == 0) {
					ordinal = namesOrdinal[Hint];
				}
				else {
					name = importName->Name;
				}

			}
			functionAddr = LdrpResolveProcedureAddress(hDll, name, &ordinal);
			if (ordinal) {
				// resolve function name for debugging
				for (size_t i = 0; i < exportDir->NumberOfNames; i++) {
					if (namesOrdinal[i] == ordinal) {
						name = dllBase + nameTable[i];
					}
				}
			}
			printf("	[+] Resolved function address for %s: %p\n", name, functionAddr);
			firstThunk->u1.Function = (DWORD_PTR)functionAddr; // Populating IAT with resolved addresses after resolving import names
			origFirstThunk++;
			firstThunk++;
		}
		importDesc++;
	}

	// process our delayed imports
	IMAGE_DATA_DIRECTORY delayDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (delayDir.Size) {
		IMAGE_DELAYLOAD_DESCRIPTOR* delayDirectory = (IMAGE_DELAYLOAD_DESCRIPTOR*)((DWORD_PTR)imageBase + delayDir.VirtualAddress);

		while (delayDirectory->DllNameRVA) {

			IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)((DWORD_PTR)imageBase + delayDirectory->ImportAddressTableRVA);

			IMAGE_THUNK_DATA* origFirstThunk = (IMAGE_THUNK_DATA*)((DWORD_PTR)imageBase + delayDirectory->ImportNameTableRVA);
			const char* dllName = (const char*)((DWORD_PTR)imageBase + delayDirectory->DllNameRVA);
			HMODULE module = MyLoadLibrary(dllName);
			while (origFirstThunk->u1.AddressOfData) {

				BYTE* dllBase = (BYTE*)module;
				IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)dllBase;
				IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)dosHeader + dosHeader->e_lfanew);
				IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				IMAGE_IMPORT_BY_NAME* importName = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)imageBase + origFirstThunk->u1.AddressOfData);
				//PDWORD nameTable = (PDWORD)((DWORD_PTR)dllBase + exportDir->AddressOfNames);
				//PWORD ordinalTable = dllBase + exportDir->AddressOfNameOrdinals;
				//PDWORD addressOfFunctions = dllBase + exportDir->AddressOfFunctions;
				//DWORD numberOfNames = exportDir->NumberOfNames;
				WORD ordinal = 0;
				const char* name = NULL;
				FARPROC functionAddr = NULL;

				if (IMAGE_SNAP_BY_ORDINAL(origFirstThunk->u1.Ordinal)) {

					ordinal = (WORD)(IMAGE_ORDINAL(firstThunk->u1.Ordinal) - exportDir->Base);
				}
				else {
					name = importName->Name;
				}

				//printf("Found function imported by name: %s, position: %d\n", importName->Name, ordinal);
				functionAddr = LdrpResolveProcedureAddress(module, name, &ordinal);

				printf("	[+] Resolved function address for %s: %p\n", name, functionAddr);
				firstThunk->u1.Function = (DWORD_PTR)functionAddr; // Populating IAT with resolved addresses after resolving import names
				origFirstThunk++;
				firstThunk++;
			}
			delayDirectory++;

		}

	}

	printf("\nEditing section protections...\n\n");
	// setting memory protections after mapping

	printf("Success!...\n\n");



	// now it's the final steps
	// flush the instruction cache
	BOOL flushCache = FlushInstructionCache(GetCurrentProcess(), NULL, 0);
	// handle TLS calllbacks

	IMAGE_DATA_DIRECTORY tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDir.Size) {

		IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)((DWORD_PTR)imageBase + tlsDir.VirtualAddress);
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tlsDirectory->AddressOfCallBacks;
		PDWORD indexAddr = (PDWORD)tlsDirectory->AddressOfIndex;
		DWORD index = GetTlsIndex(myGetModuleHandle(NULL)); // this is essentially the dreaded "TlsResolver" in fatpack
		InitializeTlsIndex(imageBase, index);
		InitializeTlsData(imageBase, index);
		if (callback) {
			while (*callback) {
				// Execute each TLS callback with DLL_PROCESS_ATTACH
				(*callback)(imageBase, DLL_PROCESS_ATTACH, NULL);
				callback++;
			}
		}
	}
	DWORD_PTR EntryPoint = (DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#ifdef _WIN64
	IMAGE_DATA_DIRECTORY exceptionDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (exceptionDir.Size) {
		DWORD count = exceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
		// Add RtlInsertInvertedFunctionTable support for x86
		PRUNTIME_FUNCTION functionTable = (PRUNTIME_FUNCTION)((DWORD_PTR)imageBase + exceptionDir.VirtualAddress);
		pRtlAddFunctionTable myRtlAddFunctionTable = (pRtlAddFunctionTable)myGetProcAddress(myGetModuleHandle("ntdll.dll"), "RtlAddFunctionTable");
		BOOLEAN status = myRtlAddFunctionTable(functionTable, count, (DWORD64)imageBase);
		if (status) {
			printf("Registered %u entries in runtime function table: %p\n", count, functionTable);
		}
	}
	printf("Original entry point address: %p\n", (BYTE*)(EntryPoint));
#endif
#ifdef _WIN64
	MYPEB* pPeb = (MYPEB*)__readgsqword(0x60);
#elif _WIN32
	MYPEB* pPeb = (MYPEB*)__readfsdword(0x30);
#endif
	PEB_LDR_DATA* loaderData = (PEB_LDR_DATA*)pPeb->Ldr;
	LIST_ENTRY* ModuleListHead = &loaderData->InMemoryOrderModuleList;
	LIST_ENTRY* ModuleEntry = (LIST_ENTRY*)ModuleListHead->Flink;
	MYLDR_DATA_TABLE_ENTRY* dataTableEntry = CONTAINING_RECORD(ModuleEntry, MYLDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	pPeb->ImageBaseAddress = (PVOID)ntHeaders->OptionalHeader.ImageBase;
	dataTableEntry->EntryPoint = (PVOID)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	dataTableEntry->SizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	dataTableEntry->TimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
	dataTableEntry->DllBase = (PVOID)imageBase;
	dataTableEntry->TlsIndex = (USHORT)TLS_OUT_OF_INDEXES;

	return (LPVOID)EntryPoint;
}

int main() {
#ifdef DEBUG_STUB

	size_t unpacked_size = 441198;

	LPVOID EntryPoint = executePE(decompressPayload(unpacked_size));
#else 

	ppacked_section packed_section = findPackedSection();
	if (packed_section == NULL) {
		printf("Could not locate .packed section. This unpacker mostly serves as a template; make sure you're using the builder!\n");
		return 1;
	}
	size_t unpacked_size = packed_section->unpacked_size;
	unsigned char* packed_payload = packed_section->payload;

	LPVOID EntryPoint = executePE(decompressPayload(packed_payload, unpacked_size, packed_section->packed_size));

#endif
	if (!EntryPoint) {
		return 1;
	}

	int (*ep)() = EntryPoint;

	int result = ep();

	return result;
}