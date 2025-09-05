
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
#include "encryptdebug.h"
#include "structs.h"
#include <Wtsapi32.h>
#include "definitions.h"
//#include "tls.h"
#include <winnt.h>
#include <CRTDBG.H>
#define ROTATE_BITS 3
 // For debugging the unpacker with a static payload
 #define DEBUG_STUB

uint32_t DJB2_hash(const unsigned char* buf, size_t size) {
	uint32_t hash = 5381;
	for (size_t i = 0; i < size; i++)
		hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + byte */
	return hash;
}
LPVOID globalImageBase = NULL;
LPVOID globalSizeOfImage = NULL;
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




BYTE* compressAndEncrypt(BYTE* inputFile, DWORD fileSize, DWORD* returnCompressedSize) {

	int max_size = lzav_compress_bound(fileSize);
	BYTE* compressed_buffer = malloc(max_size);
	if (compressed_buffer == NULL) {
		return NULL;
	}
	printf("[+] File compression started!\n");

	int comp_len = lzav_compress_default(inputFile, compressed_buffer, fileSize, max_size);
	printf("[+] Compression finished!\n");
	uint32_t key[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 }; // 128 bit key
	encrypt_payload(compressed_buffer, comp_len, key);
	*returnCompressedSize = comp_len;

	printf("[+] Encryption successful!\n");


	return compressed_buffer;
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

		API_SET_NAMESPACE_ARRAY* apiSetSchema = (API_SET_NAMESPACE_ARRAY*)pPeb->ApiSetMap;
		for (size_t i = 0; i < apiSetSchema->Count; i++) {
			char apiSetName[MAX_PATH] = { 0 };
			char dllName[MAX_PATH] = { 0 };
			size_t oldValueLen = 0;
			API_SET_NAMESPACE_ENTRY* Entry = (API_SET_NAMESPACE_ENTRY*)apiSetSchema + apiSetSchema->Start;
			PAPI_SET_VALUE_ARRAY pHostArray = (PAPI_SET_VALUE_ARRAY)((PUCHAR)apiSetSchema +
				apiSetSchema->Start + sizeof(API_SET_VALUE_ARRAY) * apiSetSchema->Size);

			
			// So there's a Count numbers of descriptor arrays


		}

	}
	if (strrchr(inputModule, '.') == NULL) {
		// add .dll extension
		strcat(inputModule, ".dll");
	}

	wchar_t wideInputModule[MAX_PATH] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, inputModule, MAX_PATH, wideInputModule, MAX_PATH);
	for (ModuleEntry; ModuleEntry != ModuleListHead; ModuleEntry = ModuleEntry->Flink) {
		MYLDR_DATA_TABLE_ENTRY* dataTableEntry = CONTAINING_RECORD(ModuleEntry, MYLDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

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
LPCSTR LdrpOrdinalToName(WORD ordinal, LPVOID imageBase, PIMAGE_EXPORT_DIRECTORY exportDir) {

	DWORD NumberOfNames = exportDir->NumberOfNames;
	PDWORD nameTable = (PDWORD)((unsigned char*)imageBase + exportDir->AddressOfNames); // Export Name Table
	PWORD namesOrdinal = (PWORD)((unsigned char*)imageBase + exportDir->AddressOfNameOrdinals);
	const char* name = NULL;

	// let's do linear search
	for (size_t i = 0; i < exportDir->NumberOfNames; i++) {
		if (namesOrdinal[i] == ordinal) {
		name = (const char*)imageBase + nameTable[i];
		}
	}
	return name;
}
WORD __stdcall LdrpNameToOrdinal(LPCSTR importName,DWORD NumberOfNames, LPVOID imageBase, PDWORD nameTable, PWORD namesOrdinal) {

	LONG low, high, middle, result;

	middle = 0;
	low = 0;
	high = NumberOfNames;
	while (low <= high) {
		middle = low + ((high - low) / 2);
		char* name = (const char*)imageBase + nameTable[middle];
		result = strcmp(name, importName);
		if (result > 0) {
			high = middle - 1;
		}
		else if (result < 0) {
			low = middle + 1;
		}
		else {
			// found it
		    WORD ordinal = namesOrdinal[middle];
			return ordinal;
		}

	}
	return (USHORT)-1;
}

FARPROC LdrpResolveProcedureAddress(HMODULE hModule, LPCSTR lpProcName, PWORD Ordinal) {
	if (hModule == NULL) {
		return NULL;
	}
	LPVOID dllBase = (LPVOID)hModule;

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((unsigned char*)dllBase);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((unsigned char*)dllBase + dosHeader->e_lfanew);

	IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((DWORD_PTR)dosHeader + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // Export Address Table

	PDWORD exportAddr = (PDWORD)((unsigned char*)dllBase + exportDir->AddressOfFunctions);
	FARPROC functionAddr = NULL;
	DWORD functionRVA = 0;

	DWORD NumberOfNames = exportDir->NumberOfNames;
	WORD ordinal = 0;
	PDWORD nameTable = (PDWORD)((unsigned char*)dllBase + exportDir->AddressOfNames); // Export Name Table
	PWORD namesOrdinal = (PWORD)((unsigned char*)dllBase + exportDir->AddressOfNameOrdinals);
	if (lpProcName) {
		// import by name

		ordinal = LdrpNameToOrdinal(lpProcName, NumberOfNames, dllBase, nameTable, namesOrdinal);
	}
	else {
		// import by ordinal
		ordinal = *Ordinal;
	}

	if (ordinal >= exportDir->NumberOfFunctions) {
		// invalid ordinal
		return NULL;
	}
	functionRVA = exportAddr[ordinal];
	if (functionRVA > ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && functionRVA < ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
		// parse, call ourselves with the new values
		const char* forwarderString = (const char*)dllBase + functionRVA;
		LPCSTR forwardedDllName, forwardedFunctionName = NULL;
		NTSTATUS status = LdrpParseForwarderDescription(forwarderString, &forwardedDllName, &forwardedFunctionName, &ordinal);

		if (status) {
			return NULL;
		}
		HMODULE forwardedModule = LoadLibraryA(forwardedDllName);
		if (hModule == forwardedModule) {
			// forwarded to itself somehow
			// FUCK MICROSOFT
			// let's load kernelbase
			forwardedModule = LoadLibraryA("kernelbase.dll");
		}
		LoadLibraryA(forwardedDllName);
		functionAddr = LdrpResolveProcedureAddress(forwardedModule, forwardedFunctionName, &ordinal);
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

BOOL myVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {

	HMODULE ntdll = myGetModuleHandle("ntdll.dll");
	if (ntdll == NULL) {
		return FALSE;
	}
	pZwProtectVirtualMemory myProtectVirtualMemory = (pZwProtectVirtualMemory)myGetProcAddress(ntdll, "ZwProtectVirtualMemory");
	if (myProtectVirtualMemory == NULL) {
		return FALSE;
	}
	NTSTATUS status = myProtectVirtualMemory(GetCurrentProcess(), &lpAddress, &dwSize, flNewProtect, lpflOldProtect);
	if (status < 0) {
		return FALSE;
	}
	return TRUE;


}


BOOL myRtlInsertInvertedFunctionTable(LPVOID imageBase, DWORD SizeOfImage) {
	HMODULE ntdll = myGetModuleHandle("ntdll.dll");
	pRtlInsertInvertedFunctionTable myRtlInsertInvertedFunctionTable = (pRtlInsertInvertedFunctionTable)((DWORD_PTR)ntdll + 0x108F0);
	NTSTATUS status = myRtlInsertInvertedFunctionTable(imageBase, SizeOfImage);
	if (status < 0) {
		return FALSE;
	}
	return TRUE;

}

unsigned char* decompressPayload(unsigned char* packed_payload, size_t unpacked_size, size_t packed_size) {

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

/*IMAGE_TLS_DIRECTORY* GetTlsDirectory(LPVOID imageBase) {

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

void SetTlsData(DWORD tlsIndex, LPVOID tlsData) {
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
	if (!targetIndex) {
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
		SetTlsData(index, tlsData);
	}
}


void executeCallbacks(LPVOID imageBase, DWORD Reason, PVOID Context) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)imageBase);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDir.Size) {

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
		return;
	}

	VirtualFree(tlsData, 0, MEM_RELEASE);
	SetTlsData(tlsIndex, NULL);
}
BOOL entryPointCalled = FALSE;

void NTAPI TlsCallbackProxy(PVOID DllBase, DWORD Reason, PVOID Context) {
	if (!entryPointCalled) {
		return;
	}
	switch (Reason) {
		case DLL_PROCESS_ATTACH: {
			executeCallbacks(tlsGlobalBase, Reason, Context);
			break;
		}
		case DLL_PROCESS_DETACH: {
			executeCallbacks(tlsGlobalBase, Reason, Context);
			break;
		}
		case DLL_THREAD_ATTACH: {
			InitializeTlsData(tlsGlobalBase, 0);
			executeCallbacks(tlsGlobalBase, Reason, Context);
			break;
		}

		case DLL_THREAD_DETACH: {

			executeCallbacks(tlsGlobalBase, Reason, Context);
			ClearTlsData(0);
			break;
		}
	}
}*/


BOOL PatchRtlIsValidHandler(HMODULE ntdll) {
	if (!ntdll) {
		return FALSE;
	}
	// RtlIsValidHandler offset from ntdll image base: 0x699C3 (this may change in different versoins; I'm just too lazy to implement a proper solution
	BYTE* RtlIsValidHandlerAddr = (BYTE*)ntdll + 0x699C3;
	BYTE* instructionPatchOpcode = RtlIsValidHandlerAddr + 0x3C22E + 1;
	// je opcode 0x84^
	DWORD oldProtect = 0;
	BOOL status = myVirtualProtect((LPVOID)instructionPatchOpcode, 0x1, PAGE_EXECUTE_READWRITE, &oldProtect);

	if (!status) {
		return FALSE;
	}

	*instructionPatchOpcode += 1; // Patch to jne instead of je
	return TRUE;

}

BOOL PatchWriteFile(HMODULE ntdll) {

}

VOID LdrpMapSectionsOfImage(LPVOID imageBase, BYTE* decryptedPE) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)decryptedPE);

	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)decryptedPE + dosHeader->e_lfanew);
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

BOOL LdrpProtectImage(LPVOID imageBase, IMAGE_NT_HEADERS* ntHeaders) {

	DWORD characteristic = 0;
	DWORD permission = 0;
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
	DWORD newProtect = 0;
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {

		LPVOID sectionVA = (LPVOID)((DWORD_PTR)imageBase + section->VirtualAddress);
		DWORD oldProtect = section->Characteristics;

		BOOL executable = (oldProtect & IMAGE_SCN_MEM_EXECUTE) != 0;
		BOOL readable = (oldProtect & IMAGE_SCN_MEM_READ) != 0;
		BOOL writeable = (oldProtect & IMAGE_SCN_MEM_WRITE) != 0;
		if (!oldProtect & IMAGE_SCN_MEM_EXECUTE && !readable && !writeable)
			newProtect = PAGE_NOACCESS;
		else if (!executable && !readable && writeable)
			newProtect = PAGE_WRITECOPY;
		else if (!executable && readable && !writeable)
			newProtect = PAGE_READONLY;
		else if (!executable && readable && writeable)
			newProtect = PAGE_READWRITE;
		else if (executable && !readable && !writeable)
			newProtect = PAGE_EXECUTE;
		else if (executable && !readable && writeable)
			newProtect = PAGE_EXECUTE_WRITECOPY;
		else if (executable && readable && !writeable)
			newProtect = PAGE_EXECUTE_READ;
		else if (executable && readable && writeable)
			newProtect = PAGE_EXECUTE_READWRITE;

		if (oldProtect & IMAGE_SCN_MEM_NOT_CACHED)
			newProtect |= PAGE_NOCACHE;

		BOOL protectStatus = myVirtualProtect(sectionVA, section->Misc.VirtualSize, newProtect, &oldProtect);
		if (!protectStatus) {
			return FALSE;
		}
		
	}
	return TRUE;

}

VOID LdrpRelocateImage(LPVOID imageBase) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)imageBase);

	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
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
	}

	return 0;
}

VOID LdrpPatchDataTableEntry(MYLDR_DATA_TABLE_ENTRY* dataTableEntry, LPVOID imageBase) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(DWORD_PTR)imageBase;

	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
#ifdef _WIN64
	MYPEB* pPeb = (MYPEB*)__readgsqword(0x60);
#elif _WIN32
	MYPEB* pPeb = (MYPEB*)__readfsdword(0x30);
#endif

	pPeb->ImageBaseAddress = (PVOID)imageBase;
	dataTableEntry->EntryPoint = (PVOID)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	dataTableEntry->SizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	dataTableEntry->TimeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
	dataTableEntry->DllBase = (PVOID)imageBase;
}

/*#ifdef _WIN64
VOID LdrpResolveExceptions(imageBase) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)imageBase);

	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
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

}
//#endif _WIN64

//VOID LdrpResolveLoadConfig(imageBase) {

//	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)imageBase);

//	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
	//*/

LPVOID executePE(BYTE* decryptedPE) {

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)decryptedPE;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(decryptedPE + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->OptionalHeader.SectionAlignment & 1) {
		return NULL;
	}

	LPVOID imageBase = myVirtualAlloc((LPVOID)(ntHeaders->OptionalHeader.ImageBase), ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!imageBase) {

		// Allocation at preferred base address failed. 
		// We can only proceed if relocations exist in the PE headers

		fprintf(stderr, "[-] Could not allocate memory at preferred base address: %p\n", (LPVOID)(ntHeaders->OptionalHeader.ImageBase));
		printf("%d", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		if (!ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {

			// No relocation directory, we cannot reliably load this image.
			fprintf(stderr, "[-] No relocation directory found in PE header! We cannot reliably load this image.\n");
			return NULL;

		}
		// Let's try to allocate to an OS-chosen location.
		imageBase = myVirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		// we will relocate after mapping sections
		if (!imageBase) {
			return NULL;
		}
	}

	printf("Allocation success! allocated image: %p\n", imageBase);

	LdrpMapSectionsOfImage(imageBase, decryptedPE);

	if ((DWORD_PTR)imageBase != ntHeaders->OptionalHeader.ImageBase) {
		// Handle relocations if not loaded at preferred base address

		if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {

			printf("[+] Relocation directory found in PE header!\n");

			LdrpRelocateImage(imageBase);
			printf("Successfully relocated image to: %p\n", imageBase);

		}

	}
	
	globalImageBase = imageBase; // Store the base address of the image globally for TLS handling and exception handling
	globalSizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;


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
		if (importDesc->OriginalFirstThunk == 0) {
			// Handle cases where the Import Lookup Table also serves as the Import Address Table
			origFirstThunk = firstThunk;
		}

		while (origFirstThunk->u1.AddressOfData) {
			BYTE* dllBase = (BYTE*)hDll;
			IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)dllBase);
			IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)dllBase + dosHeader->e_lfanew);
			IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((DWORD_PTR)dosHeader + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // Export Address Table
			PDWORD nameTable = (PDWORD)((DWORD_PTR)dllBase + exportDir->AddressOfNames); // Export Name Table

			IMAGE_IMPORT_BY_NAME* importName = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)imageBase + origFirstThunk->u1.AddressOfData);
			PWORD namesOrdinal = (PWORD)((DWORD_PTR)(dllBase + exportDir->AddressOfNameOrdinals));
			FARPROC functionAddr = NULL;

			WORD ordinal = 0;
			const char* name = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(firstThunk->u1.Ordinal)) {
				// Function is imported by ordinal
				ordinal = (WORD)(IMAGE_ORDINAL(firstThunk->u1.Ordinal) - exportDir->Base);

			}
			else {

				// check for hint
				// credit: Windows Research Kernel
				WORD Hint = importName->Hint;

				if ((ULONG)Hint < exportDir->NumberOfNames && !strcmp((PSZ)importName->Name, (PSZ)((PCHAR)dllBase + nameTable[Hint]))) {

					ordinal = namesOrdinal[Hint];
				}
				else {
					name = importName->Name;
				}

			}

			// unified function for walking export table of dlls
			functionAddr = LdrpResolveProcedureAddress(hDll, name, &ordinal);

			if (name) {

				if (IsBadStringPtrA(name, MAX_PATH) == TRUE) {
					system("pause");
				}
				printf("	[+] Resolved function address for %s: %p\n", name, functionAddr);
			}
			else {

				// resolve function name for debugging
				//name = LdrpOrdinalToName(ordinal, dllBase, exportDir);
				printf("	[+] Resolved function address for %u: %p\n", ordinal, functionAddr);
			}

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
			if (!module) {
				fprintf(stderr, "Failed to load delayed dependency: %s\n", dllName);
				return NULL;
			}
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
				if (ordinal) {
					name = LdrpOrdinalToName(ordinal, dllBase, exportDir);
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

	IMAGE_LOAD_CONFIG_DIRECTORY* configDir = (IMAGE_LOAD_CONFIG_DIRECTORY*)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
	if (configDir->SecurityCookie) {
		// Get the security cookie from the load config directory
#ifdef _WIN64
#define COOKIE_MAX 0x0000FFFFFFFFFFFFll
#define DEFAULT_SECURITY_COOKIE 0x00002B992DDFA232ll
#else
#define DEFAULT_SECURITY_COOKIE 0xBB40E64E
#endif
		if ((configDir->SecurityCookie == DEFAULT_SECURITY_COOKIE) || (configDir->SecurityCookie == 0)) {
			ULONG_PTR newCookie = (ULONG_PTR)GetTickCount64() ^ GetCurrentProcessId();
#ifdef WIN64
			if (newCookie > COOKIE_MAX) {
				newCookie >>= 16;

			}
#endif
			configDir->SecurityCookie = newCookie;

		}
	}
	if (configDir->SEHandlerTable && configDir->SEHandlerCount) {
		// Safe Exception Handler Table
		// Safe Exception Handler Count

		//*FunctionTable = (PVOID)configDir->SEHandlerTable;
		//*TableSize = configDir->SEHandlerCount;
		// Register a custom vectored exception handler to support manual mapped x86 SEH (otherwise invalidated by RtlIValidHandler
	}

#ifdef _WIN64
	IMAGE_DATA_DIRECTORY exceptionDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (exceptionDir.VirtualAddress && exceptionDir.Size) {
		DWORD count = exceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
		// Add RtlInsertInvertedFunctionTable support for x86
		PRUNTIME_FUNCTION functionTable = (PRUNTIME_FUNCTION)((DWORD_PTR)imageBase + exceptionDir.VirtualAddress);
		pRtlAddFunctionTable myRtlAddFunctionTable = (pRtlAddFunctionTable)myGetProcAddress(myGetModuleHandle("ntdll.dll"), "RtlAddFunctionTable");
		BOOLEAN status = myRtlAddFunctionTable(functionTable, count, (DWORD64)imageBase);
		if (status) {
			printf("Registered %u entries in runtime function table: %p\n", count, functionTable);
		}
	}

#elif _WIN32

	HMODULE hModule = myGetModuleHandle("ntdll.dll");

	BOOL patchStatus = PatchRtlIsValidHandler(hModule);
	if (!patchStatus) {

		fprintf(stderr, "[-] Failure patching RtlIsValidHandler!");
		return 1;
	}

	printf("Successfully patched RtlIsValidHandler for x86 SEH support\n");
#endif

	printf("\nEditing section protections...\n\n");

	BOOL protectStatus = LdrpProtectImage(imageBase, ntHeaders); // setting memory protections after mapping

	if (!protectStatus) {
		fprintf(stderr, "[-] Could not protect one or more memory sections!\n");
		return NULL;
	}
	printf("Success!...\n\n");
	// setting memory protections after mapping


	// now it's the final steps
	// flush the instruction cache
	BOOL flushCache = FlushInstructionCache(GetCurrentProcess(), NULL, 0);

	// handle TLS calllbacks


	IMAGE_DATA_DIRECTORY tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDir.Size) {

		IMAGE_TLS_DIRECTORY* tlsDirectory = (IMAGE_TLS_DIRECTORY*)((DWORD_PTR)imageBase + tlsDir.VirtualAddress);
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tlsDirectory->AddressOfCallBacks;
		//PDWORD indexAddr = (PDWORD)tlsDirectory->AddressOfIndex;
		//DWORD index = GetTlsIndex(myGetModuleHandle(NULL)); // this is essentially the dreaded "TlsResolver" in fatpack
		//InitializeTlsIndex(imageBase, index);
		//InitializeTlsData(imageBase, index);
		if (callback) {
			while (*callback) {
				// Execute each TLS callback with DLL_PROCESS_ATTACH
				(*callback)(imageBase, DLL_PROCESS_ATTACH, NULL);
				callback++;
			}
		}
	}
	DWORD_PTR EntryPoint = (DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
	printf("Original entry point address: %p\n", (BYTE*)(EntryPoint));

#ifdef _WIN64
	MYPEB* pPeb = (MYPEB*)__readgsqword(0x60);
#elif _WIN32
	MYPEB* pPeb = (MYPEB*)__readfsdword(0x30);
#endif
	PEB_LDR_DATA* loaderData = (PEB_LDR_DATA*)pPeb->Ldr;
	LIST_ENTRY* ModuleListHead = &loaderData->InMemoryOrderModuleList;
	LIST_ENTRY* ModuleEntry = (LIST_ENTRY*)ModuleListHead->Flink;
	MYLDR_DATA_TABLE_ENTRY* dataTableEntry = CONTAINING_RECORD(ModuleEntry, MYLDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	LdrpPatchDataTableEntry(dataTableEntry, imageBase);
	BOOL insertStatus = myRtlInsertInvertedFunctionTable(imageBase, ntHeaders->OptionalHeader.SizeOfImage);
	if (!insertStatus) {
		fprintf(stderr, "[-] Failure registering Inverted Function Table entry!");
	}
	printf("Successfully registered Inverted Function Table entry!");

	return imageBase;
}

int main() {
#ifdef DEBUG_STUB
	//size_t unpacked_size = 441198;
	FILE* fuck = fopen("C:\\Users\\tamar\\Downloads\\packed_files\\vscode_[unknowncheats.me]_.exe", "rb");
	fseek(fuck, 0L, SEEK_END);
	size_t unpacked_size = ftell(fuck);
	unsigned char* file_debug = malloc(unpacked_size);
	if (file_debug == NULL) {
		return 1;
	}
	rewind(fuck);
	fread(file_debug, sizeof(unsigned char), unpacked_size, fuck);
	size_t packed_debugsize = 0;
	unsigned char* packed_debug = compressAndEncrypt(file_debug, unpacked_size, &packed_debugsize);
	//LPVOID EntryPoint = executePE(decompressPayload(packed_payload, unpacked_size, packed_size));
	LPVOID imageBase = executePE(decompressPayload(packed_debug, unpacked_size, packed_debugsize));
	//entryPointCalled = TRUE;
#else 

	ppacked_section packed_section = findPackedSection();
	if (packed_section == NULL) {
		printf("Could not locate .packed section.\n");
		return 1;
	}
	size_t unpacked_size = packed_section->unpacked_size;
	unsigned char* packed_payload = packed_section->payload;
	if (packed_section->lockFlag) {
		// payload locking is enabled
		unsigned char inputKey[32] = { 0 };
		printf("This oldProtect & IMAGE_SCN_MEM_EXECUTE file is locked with a password for security reasons. Enter the password to unlock the program (maximum 32 characters):\n\n");

		if (scanf_s("%s", inputKey, (unsigned)_countof(inputKey))) {
			uint32_t key[4] = { 0 };
			for (int i = 0; i < 4; i++) {
				key[i] = strtoul(inputKey, 0, 10);
			}
			decrypt_payload(packed_payload, packed_section->packed_size, key);
			if (DJB2_hash(packed_payload, packed_section->packed_size) == packed_section->lockHash) {
				printf("Correct key! Unlocking program...\n");
			}
			else {
				printf("Incorrect key entered\n");
				return 1;
			}
		}

	}
	BYTE* decryptedPE = decompressPayload(packed_payload, unpacked_size, packed_section->packed_size);
	LPVOID EntryPoint = executePE(decryptedPE);

#endif
	if (!imageBase) {
		return 1;
	}
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)imageBase);
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	LPVOID (*ep)() = (LPVOID)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("\n%p\n", imageBase);
	system("pause");

	int result = ep();

	return result;
}