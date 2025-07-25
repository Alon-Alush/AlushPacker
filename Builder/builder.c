#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdint.h>
#include "lzav.h"
#include "encrypt.h"
#include "stubs.h"
#include "structs.h"
#include <intrin.h>

#define ALIGN_UP(x, align) ((x) & -(align))
// align x up to the nearest multiple of align. align must be a power of 2.
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

DWORD align_value(DWORD valueToAlign, DWORD alignment) {
    DWORD r = valueToAlign % alignment;
    return r ? valueToAlign + (alignment - r) : valueToAlign;
}

uint32_t DJB2_hash(const unsigned char* buf, size_t size) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < size; i++)
        hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + byte */
    return hash;
}

size_t determineWriteSize(LPVOID imageBase, size_t inputFileSize, DWORD packedSectionSize) {

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)imageBase);
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
    IMAGE_FILE_HEADER* fileHeader = &ntHeaders->FileHeader;
    IMAGE_SECTION_HEADER* firstSection = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = fileHeader->NumberOfSections;
    DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
    DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
    size_t sectionSize = sizeof(IMAGE_SECTION_HEADER);

    IMAGE_SECTION_HEADER* lastSection = &firstSection[numSections - 1];

    return (size_t)align_value(lastSection->PointerToRawData + lastSection->SizeOfRawData, fileAlignment) + align_value(packedSectionSize, fileAlignment);
}

BYTE* addSectionToInputFile(BYTE* inputFile, size_t inputFileSize, void* pSection, DWORD pSectionSize, size_t* writeSize) {

    size_t writeSize = determineWriteSize(inputFile, inputFileSize, pSectionSize);

    BYTE* resizedInput = malloc(writeSize);
    if (resizedInput == NULL) {
        return NULL;
    }
    memcpy(resizedInput, inputFile, inputFileSize);
    LPVOID imageBase = (LPVOID)resizedInput;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)resizedInput);
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)imageBase + dosHeader->e_lfanew);
    IMAGE_FILE_HEADER* fileHeader = &ntHeaders->FileHeader;
    IMAGE_SECTION_HEADER* firstSection = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = fileHeader->NumberOfSections;
    DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
    DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
    size_t sectionSize = sizeof(IMAGE_SECTION_HEADER);
    IMAGE_SECTION_HEADER* newSection = &firstSection[numSections];
    IMAGE_SECTION_HEADER* lastSection = &firstSection[numSections - 1];
    newSection->VirtualAddress = align_value(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, sectionAlignment);
    unsigned char name[] = ".packed";
    fileHeader->NumberOfSections += 0x01;
    memcpy(newSection->Name, name, sizeof(name));
    newSection->Misc.VirtualSize = pSectionSize;
    newSection->SizeOfRawData = align_value(pSectionSize, fileAlignment);
    newSection->PointerToRawData = align_value(lastSection->PointerToRawData + lastSection->SizeOfRawData, fileAlignment);
    newSection->PointerToRelocations = 0;
    newSection->PointerToLinenumbers = 0;
    newSection->NumberOfRelocations = 0;
    newSection->NumberOfRelocations = 0;
    newSection->NumberOfLinenumbers = 0;
    newSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
    ntHeaders->OptionalHeader.SizeOfImage = align_value(newSection->VirtualAddress + newSection->Misc.VirtualSize, sectionAlignment);
    memcpy((void*)((DWORD_PTR)imageBase + newSection->PointerToRawData), pSection, pSectionSize);
    return resizedInput;
}

BYTE* processFile(FILE* fp, DWORD size) {
    BYTE* inputFile = malloc(size);
    if (inputFile == 0) {
        fprintf(stderr, "Could not allocate memory for the input file\n");
        return NULL;
    }

    size_t result = fread(inputFile, sizeof(char), size, fp);
    if (result != size) {
        fprintf(stderr, "Failure!\n");
        return NULL;
    }
    WORD mzSig = *(WORD*)(DWORD_PTR)inputFile;
    if (mzSig != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Invalid PE file entered!\n");
        return NULL;
    }
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)inputFile;

    printf("[+] Found DOS header: %p\n", dosHeader);
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(inputFile + dosHeader->e_lfanew);

    printf("[+] Found NT header: %p\n", ntHeaders);

    //DWORD_PTR comDescTable = ((DWORD_PTR)ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
    //if (comDescTable != 0) {
    //    printf(".NET exe detected! Since Alush Packer is written in native C, it unfortunately does not yet support packing\n .NET executables. To avoid crashing, the program will now exit gracefully.\n");
    //   return NULL;
    //}
    return inputFile;
}

BYTE* compressAndEncrypt(BYTE* inputFile, size_t fileSize, size_t * returnCompressedSize) {

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

int main(int argc, char* argv[]) {

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    SetConsoleOutputCP(CP_UTF8);
    const wchar_t* text =
        L" █████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ \n"
        L"██╔══██╗██║     ██║   ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗\n"
        L"███████║██║     ██║   ██║███████╗███████║██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝\n"
        L"██╔══██║██║     ██║   ██║╚════██║██╔══██║██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗\n"
        L"██║  ██║███████╗╚██████╔╝███████║██║  ██║██║     ██║  ██║╚██████╗██║  ██╗███████╗██║  ██║\n"
        L"╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n"
        L"Copyright(C) 2025 / alonalush5@gmail.com\n";
    WriteConsoleW(hConsole, text, wcslen(text), NULL, NULL);
    SetConsoleTextAttribute(hConsole, 7);

    if (argc < 2) {
        fprintf(stderr, "Usage:\n   %s [OPTIONS] <input_file> <output_file\n", argv[0]);
        printf("Options:\n");
        //printf("   -e          Encrypt file with a random 16-byte key.\n");
        //printf("   -c          Compress input file with LZAV, a fast general-purpose in-memory data compression algorithm\n");
        printf("   -l <key>    Protect the packed file with a password. Example: -l mypassword\n\n");

        printf("    Example usage: packer.exe <input.exe> <output.exe>");
        return 1;
    }
    //BOOL encryptFlag = FALSE;
    //BOOL compressFlag = FALSE;
    BOOL lockFlag = FALSE;
    BOOL outputFlag = FALSE;
    char inputPath[MAX_PATH] = { 0 };
    FILE* inputfp = NULL;
    FILE* outputfp = NULL;
    if (fopen_s(&inputfp, argv[1], "rb") != 0) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
        fprintf(stderr, "Invalid input path!\n");
        SetConsoleTextAttribute(hConsole, 7);
        return 1;
    }

    strcpy_s(inputPath, MAX_PATH, argv[1]);

    char outputPath[MAX_PATH] = { 0 };
    uint32_t lockKey[4] = { 0 };
    uint32_t lockHash = 0;
    for (int i = 2; i < argc; i++) {
        if (argv[i] != NULL) {
            /*if (strcmp(argv[i], "-e") == 0) {
                encryptFlag = TRUE;
            }
            else if (strcmp(argv[i], "-c") == 0) {
                compressFlag = TRUE;
            }*/
            if (strcmp(argv[i], "-l") == 0) {
                if (argv[i + 1] != NULL) {
                    if ((strlen(argv[i + 1]) > 32)) {
                        printf("Maximum key size is 32 characters!\n");
                        return 1;
                    }

                    lockFlag = 1;

                    lockHash = hash(argv[i + 1]);
                    // let's convert it to a 128 bit key
                    for (int i = 0; i < 4; i++) {

                        lockKey[i] = strtoul(argv[i + 1], 0, 10);
                    }

                }
            }
            else if (strcmp(argv[i], "-o") == 0) {
                if (i == argc - 1) {
                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
                    fprintf(stderr, "Error: Missing argument \"Output path\"");
                    SetConsoleTextAttribute(hConsole, 7);
                    return 1;
                }
                else if (fopen_s(&outputfp, argv[i + 1], "wb") != 0) {
                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
                    fprintf(stderr, "Could not open the output path! Please check that the path is enclosed in double quotations \" \"\n");

                    SetConsoleTextAttribute(hConsole, 7);
                    return 1;
                }

                else if (strcpy_s(outputPath, MAX_PATH, argv[i + 1]) != 0) {
                    fprintf(stderr, "Could not copy string!");
                    return 1;
                }

                outputFlag = TRUE;
            }
        }

        else {
            fprintf(stderr, "Error: One of the arguments is NULL!\n");
        }
    }

    if (outputFlag == FALSE) {

        char append[] = "_packed.exe";
        if (strcpy_s(outputPath, sizeof(inputPath), inputPath) != 0) {
            return 1;
        }
        char* extension = strstr(outputPath, ".exe");
        if (extension == NULL) {

            SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
            fprintf(stderr, "Could not locate .exe extension?\n");
            SetConsoleTextAttribute(hConsole, 7);
            return 1;
        }
        memcpy(extension, append, sizeof(append));
    }
    // now outputpath should contain a valid path to write to
    DWORD fileSize = 0;

    fseek(inputfp, 0, SEEK_END);
    fileSize = ftell(inputfp);
    fseek(inputfp, 0, SEEK_SET);

    BYTE* inputFile = processFile(inputfp, &fileSize);

    if (inputFile == NULL) {
        return 1;
    }
    // fileSize contains size of input file
    size_t packed_size = 0;
    BYTE* packedPayload = compressAndEncrypt(inputFile, &fileSize, &packed_size);

    if (packedPayload == NULL) {
        return 1;
    }

    packed_section* packedSection = malloc(packed_size);
    if (packedSection == NULL) {
        return 1;
    }
    DWORD packedSectionSize = packedSection->packed_size + sizeof(packed_section);
    if (packedSection == NULL) {
        return 1;
    }
    if (lockFlag == TRUE) {

        packedSection->lockFlag = TRUE;
        printf("[+] Successfully locked payload with input password\n");
        // encrypt again with user input key
        encrypt_payload(packedPayload, packed_size, lockKey);
        packedSection->lockHash = DJB2_hash(packedPayload, packed_size);
    }

    packedSection->unpacked_size = fileSize;
    packedSection->packed_size = packed_size;
    memcpy(packedSection->payload, packedPayload, packed_size);

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)((DWORD_PTR)inputFile);

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)inputFile + dosHeader->e_lfanew);
    unsigned char* precompiled_unpacker = NULL;
    size_t stub_size = 0;
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        // 64-bit
        stub_size = stub_size_x64;
        precompiled_unpacker = precompiled_unpacker_x64;
    }
    else {
        // 32-bit

        stub_size = stub_size_x86;
        precompiled_unpacker = precompiled_unpacker_x86;
    }
    size_t finalSize = 0;
    BYTE* finalFile = addSectionToInputFile(&precompiled_unpacker, stub_size, (LPVOID)packedSection, packedSectionSize, finalSize);
    outputfp = fopen(outputPath, "wb");
    if (!outputfp) {
        return 1;
    }

    fwrite(finalFile, sizeof(char), finalSize, outputfp);
    fclose(outputfp);
    printf("Successfully saved payload to %s\n", outputPath);


    return 0;
}

