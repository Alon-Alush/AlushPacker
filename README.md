<p align="center">
  <a href="#">
    <img src="https://github.com/user-attachments/assets/d56f58bc-70ef-4d57-964f-8749aa1ed921" alt="AlushPacker logo" width="800">
  </a>
</p>
<h1 align="center">AlushPacker: Executable file packer for Windows</h1>
<p align="center">
  <a href="https://github.com/Alon-Alush/AlushPacker/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Alon-Alush/AlushPacker?style=flat&color=blue" alt="License">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker">
    <img src="https://img.shields.io/github/languages/top/Alon-Alush/AlushPacker?style=flat&logo=c&color=red" alt="Top Language">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker/releases">
    <img src="https://img.shields.io/github/v/release/Alon-Alush/AlushPacker?style=flat&color=purple" alt="Latest Release">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker/stargazers">
    <img src="https://img.shields.io/github/stars/Alon-Alush/AlushPacker?style=flat&color=yellow" alt="GitHub Stars">
  </a>
  <a href="https://opensource.org">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg?style=flat" alt="Open Source">
  </a>
</p>

## Introduction


*AlushPacker* is a reflective PE packer that enables in-memory execution of native `.exe` files. The packed file can hinder static analysis and reverse engineering with tools like IDA Pro or Ghidra.

# Demo

![Running the packed file](https://github.com/user-attachments/assets/40ce8bab-492e-4a7d-b8c2-3f8529ff5a50)

# How it works

The [builder](https://github.com/Alon-Alush/AlushPacker/blob/main/src/Builder/builder.c) creates new `.packed` section header that stores the packed version of the original executable, that is, after it has been compressed with the [LZAV](https://github.com/Alon-Alush/AlushPacker/blob/main/src/Builder/lzav.h) compression library, and encrypted using a [custom implementation](https://github.com/Alon-Alush/AlushPacker/blob/main/src/Builder/encrypt.h) of [XTEA](https://en.wikipedia.org/wiki/XTEA) (eXtended Tiny Encryption Algorithm) block cypher.

<img width="773" height="226" alt=".packed section in CFF Explorer" src="https://github.com/user-attachments/assets/bbe667e0-3eb1-42d7-9c28-619477035dfe" />

At runtime, the [reflective loader](https://github.com/Alon-Alush/AlushPacker/blob/main/src/Packer/loader.c) locates  the base address of this section (which is embedded within itself), decrypts and decompresses those contents, and manually loads the executable entirely from memory, with no disk I/O or help from the Windows loader.

# Showcase

### Encrypted data (IDA Pro):

In the packed version, the original executable's data is stored, well.. packed, meaning that disassemblers like IDA are unable to extract any meaningful interpretation out of that packed data.

<img width="291" height="131" alt="image" src="https://github.com/user-attachments/assets/914edc83-8078-4561-b1d7-a0baab6fea94" />

### Detect-It-Easy analysis:

*Detect-It-Easy* has detected that our executable is packed due to the high entropy in the `.packed` section. However, this detection can be bypassed by placing the packed data inside `payload.h` instead of writing this packed data to a separate section header. You can do this by compiling from source, setting the `DEBUG_STUB` macro, and placing the packed data inside `payload.h`. But, this requires a more "hacky approach", so to make the build process more straightforward, we place the packed data inside a separate section header.

<img width="717" height="214" alt="image" src="https://github.com/user-attachments/assets/3d4e3829-a209-4260-ac12-41f8fc100604" />

# Installation and usage

The packer can be downloaded here: [latest release binaries](https://github.com/Alon-Alush/AlushPacker/releases/tag/v1.0.0).

## Usage

To pack a program, you must specify its *input path*. Optionally, you can specify the output path, although this is not strictly required.

Example usage:

```
packer <input_file> <output_file>
```

**Full usage**:
```
> packer.exe
Usage:
   C:\Users\tamar\Downloads\packed_files\Builder.exe [OPTIONS] <input_file> <output_file>
Options:
   -l <key>    Protect the packed file with a password. Example: -l mypassword

    Example usage: packer.exe <input.exe> <output.exe>
C:\Users\tamar\Downloads\packed_files>
```

**Visual Demo**:

![AlushPacker command line demonstration](https://github.com/user-attachments/assets/12f55d88-19a3-4982-86ab-1923825a539a)

# Features

* x64 and x86 support
* Native console, GUI, and legacy EXE support
* File compression, encryption
* Payload locking (if built with `-l` option, output file will request a password before executing)
# Technical features
* Section headers manual mapping
* Custom WinAPI / loader function implementations (e.g. `myGetProcAddress`, `myGetModuleHandle`)
* Resolving imports (normal / delay-loaded), by name and by ordinal.
* Fast export directory traversal using binary search. [Forwarded exports](https://devblogs.microsoft.com/oldnewthing/20060719-24/?p=30473) specifically are resolved using a highly reliable recursion + parsing logic in `LdrpResolveProcedureAddress`
* Relocations (in case PE image is not loaded at base address)
* [Structured Exception Handling (SEH)](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=msvc-170), registering function table in `.pdata`
* [Thread Local Storage](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-local-storage) (TLS callbacks) support
* Appropriate section memory protection (with `VirtualProtect`)
* Finally, PEB patching (e.g. `PPEB->pPeb->ImageBaseAddress = (PVOID)ntHeaders->OptionalHeader.ImageBase`)

# Contributing

Contributions to the project are welcome!

You can improve parts of the code, report bugs, or just suggest features you think would be cool to add. I will review your suggestions and approve them if they step the project towards a better place :)

