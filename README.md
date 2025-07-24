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

A new `.packed` section header will store the encrypted contents version of the original executable, after it has been compressed with [LZAV]([https://github.com/avaneev/lzav](https://github.com/Alon-Alush/AlushPacker/blob/main/src/Builder/lzav.h)), and encrypted using an [XTEA](https://github.com/Alon-Alush/AlushPacker/blob/main/src/Builder/encrypt.h) implementation.

<img width="773" height="226" alt=".packed section in CFF Explorer" src="https://github.com/user-attachments/assets/bbe667e0-3eb1-42d7-9c28-619477035dfe" />

At runtime, the reflective loader locates this section within itself, decrypts and decompresses those contents, and manually loads the executable entirely from memory, with no disk I/O or help from the Windows loader.


# Showcase

### Encrypted data (IDA Pro):

In the packed version, the original executable's data is stored encrypted. Disassemblers like IDA will only be able to view the unpacker stub's code, not the actual payload we're going to execute at runtime.

<img width="291" height="131" alt="image" src="https://github.com/user-attachments/assets/914edc83-8078-4561-b1d7-a0baab6fea94" />

### Detect-It-Easy analysis:

`Detect-It-Easy` has detected our packed section due to the high entropy. However, this detection can be bypassed by putting the payload inside a static C buffer, which you can do by compiling from source. To make the building straightforward, we use a precompiled stub that locates the packed data inside a separate section.

<img width="717" height="214" alt="image" src="https://github.com/user-attachments/assets/3d4e3829-a209-4260-ac12-41f8fc100604" />

# Getting started

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
   C:\Users\tamar\Downloads\packed_files\Builder.exe [OPTIONS] <input_file> <output_file
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

