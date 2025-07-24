
<h1>AlushPacker: Executable file packer for Windows</h1>
  <a href="https://github.com/Alon-Alush/AlushPacker/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Alon-Alush/AlushPacker?style=flat-square&color=blue" alt="License">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker">
    <img src="https://img.shields.io/github/languages/top/Alon-Alush/AlushPacker?style=flat-square&logo=c&color=red" alt="Top Language">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker/releases">
    <img src="https://img.shields.io/github/v/tag/Alon-Alush/AlushPacker?label=Release&style=flat-square&color=purple" alt="Latest Release">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker/stargazers">
    <img src="https://img.shields.io/github/stars/Alon-Alush/AlushPacker?style=flat-square&color=yellow" alt="GitHub Stars">
  </a>
  <a href="https://opensource.org">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg?style=flat-square" alt="Open Source">
  </a>
</p>

# Introduction

*AlushPacker* is a reflective PE packer that enables in-memory execution of native `.exe` files. The new PE file, after packing, can obstruct static analysis and reverse engineering with tools like IDA Pro or Ghidra.


 # Demo

![Animation8](https://github.com/user-attachments/assets/36bfefa1-7a8c-4cf3-a233-310bce190d9f)


# How it works

A new `.packed` section header is first created inside the new, packed file:

<img width="773" height="226" alt=".packed section in CFF Explorer" src="https://github.com/user-attachments/assets/bbe667e0-3eb1-42d7-9c28-619477035dfe" />

This new section will store the encrypted contents version of the original executable, after it has been compressed with [LZAV](https://github.com/avaneev/lzav), and encrypted using an [XTEA](https://en.wikipedia.org/wiki/XTEA) implementation.

At runtime, the unpacker stub locates this section within itself, decrypts and decompresses those contents, and manually loads the executable entirely from memory, with no disk I/O or help from the Windows loader.

Encrypted strings in IDA Pro:

<img width="293" height="267" alt="image" src="https://github.com/user-attachments/assets/3edc09ff-d389-4241-9e90-3bbc152cbfdb" /> 


# Getting started

The packer binaries can be downloaded here: [latest release binaries](https://github.com/Alon-Alush/AlushPacker/releases/tag/v1.0.0).

## Usage

To pack a program, you generally specify its *input name* and *output name*. If an *output name* is not provided, the packed file will automatically be written to the input directory with a `_packed` filename extension.

For example: 

```
packer <input_file> <output_file>
```

Here's the full usage:

```
> packer.exe

Alush Packer
Copyright (C) 2025
Alon Alush / alonalush5@gmail.com
Usage:
   packer.exe [OPTIONS] <input_file>
Options:
   -o <output_file>   Specify packed output file path. If not provided, writes to input directory
   -l <key>    Lock the packed file with a password. Example: -l mypassword
```

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

