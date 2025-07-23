
<h1>AlushPacker: Executable file packer for Windows</h1>
  <a href="https://github.com/Alon-Alush/AlushPacker/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Alon-Alush/AlushPacker?style=flat-square&color=blue" alt="License">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker">
    <img src="https://img.shields.io/github/languages/top/Alon-Alush/AlushPacker?style=flat-square&logo=c&color=red" alt="Top Language">
  </a>

# Introduction

*AlushPacker* is a reflective PE packer that enables in-memory execution of native `.exe` files.

The encrypted + compressed version of the original executable is first stored inside a new `.packed` section:

<img width="773" height="226" alt=".packed section in CFF Explorer" src="https://github.com/user-attachments/assets/bbe667e0-3eb1-42d7-9c28-619477035dfe" />



At runtime, the unpacker stub decrypts those contents, and manually loads the executable entirely from memory, with no disk I/O or help from the Windows loader.

The resulting executable is smaller in size, and is much harder to statically analyze with tools like IDA or Ghidra, making reverse engineering / tampering more difficult.

Showcase: Encrypted strings (IDA Pro):

<img width="311" height="699" alt="image" src="https://github.com/user-attachments/assets/fed41c59-390f-4d7f-85cd-6c5c0332ce39" />


# Installation and usage

Download the [latest release binaries](https://github.com/Alon-Alush/AlushPacker/releases/tag/v1.0.0) to get started.

Basic usage: `packer.exe input.exe`

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

**Demo usage:**

![Animation1](https://github.com/user-attachments/assets/1a8d9070-cb03-448f-90b1-69191beea82e)


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

