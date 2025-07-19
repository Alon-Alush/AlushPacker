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

*AlushPacker* is a reflective PE packer that allows in-memory execution of native `.exe` files. The compressed + encrypted contents of the original executable are embedded inside a new `.packed` section. At runtime, the unpacker stub decrypts those contents, and manually loads the executable entirely from memory, with no disk I/O or help from the Windows loader.

The final resulting binary is smaller in size, and is much harder to statically analyze with tools like IDA or Ghidra, making reverse engineering / tampering more difficult.

 # Example: Packed HxD in Action

![Animation](https://github.com/user-attachments/assets/bc89a043-370b-49f7-98bf-c46fc17e4107)


# Installation and usage

The easiest and simplest way to pack your files with AlushPacker is to download the [latest release binaries](https://github.com/Alon-Alush/AlushPacker/releases/tag/release).

Basic usage: `packer.exe input.exe`

```
packer.exe

Alush Packer
Copyright (C) 2025
Alon Alush / alonalush5@gmail.com
Usage:
   C:\Users\tamar\source\repos\ConsoleApplication2\x64\Release\ConsoleApplication2.exe [OPTIONS] <input_file>
Options:
   -o <output_file>   Specify packed output file path. If not provided, writes to input directory
   -l <key>    Lock the packed file with a password. Example: -l mypassword
```

Example usage: 

`packer.exe "C:\Users\tamar\Downloads\HxD.exe"`

<img width="961" height="203" alt="image" src="https://github.com/user-attachments/assets/d2c79fa7-5022-4577-bf43-15424360ead5" />

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

