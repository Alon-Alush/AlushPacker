<p align="center">
  <a href="#">
    <img src="https://github.com/user-attachments/assets/d56f58bc-70ef-4d57-964f-8749aa1ed921" alt="AlushPacker logo" width="800">
  </a>
</p>
<h1 align="center">AlushPacker</h1>
<p align="center">
  <strong>Executable file packer for Windows</strong>
</p>
<p align="center">
  <a href="https://github.com/Alon-Alush/AlushPacker/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Alon-Alush/AlushPacker?style=for-the-badge&color=blue" alt="License">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker">
    <img src="https://img.shields.io/github/languages/top/Alon-Alush/AlushPacker?style=for-the-badge&logo=c&logoColor=white&color=00599C" alt="Top Language">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker/releases">
    <img src="https://img.shields.io/github/v/release/Alon-Alush/AlushPacker?style=for-the-badge&color=green" alt="Latest Release">
  </a>
</p>
<p align="center">
  <a href="https://github.com/Alon-Alush/AlushPacker/stargazers">
    <img src="https://img.shields.io/github/stars/Alon-Alush/AlushPacker?style=for-the-badge&color=yellow" alt="GitHub Stars">
     </a>
  <a href="https://github.com/Alon-Alush/AlushPacker">
    <img src="https://img.shields.io/github/repo-size/Alon-Alush/AlushPacker?style=for-the-badge&color=lightblue" alt="Repo Size">
  </a>
  <a href="https://opensource.org">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg?style=for-the-badge" alt="Open Source">
  </a>
</p>


*AlushPacker* is an advanced, high-performance executable packer for Windows PE `.exe` files, made in C.

It first compresses your *entire* static executable with [LZAV compression library](https://github.com/avaneev/lzav), then encrypts it with a custom TEA-32 encryption implementation. The resulting packed file manually maps and loads itself at runtime. It is significantly smaller in size, and all the original resources —  strings, headers, and executable code — are fully hidden once packed, making static analysis with tools like IDA significantly more difficult.

 # Example: Packed HxD in Action

![Animation](https://github.com/user-attachments/assets/09efedd6-6a3a-43ce-9bfe-2d7816cf01b7)

# Installation and usage

In order for the packed executable to run correctly on your machine, you'd need Visual C/C++ redistributables.

Basic usage: `builder.exe input.exe`

```
builder.exe

Alush Packer
Copyright (C) 2025
Alon Alush / alonalush5@gmail.com
Usage:
   C:\Users\tamar\source\repos\ConsoleApplication2\x64\Release\ConsoleApplication2.exe [OPTIONS] <input_file>
Options:
   -o <output_file>   Specify packed output file path. If not provided, writes to input directory
   -e          Encrypt file with a random 16-byte key.
   -c          Compress input file with LZAV, a fast general-purpose in-memory data compression algorithm
   -l <key>    Lock the packed file with a password. Example: -l mypassword
```

Example usage: 

`builder.exe "C:\Users\tamar\Downloads\brainfuck compiler\HxD.exe"`

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

