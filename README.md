<p align="center">
    <img src="https://github.com/user-attachments/assets/474bebdd-6669-4143-89d3-ef7bab3ca08d" alt ="Banner"/>
  </a>
<h1 align="center">AlushPacker: Executable file packer for Windows</h1>
<p align="center">
  <a href="https://github.com/Alon-Alush/AlushPacker/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Alon-Alush/AlushPacker?style=for-the-badge&color=blue" alt="License">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker">
    <img src="https://img.shields.io/github/languages/top/Alon-Alush/AlushPacker?style=for-the-badge&logo=c&color=red" alt="Top Language">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker/releases">
    <img src="https://img.shields.io/github/v/tag/Alon-Alush/AlushPacker?label=Release&style=for-the-badge&color=purple" alt="Latest Release">
  </a>
  <a href="https://github.com/Alon-Alush/AlushPacker/stargazers">
    <img src="https://img.shields.io/github/stars/Alon-Alush/AlushPacker?style=for-the-badge&color=yellow" alt="GitHub Stars">
  </a>
  <a href="https://opensource.org">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg?style=for-the-badge" alt="Open Source">
  </a>
</p>

# Introduction

*AlushPacker* is a reflective PE packer that can obstruct static analysis and reverse engineering with tools like IDA or Ghidra.

At build time, the packer encrypts and compresses the contents  of the original executable, and embeds them inside a `.packed` section.

At runtime, the unpacker stub (reflective loader) locates this section within itself, decrypts and decompresses those contents, and manually loads the executable entirely from memory, with no disk I/O or help from the Windows loader.
 # Demo

![Running the packed file](https://github.com/user-attachments/assets/40ce8bab-492e-4a7d-b8c2-3f8529ff5a50)


# Getting started

The packer binaries can be downloaded here: [latest release binaries](https://github.com/Alon-Alush/AlushPacker/releases/tag/v1.0.0).

## Usage

To pack a program, you generally specify its *input name*.

For example: 

```
packer <input_file>
```

![AlushPacker command line demonstration](https://github.com/user-attachments/assets/12f55d88-19a3-4982-86ab-1923825a539a)

# Packed file (overview)

### Encrypted strings (IDA Pro):

<img width="291" height="131" alt="image" src="https://github.com/user-attachments/assets/914edc83-8078-4561-b1d7-a0baab6fea94" />

### Detect-It-Easy analysis:
<img width="717" height="214" alt="image" src="https://github.com/user-attachments/assets/3d4e3829-a209-4260-ac12-41f8fc100604" />


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

