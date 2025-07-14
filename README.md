
<img width="1280" height="168" alt="download" src="https://github.com/user-attachments/assets/d56f58bc-70ef-4d57-964f-8749aa1ed921" />

*AlushPacker* is an advanced, high-performance executable packer for Windows PE `.exe` files, made in C.

It first compresses your *entire* static executable with [LZAV compression library](https://github.com/avaneev/lzav), then encrypts it with a custom TEA-32 encryption implementation. The resulting packed file manually maps and loads itself at runtime. It is significantly smaller in size, and all the original resources —  strings, headers, and executable code — are fully hidden once packed, making static analysis with tools like IDA significantly more difficult.

# Features

* x64 and x86 support
* Supports native console, GUI, and legacy executables
* File compression, encryption
* Payload locking (if built with `-l` option, packed file will request a password before executing)
# Technical features
* Section headers manual mapping
* Custom WinAPI function implementations (e.g. `myGetProcAddress, `myGetModuleHandle`)
* Resolving imports (normal / delay), by name and by ordinal, recursive support for [forwarded exports](https://devblogs.microsoft.com/oldnewthing/20060719-24/?p=30473)
* Relocations
* [Structured Exception Handling (SEH)](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=msvc-170), registering function table in `.pdata`
* [Thread Local Storage](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-local-storage) (TLS callbacks) support
* Appropriate section memory protection (with `VirtualProtect`)
* Finally, PEB patching (e.g. `PPEB->pPeb->ImageBaseAddress = (PVOID)ntHeaders->OptionalHeader.ImageBase`)
 # Example: Packed HxD in Action

![Animation](https://github.com/user-attachments/assets/09efedd6-6a3a-43ce-9bfe-2d7816cf01b7)

