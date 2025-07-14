
<img width="1280" height="168" alt="download" src="https://github.com/user-attachments/assets/d56f58bc-70ef-4d57-964f-8749aa1ed921" />

*AlushPacker* is an advanced, high-performance executable packer for Windows PE `.exe` files. It compresses + encrypts your entire static executable, including including code, strings, resources, and headers, generating a packed file that manually maps and loads itself runtime. The packed file makes your payload completely oblivious to static analysis tools like IDA and significantly reduces file size.

AlushPacker supports both x64 and x86, with many features like compression, encryption, locking, and much more! 

Example with packed HxD:

![Animation](https://github.com/user-attachments/assets/09efedd6-6a3a-43ce-9bfe-2d7816cf01b7)


It works by statically encrypting and compressing the entire input `.exe` payload so that it's NOT visible to static analysis tools such as IDA / HxD / CFF explorer / 010 editor.

This means that things like *strings*, *resources*, *headers*, *executable code* are fully once your file is packed with our tool, thus making it much harder to patch




