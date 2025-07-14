
<img width="1280" height="168" alt="download" src="https://github.com/user-attachments/assets/d56f58bc-70ef-4d57-964f-8749aa1ed921" />

*AlushPacker* is a powerful PE executable packer for Windows - supports x86/64, compression, encryption, and much more! 

Example with packed HxD:

![Animation](https://github.com/user-attachments/assets/09efedd6-6a3a-43ce-9bfe-2d7816cf01b7)


It works by statically encrypting and compressing the entire input `.exe` payload so that it's NOT visible to static analysis tools such as IDA / HxD / CFF explorer / 010 editor.

This means that things like *strings*, *resources*, *headers*, *executable code* are NOT inspectable once your file is packed with our tool.

<img width="1280" height="168" alt="download" src="https://github.com/user-attachments/assets/77287456-18d0-4765-b1cf-197be30c0178" />



