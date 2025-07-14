
<img width="1280" height="168" alt="download" src="https://github.com/user-attachments/assets/d56f58bc-70ef-4d57-964f-8749aa1ed921" />

*AlushPacker* is an advanced, high-performance executable packer for Windows PE `.exe` files, made in C.

It first compresses your *entire* static executable with [LZAV compression library](https://github.com/avaneev/lzav) and then encrypts it with a custom TEA-32 encryption implementation. The resulting packed file manually maps and loads itself at runtime. It is significantly lower in size, and most importantely: all the original elements, including strings, resources, headers, and executable code are fully once packed, making reverse engineering or patching significantly more difficult.

AlushPacker supports both x64 and x86, with many features like compression, encryption, locking, and much more! 

 # Example: Packed HxD in Action

![Animation](https://github.com/user-attachments/assets/09efedd6-6a3a-43ce-9bfe-2d7816cf01b7)

