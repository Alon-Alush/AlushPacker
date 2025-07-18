
/**
 * @file decrypt.h
 * 
 * Purpose: Decrypting the payload
 *
 * Description is available at https://github.com/Alon-Alush/AlushPacker
 *
 * E-mail: alonalush5@gmail.com
 *
 * LICENSE:
 *
 * Copyright (c) 2025 Alon Alush
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>  // For uint32_t type
// TEA decryption implementation
void decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;
    uint32_t delta = 0x9E3779B9;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }
    v[0] = v0; v[1] = v1;
}


void decrypt_payload(unsigned char* data, size_t length, const uint32_t key[4]) {
    size_t padded_length = ((length + 7) / 8) * 8;

    for (size_t i = 0; i < padded_length; i += 8) {
        uint32_t block[2] = { 0, 0 };

        for (size_t j = 0; j < 8 && (i + j) < padded_length; j++) {
            if (j < 4) {
                block[0] |= ((uint32_t)data[i + j]) << (j * 8);
            }
            else {
                block[1] |= ((uint32_t)data[i + j]) << ((j - 4) * 8);
            }
        }

        decrypt(block, key);

        for (size_t j = 0; j < 8 && (i + j) < padded_length; j++) {
            if (j < 4) {
                data[i + j] = (block[0] >> (j * 8)) & 0xFF;
            }
            else {
                data[i + j] = (block[1] >> ((j - 4) * 8)) & 0xFF;
            }
        }
    }
}