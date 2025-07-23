#include <stdint.h>

void encrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;           /* set up */
    uint32_t delta = 0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < 32; i++) {                         /* basic cycle start */
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}

void encrypt_payload(unsigned char* data, size_t length, const uint32_t key[4]) {
    // Pad the data length to a multiple of 8 if necessary
    size_t padded_length = ((length + 7) / 8) * 8;

    // Process each 8-byte block
    for (size_t i = 0; i < padded_length; i += 8) {
        uint32_t block[2] = { 0, 0 };

        // Convert 8 bytes to two 32-bit integers
        // Handle the case where we might not have 8 full bytes
        for (size_t j = 0; j < 8 && (i + j) < length; j++) {
            if (j < 4) {
                block[0] |= ((uint32_t)data[i + j]) << (j * 8);
            }
            else {
                block[1] |= ((uint32_t)data[i + j]) << ((j - 4) * 8);
            }
        }

        // Encrypt the block
        encrypt(block, key);

        // Convert back to bytes
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
