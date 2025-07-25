#include <stdint.h>

// struct to map the contents of the .packed section
typedef struct _packed_section {
	uint32_t unpacked_size;
	uint32_t packed_size;
	BOOL lockFlag;
	uint32_t lockHash;
	unsigned char payload[];
} packed_section, * ppacked_section;