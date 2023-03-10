#include "buffer.h"


// Add these functions to track current pointer of the buffer easier
// Read 1 byte from buffer, increase current by 1
uint8_t perf_buffer_getuint8(perf_buffer_t *b) {
    unsigned char *cp;
    uint8_t result;
    assert((b)->used - (b)->current >= 1);
    cp = perf_buffer_base(b) + (b)->current;
    (b)->current += 1;
    result = ((uint8_t)(cp[0]));
    return (result);
}


// Read 2 bytes and convert to host byte order, increase current by 2
uint16_t perf_buffer_getuint16(perf_buffer_t *b) {
    unsigned char *cp;
    uint16_t result;
    assert((b)->used - (b)->current >= 2);
    cp = perf_buffer_base(b) + (b)->current;
    (b)->current += 2;
    result = ((unsigned int)(cp[0])) << 8;
    result |= ((unsigned int)(cp[1]));
    return (result);
}


// Read 4 bytes and convert to host byte order, increase current by 4
uint32_t perf_buffer_getuint32(perf_buffer_t *b) {
    unsigned char *cp;
    uint32_t result;
    assert((b)->used - (b)->current >= 4);
    cp = perf_buffer_base(b) + (b)->current;
    (b)->current += 4;
    result = ((unsigned int)(cp[0])) << 24;
    result |= ((unsigned int)(cp[1])) << 16;
    result |= ((unsigned int)(cp[2])) << 8;
    result |= ((unsigned int)(cp[3]));
    return (result);
}
