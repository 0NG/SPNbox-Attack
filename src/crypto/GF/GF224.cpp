#include "GF224.h"

#include <array>

static unsigned int _internal_mul(unsigned int a, unsigned int b) 
{
    unsigned int ret = 0;
    for (int i = 0; i < 24; ++i) {
        const auto lowBit = b & 0x01;
        if (lowBit)    ret ^= a;
        const unsigned int msb = (a & 0x800000) >> 23;
        a <<= 1;
        a ^= 0x1000019 * msb;
        b >>= 1;

        if (!b) break;
    }
    return ret;
}

// a * b in GF(2^24)
unsigned int GF224::mul(const unsigned int a, const unsigned int b) 
{
    return _internal_mul(a, b);
}

