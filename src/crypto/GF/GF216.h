#pragma once

namespace GF216 {
    // DLog respective to 0x03
    unsigned short log03(unsigned short a);

    // inverse of a in GF(2^16)
    unsigned short inv(unsigned short a);

    // a * b in GF(2^16)
    unsigned short mul(unsigned short a, unsigned short b);
}

