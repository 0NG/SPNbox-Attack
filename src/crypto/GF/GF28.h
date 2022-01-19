#pragma once

namespace GF28 {
    // DLog respective to 0x03
    unsigned char log03(unsigned char a);

    // inverse of a in GF(2^8)
    unsigned char inv(unsigned char a);

    // a * b in GF(2^8)
    unsigned char mul(unsigned char a, unsigned char b);
}

