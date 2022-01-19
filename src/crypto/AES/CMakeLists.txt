
add_library(GF28 STATIC GF28.cpp GF28.h)

add_library(AES STATIC AES128.cpp AES128.h GF28.cpp GF28.h)

add_library(AESNI STATIC AES128_ni.cpp AES128_ni.h)

add_library(AES5 STATIC AES128_5ni.cpp AES128_5ni.h)

add_library(AESFULL STATIC AES128_full.cpp AES128_full.h)

