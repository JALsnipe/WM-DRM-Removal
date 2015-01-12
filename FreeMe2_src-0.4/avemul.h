#ifndef AV_EMUL_H
#define AV_EMUL_H

// for WORDS_BIGENDIAN
#include "config.h"
#include <inttypes.h>
#include <string.h>
#define FFSWAP(type,a,b) do{type SWAP_tmp= b; b= a; a= SWAP_tmp;}while(0)
#define AV_RL32(x) ((((uint8_t*)(x))[3] << 24) | \
                    (((uint8_t*)(x))[2] << 16) | \
                    (((uint8_t*)(x))[1] <<  8) | \
                     ((uint8_t*)(x))[0])
#define AV_RB64(x)  (((uint64_t)((uint8_t*)(x))[0] << 56) | \
                     ((uint64_t)((uint8_t*)(x))[1] << 48) | \
                     ((uint64_t)((uint8_t*)(x))[2] << 40) | \
                     ((uint64_t)((uint8_t*)(x))[3] << 32) | \
                     ((uint64_t)((uint8_t*)(x))[4] << 24) | \
                     ((uint64_t)((uint8_t*)(x))[5] << 16) | \
                     ((uint64_t)((uint8_t*)(x))[6] <<  8) | \
                      (uint64_t)((uint8_t*)(x))[7])
#define AV_RL64(x)  (((uint64_t)((uint8_t*)(x))[7] << 56) | \
                     ((uint64_t)((uint8_t*)(x))[6] << 48) | \
                     ((uint64_t)((uint8_t*)(x))[5] << 40) | \
                     ((uint64_t)((uint8_t*)(x))[4] << 32) | \
                     ((uint64_t)((uint8_t*)(x))[3] << 24) | \
                     ((uint64_t)((uint8_t*)(x))[2] << 16) | \
                     ((uint64_t)((uint8_t*)(x))[1] <<  8) | \
                      (uint64_t)((uint8_t*)(x))[0])
#define AV_WL64(p, d) do { \
                    ((uint8_t*)(p))[0] = (d);     \
                    ((uint8_t*)(p))[1] = (d)>>8;  \
                    ((uint8_t*)(p))[2] = (d)>>16; \
                    ((uint8_t*)(p))[3] = (d)>>24; \
                    ((uint8_t*)(p))[4] = (d)>>32; \
                    ((uint8_t*)(p))[5] = (d)>>40; \
                    ((uint8_t*)(p))[6] = (d)>>48; \
                    ((uint8_t*)(p))[7] = (d)>>56; } while(0)

static inline uint16_t bswap_16(uint16_t x)
{
    x= (x>>8) | (x<<8);
    return x;
}

static inline uint32_t bswap_32(uint32_t x)
{
    x= ((x<<8)&0xFF00FF00) | ((x>>8)&0x00FF00FF);
    x= (x>>16) | (x<<16);
    return x;
}

static inline uint64_t bswap_64(uint64_t x)
{
    union {
        uint64_t ll;
        uint32_t l[2];
    } w, r;
    w.ll = x;
    r.l[0] = bswap_32 (w.l[1]);
    r.l[1] = bswap_32 (w.l[0]);
    return r.ll;
}

#ifdef WORDS_BIGENDIAN
#define be2me_16(x) (x)
#define be2me_32(x) (x)
#define be2me_64(x) (x)
#define le2me_16(x) bswap_16(x)
#define le2me_32(x) bswap_32(x)
#define le2me_64(x) bswap_64(x)
#else
#define be2me_16(x) bswap_16(x)
#define be2me_32(x) bswap_32(x)
#define be2me_64(x) bswap_64(x)
#define le2me_16(x) (x)
#define le2me_32(x) (x)
#define le2me_64(x) (x)
#endif

#endif
