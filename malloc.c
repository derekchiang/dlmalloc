#include <errno.h>
#include <limits.h>
#include <string.h>

#include "malloc.h"
#include "memreq.h"

// For debugging
// static char buffer[2000];

// #define debug(...) sprintf(buffer, __VA_ARGS__); puts(buffer); fflush(stdout);

struct mchunk {
    size_t size; // size of the chunk, including headers
    struct mchunk *next; // pointer to the next chunk in the same bin
    struct mchunk *prev; // pointer to the previous chunk in the same bin
};

typedef struct mchunk mchunk;

typedef struct {
    mchunk head; // A dummy chunk.  It's there so that every normal chunk
    // will have a next and a prev to point to.

    // The dirty bit is used to indicate whether the chunks
    // in this bin can be merged.
    size_t dirty;
} mbin;

// 4 on 32-bit machine, 8 on 64 bit machine.
#define SIZE_SZ (sizeof(size_t))

// MINSIZE is the minumum size of an allocated chunk
// It should be 16 on 32-bit machine and 32 on 64-bit machine.
// Machines that are not 32 or 64 bits are not supported.
#define MINSIZE (sizeof(mchunk) + SIZE_SZ)

// This would be 2 in 32-bit machines and 3 in 64-bit machines.
#define QUADRANT_POWER (((MINSIZE / 4) == 4) ? 2 : 3)

// These two macros make calculating which bin a requested size
// belongs to very easy.  See request_to_size for details.
#define MALLOC_CHUNK_OVERHEAD (SIZE_SZ + SIZE_SZ)
#define MALLOC_ALIGN_MASK (MALLOC_CHUNK_OVERHEAD - 1)

// The total number of bins
// Every 4 bins are in charge of a power range.  For example,
// bin 80 to 83 are in charge of 2^20 to (2^21)-1.
//
// On 64-bit machine, the address goes up to 2^64 so we need
// 64 * 4 = 256 bins.
#define MAXBIN 256

// Statically allocate the bins.  Code was generated using a
// Python script.
static mbin bins[MAXBIN] = {
    { { 0, &(bins[0].head),  &(bins[0].head) }, 0 },
    { { 0, &(bins[1].head),  &(bins[1].head) }, 0 },
    { { 0, &(bins[2].head),  &(bins[2].head) }, 0 },
    { { 0, &(bins[3].head),  &(bins[3].head) }, 0 },
    { { 0, &(bins[4].head),  &(bins[4].head) }, 0 },
    { { 0, &(bins[5].head),  &(bins[5].head) }, 0 },
    { { 0, &(bins[6].head),  &(bins[6].head) }, 0 },
    { { 0, &(bins[7].head),  &(bins[7].head) }, 0 },
    { { 0, &(bins[8].head),  &(bins[8].head) }, 0 },
    { { 0, &(bins[9].head),  &(bins[9].head) }, 0 },

    { { 0, &(bins[10].head), &(bins[10].head) }, 0 },
    { { 0, &(bins[11].head), &(bins[11].head) }, 0 },
    { { 0, &(bins[12].head), &(bins[12].head) }, 0 },
    { { 0, &(bins[13].head), &(bins[13].head) }, 0 },
    { { 0, &(bins[14].head), &(bins[14].head) }, 0 },
    { { 0, &(bins[15].head), &(bins[15].head) }, 0 },
    { { 0, &(bins[16].head), &(bins[16].head) }, 0 },
    { { 0, &(bins[17].head), &(bins[17].head) }, 0 },
    { { 0, &(bins[18].head), &(bins[18].head) }, 0 },
    { { 0, &(bins[19].head), &(bins[19].head) }, 0 },

    { { 0, &(bins[20].head), &(bins[20].head) }, 0 },
    { { 0, &(bins[21].head), &(bins[21].head) }, 0 },
    { { 0, &(bins[22].head), &(bins[22].head) }, 0 },
    { { 0, &(bins[23].head), &(bins[23].head) }, 0 },
    { { 0, &(bins[24].head), &(bins[24].head) }, 0 },
    { { 0, &(bins[25].head), &(bins[25].head) }, 0 },
    { { 0, &(bins[26].head), &(bins[26].head) }, 0 },
    { { 0, &(bins[27].head), &(bins[27].head) }, 0 },
    { { 0, &(bins[28].head), &(bins[28].head) }, 0 },
    { { 0, &(bins[29].head), &(bins[29].head) }, 0 },

    { { 0, &(bins[30].head), &(bins[30].head) }, 0 },
    { { 0, &(bins[31].head), &(bins[31].head) }, 0 },
    { { 0, &(bins[32].head), &(bins[32].head) }, 0 },
    { { 0, &(bins[33].head), &(bins[33].head) }, 0 },
    { { 0, &(bins[34].head), &(bins[34].head) }, 0 },
    { { 0, &(bins[35].head), &(bins[35].head) }, 0 },
    { { 0, &(bins[36].head), &(bins[36].head) }, 0 },
    { { 0, &(bins[37].head), &(bins[37].head) }, 0 },
    { { 0, &(bins[38].head), &(bins[38].head) }, 0 },
    { { 0, &(bins[39].head), &(bins[39].head) }, 0 },

    { { 0, &(bins[40].head), &(bins[40].head) }, 0 },
    { { 0, &(bins[41].head), &(bins[41].head) }, 0 },
    { { 0, &(bins[42].head), &(bins[42].head) }, 0 },
    { { 0, &(bins[43].head), &(bins[43].head) }, 0 },
    { { 0, &(bins[44].head), &(bins[44].head) }, 0 },
    { { 0, &(bins[45].head), &(bins[45].head) }, 0 },
    { { 0, &(bins[46].head), &(bins[46].head) }, 0 },
    { { 0, &(bins[47].head), &(bins[47].head) }, 0 },
    { { 0, &(bins[48].head), &(bins[48].head) }, 0 },
    { { 0, &(bins[49].head), &(bins[49].head) }, 0 },

    { { 0, &(bins[50].head), &(bins[50].head) }, 0 },
    { { 0, &(bins[51].head), &(bins[51].head) }, 0 },
    { { 0, &(bins[52].head), &(bins[52].head) }, 0 },
    { { 0, &(bins[53].head), &(bins[53].head) }, 0 },
    { { 0, &(bins[54].head), &(bins[54].head) }, 0 },
    { { 0, &(bins[55].head), &(bins[55].head) }, 0 },
    { { 0, &(bins[56].head), &(bins[56].head) }, 0 },
    { { 0, &(bins[57].head), &(bins[57].head) }, 0 },
    { { 0, &(bins[58].head), &(bins[58].head) }, 0 },
    { { 0, &(bins[59].head), &(bins[59].head) }, 0 },

    { { 0, &(bins[60].head), &(bins[60].head) }, 0 },
    { { 0, &(bins[61].head), &(bins[61].head) }, 0 },
    { { 0, &(bins[62].head), &(bins[62].head) }, 0 },
    { { 0, &(bins[63].head), &(bins[63].head) }, 0 },
    { { 0, &(bins[64].head), &(bins[64].head) }, 0 },
    { { 0, &(bins[65].head), &(bins[65].head) }, 0 },
    { { 0, &(bins[66].head), &(bins[66].head) }, 0 },
    { { 0, &(bins[67].head), &(bins[67].head) }, 0 },
    { { 0, &(bins[68].head), &(bins[68].head) }, 0 },
    { { 0, &(bins[69].head), &(bins[69].head) }, 0 },

    { { 0, &(bins[70].head), &(bins[70].head) }, 0 },
    { { 0, &(bins[71].head), &(bins[71].head) }, 0 },
    { { 0, &(bins[72].head), &(bins[72].head) }, 0 },
    { { 0, &(bins[73].head), &(bins[73].head) }, 0 },
    { { 0, &(bins[74].head), &(bins[74].head) }, 0 },
    { { 0, &(bins[75].head), &(bins[75].head) }, 0 },
    { { 0, &(bins[76].head), &(bins[76].head) }, 0 },
    { { 0, &(bins[77].head), &(bins[77].head) }, 0 },
    { { 0, &(bins[78].head), &(bins[78].head) }, 0 },
    { { 0, &(bins[79].head), &(bins[79].head) }, 0 },

    { { 0, &(bins[80].head), &(bins[80].head) }, 0 },
    { { 0, &(bins[81].head), &(bins[81].head) }, 0 },
    { { 0, &(bins[82].head), &(bins[82].head) }, 0 },
    { { 0, &(bins[83].head), &(bins[83].head) }, 0 },
    { { 0, &(bins[84].head), &(bins[84].head) }, 0 },
    { { 0, &(bins[85].head), &(bins[85].head) }, 0 },
    { { 0, &(bins[86].head), &(bins[86].head) }, 0 },
    { { 0, &(bins[87].head), &(bins[87].head) }, 0 },
    { { 0, &(bins[88].head), &(bins[88].head) }, 0 },
    { { 0, &(bins[89].head), &(bins[89].head) }, 0 },

    { { 0, &(bins[90].head), &(bins[90].head) }, 0 },
    { { 0, &(bins[91].head), &(bins[91].head) }, 0 },
    { { 0, &(bins[92].head), &(bins[92].head) }, 0 },
    { { 0, &(bins[93].head), &(bins[93].head) }, 0 },
    { { 0, &(bins[94].head), &(bins[94].head) }, 0 },
    { { 0, &(bins[95].head), &(bins[95].head) }, 0 },
    { { 0, &(bins[96].head), &(bins[96].head) }, 0 },
    { { 0, &(bins[97].head), &(bins[97].head) }, 0 },
    { { 0, &(bins[98].head), &(bins[98].head) }, 0 },
    { { 0, &(bins[99].head), &(bins[99].head) }, 0 },

    { { 0, &(bins[100].head), &(bins[100].head) }, 0 },
    { { 0, &(bins[101].head), &(bins[101].head) }, 0 },
    { { 0, &(bins[102].head), &(bins[102].head) }, 0 },
    { { 0, &(bins[103].head), &(bins[103].head) }, 0 },
    { { 0, &(bins[104].head), &(bins[104].head) }, 0 },
    { { 0, &(bins[105].head), &(bins[105].head) }, 0 },
    { { 0, &(bins[106].head), &(bins[106].head) }, 0 },
    { { 0, &(bins[107].head), &(bins[107].head) }, 0 },
    { { 0, &(bins[108].head), &(bins[108].head) }, 0 },
    { { 0, &(bins[109].head), &(bins[109].head) }, 0 },

    { { 0, &(bins[110].head), &(bins[110].head) }, 0 },
    { { 0, &(bins[111].head), &(bins[111].head) }, 0 },
    { { 0, &(bins[112].head), &(bins[112].head) }, 0 },
    { { 0, &(bins[113].head), &(bins[113].head) }, 0 },
    { { 0, &(bins[114].head), &(bins[114].head) }, 0 },
    { { 0, &(bins[115].head), &(bins[115].head) }, 0 },
    { { 0, &(bins[116].head), &(bins[116].head) }, 0 },
    { { 0, &(bins[117].head), &(bins[117].head) }, 0 },
    { { 0, &(bins[118].head), &(bins[118].head) }, 0 },
    { { 0, &(bins[119].head), &(bins[119].head) }, 0 },

    { { 0, &(bins[120].head), &(bins[120].head) }, 0 },
    { { 0, &(bins[121].head), &(bins[121].head) }, 0 },
    { { 0, &(bins[122].head), &(bins[122].head) }, 0 },
    { { 0, &(bins[123].head), &(bins[123].head) }, 0 },
    { { 0, &(bins[124].head), &(bins[124].head) }, 0 },
    { { 0, &(bins[125].head), &(bins[125].head) }, 0 },
    { { 0, &(bins[126].head), &(bins[126].head) }, 0 },
    { { 0, &(bins[127].head), &(bins[127].head) }, 0 },
    { { 0, &(bins[128].head), &(bins[128].head) }, 0 },
    { { 0, &(bins[129].head), &(bins[129].head) }, 0 },

    { { 0, &(bins[130].head), &(bins[130].head) }, 0 },
    { { 0, &(bins[131].head), &(bins[131].head) }, 0 },
    { { 0, &(bins[132].head), &(bins[132].head) }, 0 },
    { { 0, &(bins[133].head), &(bins[133].head) }, 0 },
    { { 0, &(bins[134].head), &(bins[134].head) }, 0 },
    { { 0, &(bins[135].head), &(bins[135].head) }, 0 },
    { { 0, &(bins[136].head), &(bins[136].head) }, 0 },
    { { 0, &(bins[137].head), &(bins[137].head) }, 0 },
    { { 0, &(bins[138].head), &(bins[138].head) }, 0 },
    { { 0, &(bins[139].head), &(bins[139].head) }, 0 },


    { { 0, &(bins[140].head), &(bins[140].head) }, 0 },
    { { 0, &(bins[141].head), &(bins[141].head) }, 0 },
    { { 0, &(bins[142].head), &(bins[142].head) }, 0 },
    { { 0, &(bins[143].head), &(bins[143].head) }, 0 },
    { { 0, &(bins[144].head), &(bins[144].head) }, 0 },
    { { 0, &(bins[145].head), &(bins[145].head) }, 0 },
    { { 0, &(bins[146].head), &(bins[146].head) }, 0 },
    { { 0, &(bins[147].head), &(bins[147].head) }, 0 },
    { { 0, &(bins[148].head), &(bins[148].head) }, 0 },
    { { 0, &(bins[149].head), &(bins[149].head) }, 0 },


    { { 0, &(bins[150].head), &(bins[150].head) }, 0 },
    { { 0, &(bins[151].head), &(bins[151].head) }, 0 },
    { { 0, &(bins[152].head), &(bins[152].head) }, 0 },
    { { 0, &(bins[153].head), &(bins[153].head) }, 0 },
    { { 0, &(bins[154].head), &(bins[154].head) }, 0 },
    { { 0, &(bins[155].head), &(bins[155].head) }, 0 },
    { { 0, &(bins[156].head), &(bins[156].head) }, 0 },
    { { 0, &(bins[157].head), &(bins[157].head) }, 0 },
    { { 0, &(bins[158].head), &(bins[158].head) }, 0 },
    { { 0, &(bins[159].head), &(bins[159].head) }, 0 },


    { { 0, &(bins[160].head), &(bins[160].head) }, 0 },
    { { 0, &(bins[161].head), &(bins[161].head) }, 0 },
    { { 0, &(bins[162].head), &(bins[162].head) }, 0 },
    { { 0, &(bins[163].head), &(bins[163].head) }, 0 },
    { { 0, &(bins[164].head), &(bins[164].head) }, 0 },
    { { 0, &(bins[165].head), &(bins[165].head) }, 0 },
    { { 0, &(bins[166].head), &(bins[166].head) }, 0 },
    { { 0, &(bins[167].head), &(bins[167].head) }, 0 },
    { { 0, &(bins[168].head), &(bins[168].head) }, 0 },
    { { 0, &(bins[169].head), &(bins[169].head) }, 0 },


    { { 0, &(bins[170].head), &(bins[170].head) }, 0 },
    { { 0, &(bins[171].head), &(bins[171].head) }, 0 },
    { { 0, &(bins[172].head), &(bins[172].head) }, 0 },
    { { 0, &(bins[173].head), &(bins[173].head) }, 0 },
    { { 0, &(bins[174].head), &(bins[174].head) }, 0 },
    { { 0, &(bins[175].head), &(bins[175].head) }, 0 },
    { { 0, &(bins[176].head), &(bins[176].head) }, 0 },
    { { 0, &(bins[177].head), &(bins[177].head) }, 0 },
    { { 0, &(bins[178].head), &(bins[178].head) }, 0 },
    { { 0, &(bins[179].head), &(bins[179].head) }, 0 },


    { { 0, &(bins[180].head), &(bins[180].head) }, 0 },
    { { 0, &(bins[181].head), &(bins[181].head) }, 0 },
    { { 0, &(bins[182].head), &(bins[182].head) }, 0 },
    { { 0, &(bins[183].head), &(bins[183].head) }, 0 },
    { { 0, &(bins[184].head), &(bins[184].head) }, 0 },
    { { 0, &(bins[185].head), &(bins[185].head) }, 0 },
    { { 0, &(bins[186].head), &(bins[186].head) }, 0 },
    { { 0, &(bins[187].head), &(bins[187].head) }, 0 },
    { { 0, &(bins[188].head), &(bins[188].head) }, 0 },
    { { 0, &(bins[189].head), &(bins[189].head) }, 0 },


    { { 0, &(bins[190].head), &(bins[190].head) }, 0 },
    { { 0, &(bins[191].head), &(bins[191].head) }, 0 },
    { { 0, &(bins[192].head), &(bins[192].head) }, 0 },
    { { 0, &(bins[193].head), &(bins[193].head) }, 0 },
    { { 0, &(bins[194].head), &(bins[194].head) }, 0 },
    { { 0, &(bins[195].head), &(bins[195].head) }, 0 },
    { { 0, &(bins[196].head), &(bins[196].head) }, 0 },
    { { 0, &(bins[197].head), &(bins[197].head) }, 0 },
    { { 0, &(bins[198].head), &(bins[198].head) }, 0 },
    { { 0, &(bins[199].head), &(bins[199].head) }, 0 },


    { { 0, &(bins[200].head), &(bins[200].head) }, 0 },
    { { 0, &(bins[201].head), &(bins[201].head) }, 0 },
    { { 0, &(bins[202].head), &(bins[202].head) }, 0 },
    { { 0, &(bins[203].head), &(bins[203].head) }, 0 },
    { { 0, &(bins[204].head), &(bins[204].head) }, 0 },
    { { 0, &(bins[205].head), &(bins[205].head) }, 0 },
    { { 0, &(bins[206].head), &(bins[206].head) }, 0 },
    { { 0, &(bins[207].head), &(bins[207].head) }, 0 },
    { { 0, &(bins[208].head), &(bins[208].head) }, 0 },
    { { 0, &(bins[209].head), &(bins[209].head) }, 0 },


    { { 0, &(bins[210].head), &(bins[210].head) }, 0 },
    { { 0, &(bins[211].head), &(bins[211].head) }, 0 },
    { { 0, &(bins[212].head), &(bins[212].head) }, 0 },
    { { 0, &(bins[213].head), &(bins[213].head) }, 0 },
    { { 0, &(bins[214].head), &(bins[214].head) }, 0 },
    { { 0, &(bins[215].head), &(bins[215].head) }, 0 },
    { { 0, &(bins[216].head), &(bins[216].head) }, 0 },
    { { 0, &(bins[217].head), &(bins[217].head) }, 0 },
    { { 0, &(bins[218].head), &(bins[218].head) }, 0 },
    { { 0, &(bins[219].head), &(bins[219].head) }, 0 },


    { { 0, &(bins[220].head), &(bins[220].head) }, 0 },
    { { 0, &(bins[221].head), &(bins[221].head) }, 0 },
    { { 0, &(bins[222].head), &(bins[222].head) }, 0 },
    { { 0, &(bins[223].head), &(bins[223].head) }, 0 },
    { { 0, &(bins[224].head), &(bins[224].head) }, 0 },
    { { 0, &(bins[225].head), &(bins[225].head) }, 0 },
    { { 0, &(bins[226].head), &(bins[226].head) }, 0 },
    { { 0, &(bins[227].head), &(bins[227].head) }, 0 },
    { { 0, &(bins[228].head), &(bins[228].head) }, 0 },
    { { 0, &(bins[229].head), &(bins[229].head) }, 0 },


    { { 0, &(bins[230].head), &(bins[230].head) }, 0 },
    { { 0, &(bins[231].head), &(bins[231].head) }, 0 },
    { { 0, &(bins[232].head), &(bins[232].head) }, 0 },
    { { 0, &(bins[233].head), &(bins[233].head) }, 0 },
    { { 0, &(bins[234].head), &(bins[234].head) }, 0 },
    { { 0, &(bins[235].head), &(bins[235].head) }, 0 },
    { { 0, &(bins[236].head), &(bins[236].head) }, 0 },
    { { 0, &(bins[237].head), &(bins[237].head) }, 0 },
    { { 0, &(bins[238].head), &(bins[238].head) }, 0 },
    { { 0, &(bins[239].head), &(bins[239].head) }, 0 },


    { { 0, &(bins[240].head), &(bins[240].head) }, 0 },
    { { 0, &(bins[241].head), &(bins[241].head) }, 0 },
    { { 0, &(bins[242].head), &(bins[242].head) }, 0 },
    { { 0, &(bins[243].head), &(bins[243].head) }, 0 },
    { { 0, &(bins[244].head), &(bins[244].head) }, 0 },
    { { 0, &(bins[245].head), &(bins[245].head) }, 0 },
    { { 0, &(bins[246].head), &(bins[246].head) }, 0 },
    { { 0, &(bins[247].head), &(bins[247].head) }, 0 },
    { { 0, &(bins[248].head), &(bins[248].head) }, 0 },
    { { 0, &(bins[249].head), &(bins[249].head) }, 0 },


    { { 0, &(bins[250].head), &(bins[250].head) }, 0 },
    { { 0, &(bins[251].head), &(bins[251].head) }, 0 },
    { { 0, &(bins[252].head), &(bins[252].head) }, 0 },
    { { 0, &(bins[253].head), &(bins[253].head) }, 0 },
    { { 0, &(bins[254].head), &(bins[254].head) }, 0 },
    { { 0, &(bins[255].head), &(bins[255].head) }, 0 }
};

// size_to_bin maps a given size to a bin.
static inline mbin *size_to_bin(size_t sz)
{
    mbin *b = bins;
    // If size is 2 to the power of N, then
    // it should reside in a bin between 4N and 4N+3.
    while (sz >= (MINSIZE * 2)) {
        b += 4;
        sz >>= 1;
    }

    // We don't need to check that sz > MINSIZE because it's guaranteed
    // by the rest of the program.
    b += (sz - MINSIZE) >> QUADRANT_POWER;

    return b;
}

// request_to_size translates an arbitrary size to an aligned size that
// can be called with sbrk.
static inline size_t request_to_size(size_t request)
{
    if (request == 0) {
        return MINSIZE;
    } else {
        // Bit manipulation.  To understand how this works, take
        // MALLOC_MIN_OVERHEAD as 1000 and MALLOC_ALIGN_MASK as
        // 0111.  Say a request is of size 100011 (35), then this statement
        // becomes:
        // 100011 + 010000 + 001111 & ~(001111) = 1000000 (64)
        return ((request + MALLOC_CHUNK_OVERHEAD + MALLOC_ALIGN_MASK)
                & ~(MALLOC_ALIGN_MASK));
    }
}

// is_aligned checks if a memory address is aligned.
static inline int is_aligned(void *m)
{
    // Since MALLOC_ALIGN_MASK is 1111, if the statement
    // evaluates to zero, then m's lower four bits are
    // 0000, which means it's a multiple of MALLOC_CHUNK_OVERHEAD.
    return ((size_t) (m) & (MALLOC_ALIGN_MASK)) == 0;
}

// When a chunk is in use, we set the lowest bit of its size to 1 by
// "OR"ing the size with INUSE.
#define INUSE 0x1

// inuse checks if the lowest bit of chunk->size is 1.
static inline int inuse(mchunk *chunk)
{
    return chunk->size & INUSE;
}

// set_inuse sets the lowest bit of chunk->size to 1.
static inline void set_inuse(mchunk *chunk)
{
    chunk->size |= INUSE;
}

// unset_inuse sets the lowest bit of chunk->size to 0.
static inline void unset_inuse(mchunk *chunk)
{
    chunk->size &= ~INUSE;
}

// next_chunk returns a pointer to the next memory chunk.
static inline mchunk *next_chunk(mchunk *p)
{
    return ((mchunk *)((char *)(p) + (p)->size));
}

// prev_chunk returns a pointer to the previous memory chunk.
static inline mchunk *prev_chunk(mchunk *p)
{
    // It doesn't hurt to & ~(INUSE) even if it's not inuse.
    size_t prev_size = ((size_t *)(p))[-1] & ~(INUSE);
    return (mchunk *)((char *)(p) - prev_size);
}

// BACK_SIZE_PTR returns a pointer to the size in the back of ptr
#define BACK_SIZE_PTR(ptr) ((size_t*)(((char *) ptr) + ptr->size - SIZE_SZ))

// set_size sets ptr's size to sz, both in the front and in the back.
static inline void set_size(mchunk *ptr, size_t sz)
{
    // Set the size in the front
    ptr->size = sz;

    // Set the size in the back
    *(BACK_SIZE_PTR(ptr)) = sz;
}

// chunk_to_mem converts a memory chunk to a void* that a user can use.
// It sets the chunk as in use.
static inline void *chunk_to_mem(mchunk *chunk)
{
    set_inuse(chunk);
    // We don't need to keep bin pointers "next" and "prev" across
    // memory allocation.  In other words, the only thing we
    // need to keep is the size of the chunk.  Therefore,
    // we can give the client everything after chunk + SIZE_SZ
    return (void *)((char *)chunk + SIZE_SZ);
}

// mem_to_chunk converts a memory pointer to a pointer to its
// corresponding chunk.  It sets it as not in use.
static inline mchunk *mem_to_chunk(void *mem)
{
    mchunk *chunk = (mchunk *) ((char *)mem - SIZE_SZ);
    unset_inuse(chunk);
    return chunk;
}

// functions for managing bins

// The first bin.
#define FIRSTBIN (&(bins[0]))

// We keep track of the largest used bin, so that when we want to
// merge memory chunks, we can search from this bin backward.  And
// when we want to search a large-enough bin, we can search up to
// this bin.
static mbin *max_used_bin = FIRSTBIN;

// Pointer to the head of a bin
#define BIN_HEAD_PTR(bin) (&(bin->head))

// Check if a bin is empty
#define BIN_IS_EMPTY(bin) (BIN_HEAD_PTR(bin)->prev == BIN_HEAD_PTR(bin))

// rm_chunk_from_bin removes a chunk from its bin.
static inline void rm_chunk_from_bin(mchunk *chunk)
{
    mchunk *p = chunk->prev;
    mchunk *n = chunk->next;
    p->next = n;
    n->prev = p;
}

// place_chunk_back places a chunk to the back of its corresponding bin.
// We only place a chunk to the back of a bin if the chunk is consolidated,
// a.k.a. it has already been merged with all its neighboring chunks.
static inline void place_chunk_back(mchunk *chunk)
{
    mbin *bin = size_to_bin(chunk->size);
    mchunk *head = BIN_HEAD_PTR(bin);
    mchunk *back = head->prev;
    back->next = head->prev = chunk;
    chunk->prev = back;
    chunk->next = head;

    // If head is equal to back, then the bin was empty before
    // this addition.  We thus make sure every bin is set to
    // max_used_bin at most once.
    if (head == back && bin > max_used_bin) {
        max_used_bin = bin;
    }
}

// place_chunk_front places a chunk to the front of its corresponding bin.
static inline void place_chunk_front(mchunk *chunk)
{
    mbin *bin = size_to_bin(chunk->size);
    mchunk *head = BIN_HEAD_PTR(bin);
    mchunk *front = head->next;
    front->prev = head->next = chunk;
    chunk->prev = head;
    chunk->next = front;

    if (head == front && bin > max_used_bin) {
        max_used_bin = bin;
    }

    // We set the dirty bit to 1 to indicate that it might be possible
    // to merge some chunks in the bin.
    // The reason why we don't do this in place_chunk_back() is that
    // we only place a chunk at the back of a bin if the chunk is
    // already consolidated, which means it can't be further merged.
    bin->dirty = 1;
}

// split_chunk splits a chunk using a given offset.  It then places the
// splitted portion, a.k.a. the portion after the offset, to the back
// of a bin for later use.
static inline void split_chunk(mchunk *chunk, size_t offset)
{
    // debug("splitting chunk of size %d to %d\n", (int)chunk->size, (int)offset);
    if (chunk->size > offset) {
        size_t new_chunk_sz = chunk->size - offset;
        mchunk *new_chunk = (mchunk *)((char *)chunk + offset);
        if (new_chunk_sz >= MINSIZE) {
            set_size(chunk, offset);
            set_size(new_chunk, new_chunk_sz);
            place_chunk_back(new_chunk);
        }
    }
}


// Keeps check of the end of the last chunk of memory given by sbrk.
static size_t *last_sbrk_end;

// The minimal amount of bytes we request from the system.  We want
// to do this because sbrk is a relatively expensive operation involving
// context switch.  If a user keeps requesting a very small number
// of bytes, we can avoid calling sbrk many times by requesting a large
// chunk at once.
#define SBRK_UNIT 4096

// get_memory_from_sys requests memory from the system.
static mchunk *get_memory_from_sys(size_t request)
{
    mchunk *chunk;
    // sz is the minimum multiple of SBRK_UNIT that is greater
    // than request + 2 * SIZE_SZ.
    size_t sz = ((request + SBRK_UNIT - 1 + SIZE_SZ + SIZE_SZ)
                 / SBRK_UNIT) * SBRK_UNIT;

    // Get memory from system.
    size_t *ptr = (size_t *)(get_memory(sz));

    if (ptr == NULL) {
        // No more memory.  Report the error.
        errno = ENOMEM;
        return NULL;
    }

    // We are maintaining the invariant that last_sbrk_end is one SIZE_T
    // behind where the new sbrk should begin.
    if ((last_sbrk_end + 1) != ptr) {
        // Either it's the first time malloc is called, or the client
        // has called sbrk himself.

        // Making sure it's aligned.
        while (!is_aligned(ptr)) {
            ptr++;
            sz -= SIZE_SZ;
        }


        // We mark the front as in use, so we won't go out of bound
        // when we merge memory chunks backward.
        *ptr = SIZE_SZ | INUSE;
        ptr++;

        chunk = (mchunk *)ptr;
        set_size(chunk, sz - (SIZE_SZ + SIZE_SZ));

    } else {
        chunk = (mchunk *)(last_sbrk_end);
        set_size(chunk, sz);
        mchunk *prev = prev_chunk(chunk);
        if (!inuse(prev)) {
            rm_chunk_from_bin(prev);
            set_size(prev, chunk->size + prev->size);
            chunk = prev;
        }
    }

    last_sbrk_end = (size_t *)((char *)chunk + chunk->size);

    // Mark the end as in use, so that we won't go out of bound
    // when we merge memory chunks forward.
    *last_sbrk_end = SIZE_SZ | INUSE;

    // This is necessary to ensure that it's safe to call
    // rm_chunk_from_bin with this, which we do in malloc().
    chunk->next = chunk->prev = chunk;

    return chunk;
}

// merge_and_find_chunks merges memory chunks until we get a chunk
// that is greater than the given size, at which point we stop,
// split the chunk, and return to the user.
//
// It returns NULL if, after merging, still no chunk that is big enough
// can be found.
static mchunk *merge_and_find_chunks(size_t sz)
{
    // We first find the largest bin that is not empty
    while ((max_used_bin >= FIRSTBIN) &&
           BIN_IS_EMPTY(max_used_bin)) {
        max_used_bin->dirty = 0;
        max_used_bin -= 1;
    }

    mbin *b = max_used_bin;
    while (b >= FIRSTBIN) {
        if (b->dirty) {
            mchunk *bin_head = BIN_HEAD_PTR(b);
            mchunk *chunk = bin_head->next;
            while (chunk != bin_head) {
                // Keep track of the next chunk to merge in this bin
                mchunk *next_to_merge = chunk->next;

                // Keep track of whether any merging has happened
                int merged = 0;

                // Merge backwards
                mchunk *prev;
                while (!inuse(prev = prev_chunk(chunk))) {
                    if (!merged) {
                        merged = 1;
                        rm_chunk_from_bin(chunk);
                    }
                    if (prev == next_to_merge) {
                        next_to_merge = prev->next;
                    }
                    rm_chunk_from_bin(prev);
                    set_size(prev, prev->size + chunk->size);
                    chunk = prev;
                }

                // Merge forward
                mchunk *next;
                while (!inuse(next = next_chunk(chunk))) {
                    if (!merged) {
                        merged = 1;
                        rm_chunk_from_bin(chunk);
                    }
                    if (next == next_to_merge) {
                        next_to_merge = next->next;
                    }
                    rm_chunk_from_bin(next);
                    set_size(chunk, chunk->size + next->size);
                }

                if (merged) {
                    if (chunk->size >= sz) {
                        // Make it safe to call with rm_chunk_from_bin
                        chunk->next = chunk->prev = chunk;
                        return chunk;
                    } else {
                        // If it's not big enough to be returned, place it in
                        // the right bin.
                        place_chunk_back(chunk);
                    }
                }

                chunk = next_to_merge;
            }

            // We have tried to merge the chunks in this bin, so we set
            // the dirty bit back to 0.
            b->dirty = 0;
        }
        b--;
    }

    return NULL;
}

void *malloc(size_t sz)
{
    // The actual size that we should be getting.
    size_t aligned_sz = request_to_size(sz);

    // We do four things in order:
    // 1. Check if the corresponding bin has a legit chunk; if so, returns it.
    mbin *bin = size_to_bin(aligned_sz);
    mchunk *bin_head = BIN_HEAD_PTR(bin);
    mchunk *chunk = bin_head->next;
    while (chunk != bin_head) {
        if (chunk->size >= aligned_sz) {
            rm_chunk_from_bin(chunk);
            split_chunk(chunk, aligned_sz);
            return chunk_to_mem(chunk);
        }
        chunk = chunk->next;
    }

    // 2. Get a chunk from a larger bin
    while (++bin <= max_used_bin) {
        if (!BIN_IS_EMPTY(bin)) {
            chunk = BIN_HEAD_PTR(bin)->prev;
            rm_chunk_from_bin(chunk);
            split_chunk(chunk, aligned_sz);
            return chunk_to_mem(chunk);
        }
    }

    // 3. If all larger bins are empty, we merge memory chunks
    // and return if any resulting chunks are big though.
    mchunk *merged_mem = merge_and_find_chunks(aligned_sz);
    if (merged_mem != NULL) {
        chunk = merged_mem;
        rm_chunk_from_bin(chunk);
        split_chunk(chunk, aligned_sz);
        return chunk_to_mem(chunk);
    }

    // 4. If all of the above failed, we have to request new memory
    // from the system.
    chunk = get_memory_from_sys(aligned_sz);
    rm_chunk_from_bin(chunk);
    split_chunk(chunk, aligned_sz);
    return chunk_to_mem(chunk);
}

static size_t highest(size_t in)
{
    size_t num_bits = 0;

    while (in != 0) {
        ++num_bits;
        in >>= 1;
    }

    return num_bits;
}

void *calloc(size_t number, size_t size)
{
    size_t number_size = 0;

    /* This prevents an integer overflow.  A size_t is a typedef to an integer
    * large enough to index all of memory.  If we cannot fit in a size_t, then
    * we need to fail.
    */
    if (highest(number) + highest(size) > sizeof(size_t) * CHAR_BIT) {
        errno = ENOMEM;
        return NULL;
    }

    number_size = number * size;
    void *ret = malloc(number_size);

    if (ret) {
        memset(ret, 0, number_size);
    }

    return ret;
}

void *realloc(void *ptr, size_t request)
{
    if (ptr == 0) {
        return malloc(request);
    } else {
        size_t sz = request_to_size(request);
        mchunk *chunk = mem_to_chunk(ptr);
        size_t old_size = chunk->size;

        // Merge at the first chance
        mchunk *next;
        while (!inuse(next = next_chunk(chunk))) {
            rm_chunk_from_bin(next);
            set_size(chunk, chunk->size + next->size);
        }

        if (chunk->size > sz) {
            split_chunk(chunk, sz);
            return chunk_to_mem(chunk);
        } else {
            // If the current chunk is not big enough, we free
            // it and allocate a new chunk to return to the user.

            // so that malloc() won't merge this chunk accidentally.
            set_inuse(chunk);

            void *mem = malloc(sz);
            // Copy the original data to the new memory
            memmove(mem, ptr, old_size - SIZE_SZ);
            free(ptr);
            return mem;
        }
    }
}

void free(void *ptr)
{
    if (ptr != 0) {
        mchunk *chunk = mem_to_chunk(ptr);
        place_chunk_front(chunk);
    }
}