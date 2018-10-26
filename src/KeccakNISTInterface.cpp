/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <string.h>
#include "KeccakNISTInterface.h"
#include "KeccakF-1600-interface.h"

SHA3_HashReturn SHA3_init(hashState *state, int hashbitlen)
{
    switch(hashbitlen) {
        case 0: // Default parameters, arbitrary length output
            InitSponge((Node_SHA3::spongeState*)state, 1024, 576);
            break;
        case 224:
            InitSponge((Node_SHA3::spongeState*)state, 1152, 448);
            break;
        case 256:
            InitSponge((Node_SHA3::spongeState*)state, 1088, 512);
            break;
        case 384:
            InitSponge((Node_SHA3::spongeState*)state, 832, 768);
            break;
        case 512:
            InitSponge((Node_SHA3::spongeState*)state, 576, 1024);
            break;
        default:
            return BAD_HASHLEN;
    }
    state->fixedOutputLength = hashbitlen;
    return SUCCESS;
}

SHA3_HashReturn SHA3_update(hashState *state, const SHA3_BitSequence *data, SHA3_DataLength databitlen)
{
    if ((databitlen % 8) == 0)
        return (SHA3_HashReturn) Absorb((Node_SHA3::spongeState*)state, data, databitlen);
    else {
        SHA3_HashReturn ret = (SHA3_HashReturn) Absorb((Node_SHA3::spongeState*)state, data, databitlen - (databitlen % 8));
        if (ret == SUCCESS) {
            unsigned char lastByte;
            // Align the last partial byte to the least significant bits
            lastByte = data[databitlen/8] >> (8 - (databitlen % 8));
            return (SHA3_HashReturn) Absorb((Node_SHA3::spongeState*)state, &lastByte, databitlen % 8);
        }
        else
            return ret;
    }
}

SHA3_HashReturn SHA3_final(hashState *state, SHA3_BitSequence *hashval)
{
    return (SHA3_HashReturn) Squeeze(state, hashval, state->fixedOutputLength);
}

SHA3_HashReturn SHA3_hash(int hashbitlen, const SHA3_BitSequence *data, SHA3_DataLength databitlen, SHA3_BitSequence *hashval)
{
    hashState state;
    SHA3_HashReturn result;

    if ((hashbitlen != 224) && (hashbitlen != 256) && (hashbitlen != 384) && (hashbitlen != 512))
        return BAD_HASHLEN; // Only the four fixed output lengths available through this API
    result = SHA3_init(&state, hashbitlen);
    if (result != SUCCESS)
        return result;
    result = SHA3_update(&state, data, databitlen);
    if (result != SUCCESS)
        return result;
    result = SHA3_final(&state, hashval);
    return result;
}
