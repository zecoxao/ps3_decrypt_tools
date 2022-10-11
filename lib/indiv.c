/*
 * Copyright (c) 2011-2012 by ps3dev.net
 * This file is released under the GPLv2.
 */

#include "keys.h"
#include "aes.h"

void indiv_gen(u8 *seed0, u8 *seed1, u8 *seed2, u8 *seed3, u8 *indiv) {
    u32 i, rounds = INDIV_SIZE / INDIV_CHUNK_SIZE;
    u8 iv[0x10];
    aes_context aes_ctxt;

    memset(indiv, 0, INDIV_SIZE);

    //Copy seeds.
    if (seed0 != NULL)
        memcpy(indiv, seed0, INDIV_SEED_SIZE);
    if (seed1 != NULL)
        memcpy(indiv + INDIV_SEED_SIZE, seed1, INDIV_SEED_SIZE);
    if (seed2 != NULL)
        memcpy(indiv + INDIV_SEED_SIZE * 2, seed2, INDIV_SEED_SIZE);
    if (seed3 != NULL)
        memcpy(indiv + INDIV_SEED_SIZE * 3, seed3, INDIV_SEED_SIZE);

    //Generate.
    for (i = 0; i < rounds; i++, indiv += INDIV_CHUNK_SIZE) {
        //Set key and iv.
        aes_setkey_enc(&aes_ctxt, eid_root_key, KEY_BITS(ISO_ROOT_KEY_SIZE));
        memcpy(iv, eid_root_key + 0x20, ISO_ROOT_IV_SIZE);
        //Encrypt one chunk.
        aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, INDIV_CHUNK_SIZE, iv, indiv, indiv);
    }
}
