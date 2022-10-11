/*
 * Copyright (c) 2011-2012 by ps3dev.net
 * This file is released under the GPLv2.
 */

#ifndef _KEYS_H_
#define _KEYS_H_

#include "types.h"
#include "util.h"

/*! Get the number of bits from keysize. */
#define KEY_BITS(ks) (ks * 8)

/*! Isolation root key size. */
#define ISO_ROOT_KEY_SIZE 0x20
/*! Isolation root iv size. */
#define ISO_ROOT_IV_SIZE 0x10

/*! Individuals size. */
#define INDIV_SIZE 0x100
/*! Individuals chunk size. */
#define INDIV_CHUNK_SIZE 0x40

/*! Individuals seed key size. */
#define INDIV_SEED_SIZE 0x40

/*! EID0 keyseed size. */
#define EID0_KEYSEED_SIZE 0x10

/*! EID3 keyseed size. */
#define EID3_KEYSEED_SIZE 0x10

/*! EID3 static key size. */
#define EID3_STATIC_KEY_SIZE 0x10

/*! EID2 DES key size. */
#define EID2_DES_KEY_SIZE 0x08
/*! EID2 DES iv size. */
#define EID2_DES_IV_SIZE 0x08

extern u8 *eid_root_key;

/*! Syscon key seed. */

extern u8 syscon_key_seed[INDIV_SIZE];

extern u8 keyseed_for_srk2[0x10];

extern u8 seed_for_backup[0x10];

extern u8 eid1_master_key[0x10];

extern u8 zero_iv[0x10];

extern u8 session_key_create_key[0x80];

extern u8 unknown_seed[INDIV_SEED_SIZE];

extern u8 sherwood_ss_seed[INDIV_SEED_SIZE];

extern u8 ss_seed_one_more[INDIV_SEED_SIZE];

/*! Common individuals seed. */
extern u8 common_indiv_seed[INDIV_SEED_SIZE];
/*! EID0 individuals seed. */
extern u8 eid0_indiv_seed[INDIV_SEED_SIZE];
/*! EID1 individuals seed. */
extern u8 eid1_indiv_seed[INDIV_SEED_SIZE];
/*! EID2 individuals seed. */
extern u8 eid2_indiv_seed[INDIV_SEED_SIZE];
/*! EID3 individuals seed. */
extern u8 eid3_indiv_seed[INDIV_SEED_SIZE];
/*! EID4 individuals seed. */
extern u8 eid4_indiv_seed[INDIV_SEED_SIZE];

/*! EID0 keyseed version 1. */
extern u8 eid0_keyseed_0[EID0_KEYSEED_SIZE];
/*! EID0 keyseed version 6. */
extern u8 eid0_keyseed_6[EID0_KEYSEED_SIZE];
/*! EID0 keyseed version 6 encrypted private key. */
extern u8 eid0_keyseed_6_priv[EID0_KEYSEED_SIZE];
/*! EID0 keyseed version A. */
extern u8 eid0_keyseed_A[EID0_KEYSEED_SIZE];

/*! EID3 keyseed. */
extern u8 eid3_keyseed[EID3_KEYSEED_SIZE];

/*! EID3 static key. */
extern u8 eid3_static_key[EID3_STATIC_KEY_SIZE];

/*! EID2 DES key. */
extern u8 eid2_des_key[EID2_DES_KEY_SIZE];
/*! EID2 DES iv. */
extern u8 eid2_des_iv[EID2_DES_IV_SIZE];

#endif
