/*
 * Copyright (c) 2011-2012 by ps3dev.net
 * This file is released under the GPLv2.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "types.h"
#include "util.h"
#include "eid.h"
#include "keys.h"
#include "indiv.h"
#include "des.h"
#include "aes.h"
#include "sha1.h"
#include "aes_omac.h"

void eid_unpack(s8 *file) {
    u32 i, length;
    u8 *eid = _read_buffer(file, &length);

    if (eid != NULL) {
        eid_header_t *h = (eid_header_t *) eid;

        //Fix header.
        _es_eid_header(h);

        eid_entry_t *e = (eid_entry_t *) (eid + sizeof (eid_header_t));
        for (i = 0; i < h->entcnt; i++, e++) {
            //Fix entry.
            _es_eid_entry(e);

            s8 fname[128];
            sprintf(fname, "%s%d", file, (u32) e->entnum);
            printf("writing entry @ offset 0x%08x (0x%08x bytes) to %s\n", e->offset, e->size, fname);
            _write_buffer(fname, eid + e->offset, e->size);
        }

        free(eid);
    } else
        printf("error: could not read %s\n", file);
}

u8 *eid_get_entry(s8 *file, u64 entnum) {
    u32 i, length;
    u8 *res = NULL;
    u8 *eid = _read_buffer(file, &length);

    if (eid != NULL) {
        eid_header_t *h = (eid_header_t *) eid;

        //Fix header.
        _es_eid_header(h);

        eid_entry_t *e = (eid_entry_t *) (eid + sizeof (eid_header_t));
        for (i = 0; i < h->entcnt; i++, e++) {
            //Fix entry.
            _es_eid_entry(e);

            if (e->entnum == entnum) {
                res = (u8 *) malloc(e->size);
                memcpy(res, eid + e->offset, e->size);
                break;
            }
        }

        free(eid);
    } else
        printf("error: could not read %s\n", file);

    return res;
}

void eid0_decrypt_section(u8 *eid0_in, u8 *section_out, int i) {
    u8 indiv[INDIV_SIZE];
    u8 key[0x10];
	u8 key_priv[0x10];
	u8 zero_iv[0x10];
	memset (key_priv,0,0x10);
	memset (zero_iv,0,0x10);
    aes_context aes_ctxt;
	//aes_context aes_ctxt2;

    //Generate individuals.
    indiv_gen(eid0_indiv_seed, NULL, NULL, NULL, indiv);

    //Generate key.
    if (i == 0) {
        aes_setkey_enc(&aes_ctxt, indiv + INDIV_EID0_SEC_0_GENKEY_OFFSET, 0x100);
        aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, eid0_keyseed_0, key);
    } else if (i == 6) {
        aes_setkey_enc(&aes_ctxt, indiv + INDIV_EID0_SEC_0_GENKEY_OFFSET, 0x100);
        aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, eid0_keyseed_6, key);
		/*
		aes_setkey_enc(&aes_ctxt2, indiv + INDIV_EID0_SEC_0_GENKEY_OFFSET, 0x100);
        aes_crypt_ecb(&aes_ctxt2, AES_ENCRYPT, eid0_keyseed_6_priv, key_priv);
		*/
    } else if (i == 10) {
        aes_setkey_enc(&aes_ctxt, indiv + INDIV_EID0_SEC_0_GENKEY_OFFSET, 0x100);
        aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, eid0_keyseed_A, key);
    }
    //Decrypt section 0 of eid0.
    aes_setkey_dec(&aes_ctxt, key, 0x80);
    aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0xC0, indiv + INDIV_EID0_SEC_0_IV_OFFSET, eid0_in + 0x20 + 0xC0 * i, section_out);
	
    //Calculate aes omac1.
    u8 digest[AES_OMAC1_DIGEST_SIZE];
    aes_omac1(digest, section_out, 0xA8, key, 0x80);

    if (memcmp(digest, section_out + 0xA8, AES_OMAC1_DIGEST_SIZE) != 0){
		if (i == 0) {
			printf("warning: eid0 section 0 hash check failed!\n");
		} else if (i == 6) {
			printf("warning: eid0 section 6 hash check failed!\n");
		} else if (i == 10) {
			printf("warning: eid0 section A hash check failed!\n");
		}
		
	}
	
	/*
	if (i == 6) {
		//Decrypt section 0 of eid0.
		aes_setkey_dec(&aes_ctxt2, key_priv, 0x80);
		aes_crypt_cbc(&aes_ctxt2, AES_DECRYPT, 0x20, zero_iv, section_out + 0x88, section_out + 0x88);
		
		memset (zero_iv, 0, 0x10);
		
		if (memcmp(section_out + 0x9C, zero_iv, 0xC) != 0){
			printf("Failure with padding on section 6 priv key area!\n");
		}
		else{
			_hexdump(stdout, "Section 6:", 0x88, section_out + 0x88 , 0x20, TRUE);
		}
	}
	*/
}

void eid0_hash_encrypt_section_0(u8 *section_in, u8 *section_out) {
    u8 indiv[INDIV_SIZE];
    u8 key[0x10];
    aes_context aes_ctxt;

    //Generate individuals.
    indiv_gen(eid0_indiv_seed, NULL, NULL, NULL, indiv);

    //Generate key.
	aes_setkey_enc(&aes_ctxt, indiv + INDIV_EID0_SEC_0_GENKEY_OFFSET, 0x100);
    aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, eid0_keyseed_0, key);

    //Calculate aes omac1.
    aes_omac1(section_in + 0xA8, section_in, 0xA8, key, 0x80);

    //Encrypt section 0 of eid0.
    aes_setkey_enc(&aes_ctxt, key, 0x80);
    aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0xC0, indiv + INDIV_EID0_SEC_0_IV_OFFSET, section_in, section_out);
}

void eid0_hash_encrypt_section_6(u8 *section_in, u8 *section_out) {
    u8 indiv[INDIV_SIZE];
    u8 key[0x10];
    aes_context aes_ctxt;

    //Generate individuals.
    indiv_gen(eid0_indiv_seed, NULL, NULL, NULL, indiv);

    //Generate key.
    aes_setkey_enc(&aes_ctxt, indiv + INDIV_EID0_SEC_6_GENKEY_OFFSET, 0x100);
    aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, eid0_keyseed_6, key);

    //Calculate aes omac1.
    aes_omac1(section_in + 0xA8, section_in, 0xA8, key, 0x80);

    //Encrypt section 0 of eid0.
    aes_setkey_enc(&aes_ctxt, key, 0x80);
    aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0xC0, indiv + INDIV_EID0_SEC_6_IV_OFFSET, section_in, section_out);
}

void eid0_hash_encrypt_section_A(u8 *section_in, u8 *section_out) {
    u8 indiv[INDIV_SIZE];
    u8 key[0x10];
    aes_context aes_ctxt;

    //Generate individuals.
    indiv_gen(eid0_indiv_seed, NULL, NULL, NULL, indiv);

    //Generate key.
    aes_setkey_enc(&aes_ctxt, indiv + INDIV_EID0_SEC_A_GENKEY_OFFSET, 0x100);
    aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, eid0_keyseed_A, key);

    //Calculate aes omac1.
    aes_omac1(section_in + 0xA8, section_in, 0xA8, key, 0x80);

    //Encrypt section A of eid0.
    aes_setkey_enc(&aes_ctxt, key, 0x80);
    aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0xC0, indiv + INDIV_EID0_SEC_A_IV_OFFSET, section_in, section_out);
}

void eid0_decrypt(s8 *file_in, s8 *file_out) {
    u32 length;
    u8 *eid0 = _read_buffer(file_in, &length);

    if (eid0 != NULL) {
        u8 section_0[EID0_SECTION_0_SIZE];
        eid0_decrypt_section(eid0, section_0, 0);

        u8 section_6[EID0_SECTION_0_SIZE];
        eid0_decrypt_section(eid0, section_6, 6);

        u8 section_A[EID0_SECTION_0_SIZE];
        eid0_decrypt_section(eid0, section_A, 10);

        s8 fname_0[128];
        sprintf(fname_0, "%s.section_0.bin", file_out);
        _write_buffer(fname_0, section_0, 0xC0);

        s8 fname_6[128];
        sprintf(fname_6, "%s.section_6.bin", file_out);
        _write_buffer(fname_6, section_6, 0xC0);

        s8 fname_A[128];
        sprintf(fname_A, "%s.section_A.bin", file_out);
        _write_buffer(fname_A, section_A, 0xC0);

        free(eid0);
    }
}

void eid0_encrypt_section_0(s8 *file_in, s8 *file_out) {
    s8 fname_0_in[128];
    sprintf(fname_0_in, "%s.bin", file_in);

    u32 length;
    u8 *section_0_decrypted = _read_buffer(fname_0_in, &length);

    if (section_0_decrypted != NULL) {
        u8 section_0[EID0_SECTION_0_SIZE];
        eid0_hash_encrypt_section_0(section_0_decrypted, section_0);

        s8 fname_0[128];
        sprintf(fname_0, "%s.bin", file_out);
        _write_buffer(fname_0, section_0, 0xC0);

        free(section_0_decrypted);
    }
}

void eid0_encrypt_section_6(s8 *file_in, s8 *file_out) {
    s8 fname_6_in[128];
    sprintf(fname_6_in, "%s.bin", file_in);

    u32 length;
    u8 *section_6_decrypted = _read_buffer(fname_6_in, &length);

    if (section_6_decrypted != NULL) {
        u8 section_6[EID0_SECTION_6_SIZE];
        eid0_hash_encrypt_section_6(section_6_decrypted, section_6);

        s8 fname_6[128];
        sprintf(fname_6, "%s.bin", file_out);
        _write_buffer(fname_6, section_6, 0xC0);

        free(section_6_decrypted);
    }
}

void eid0_encrypt_section_A(s8 *file_in, s8 *file_out) {
    s8 fname_A_in[128];
    sprintf(fname_A_in, "%s.bin", file_in);

    u32 length;
    u8 *section_A_decrypted = _read_buffer(fname_A_in, &length);

    if (section_A_decrypted != NULL) {
        u8 section_A[EID0_SECTION_A_SIZE];
        eid0_hash_encrypt_section_A(section_A_decrypted, section_A);

        s8 fname_A[128];
        sprintf(fname_A, "%s.bin", file_out);
        _write_buffer(fname_A, section_A, 0xC0);

        free(section_A_decrypted);
    }
}

void eid0_list_infos(s8 *file_in) {
    u32 length;
    eid05_section_t *sptr;
    u8 *eid0 = _read_buffer(file_in, &length);

    if (eid0 != NULL) {
        printf("EID0:\n");

        u8 section_0[EID0_SECTION_0_SIZE];
        eid0_decrypt_section(eid0, section_0, 0);
        _hexdump(stdout, "Section 0:", 0, section_0, EID0_SECTION_0_SIZE, TRUE);
        sptr = (eid05_section_t *) section_0;
        _hexdump(stdout, " Data:    ", 0, sptr->data, 0x60, FALSE);
        _hexdump(stdout, " Common:  ", 0, sptr->common, 0x30, FALSE);
        _hexdump(stdout, " Unk:     ", 0, sptr->unk, 0x18, FALSE);
        _hexdump(stdout, " OMAC:    ", 0, sptr->omac, 0x10, FALSE);
        _hexdump(stdout, " Pad:     ", 0, sptr->pad, 0x08, FALSE);

        u8 section_A[EID0_SECTION_A_SIZE];
        eid0_decrypt_section(eid0, section_A, 10);
        _hexdump(stdout, "Section A:", 0, section_A, EID0_SECTION_A_SIZE, TRUE);
        sptr = (eid05_section_t *) section_A;
        _hexdump(stdout, " Data:    ", 0, sptr->data, 0x60, FALSE);
        _hexdump(stdout, " Common:  ", 0, sptr->common, 0x30, FALSE);
        _hexdump(stdout, " Unk:     ", 0, sptr->unk, 0x18, FALSE);
        _hexdump(stdout, " OMAC:    ", 0, sptr->omac, 0x10, FALSE);
        _hexdump(stdout, " Pad:     ", 0, sptr->pad, 0x08, FALSE);

        free(eid0);
    }
}

void eid1_decrypt_buffer(u8 *eid1) {
    u8 indiv[INDIV_SIZE];
    aes_context aes_ctxt;

    //Generate individuals.
    indiv_gen(eid1_indiv_seed, NULL, NULL, NULL, indiv);

    //Calculate eid1 aes omac1.
    u8 digest[AES_OMAC1_DIGEST_SIZE];
    aes_omac1(digest, eid1, 0x290, indiv + 0x20, 0x100);

    if (memcmp(digest, eid1 + 0x290, AES_OMAC1_DIGEST_SIZE) != 0)
        printf("warning: eid1 hash check failed!\n");

    //Decrypt eid1.
    aes_setkey_dec(&aes_ctxt, indiv + INDIV_EID1_KEY_OFFSET, 0x100);
    aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0x290, indiv + INDIV_EID1_IV_OFFSET, eid1, eid1);
	
    aes_omac1(digest, eid1, 0x280, eid1_master_key, 0x80);

    if (memcmp(digest, eid1 + 0x280, AES_OMAC1_DIGEST_SIZE) != 0){
        printf("warning: eid1 second hash check failed! Using second key...\n");
		goto key2;
	}else{
		//Decrypt eid1.
		aes_setkey_dec(&aes_ctxt, eid1_master_key, 0x80);
		aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0x280, zero_iv, eid1, eid1);
		return;
	}
	
key2:
	aes_omac1(digest, eid1, 0x280, eid1_master_key2, 0x80);
	
	if (memcmp(digest, eid1 + 0x280, AES_OMAC1_DIGEST_SIZE) != 0){
        printf("warning: eid1 second hash check failed!\n");
	}
	
    //Decrypt eid1.
	aes_setkey_dec(&aes_ctxt, eid1_master_key2, 0x80);
	aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0x280, zero_iv, eid1, eid1);
	return;

}

void eid1_decrypt(s8 *file_in, s8 *file_out) {
    u32 length;
    u8 *eid1 = _read_buffer(file_in, &length);

    if (eid1 != NULL) {
        eid1_decrypt_buffer(eid1);
		_write_buffer(file_out, eid1, 0x280);
		free(eid1);
    }
}

u8 *eid2_generate_block_buffer(u8 *eid2, u32 blocktype) {
    u8 *res = NULL, indiv[INDIV_SIZE];
    aes_context aes_ctxt;

    //Generate individuals.
    indiv_gen(eid2_indiv_seed, NULL, NULL, NULL, indiv);

    switch (blocktype) {
        case EID2_BLOCKTYPE_P:
            res = (u8 *) malloc(0x80);
            aes_setkey_dec(&aes_ctxt, indiv + INDIV_EID2_KEY_OFFSET, 0x100);
            aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0x80, indiv + INDIV_EID2_IV_OFFSET, eid2 + 0x20, res);
            break;
        case EID2_BLOCKTYPE_S:
            res = (u8 *) malloc(0x690);
            aes_setkey_dec(&aes_ctxt, indiv + INDIV_EID2_KEY_OFFSET, 0x100);
            aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0x690, indiv + INDIV_EID2_IV_OFFSET, eid2 + 0x20 + 0x80, res);
            break;
    }

    return res;
}

void eid2_generate_block(s8 *file_in, u32 blocktype, s8 *file_out) {
    u32 length;
    u8 *eid2 = _read_buffer(file_in, &length);

    if (eid2 != NULL) {
        u8 *block = eid2_generate_block_buffer(eid2, blocktype);
        if (block != NULL) {
            switch (blocktype) {
                case EID2_BLOCKTYPE_P:
                    _write_buffer(file_out, block, 0x80);
                    free(block);
                    break;
                case EID2_BLOCKTYPE_S:
                    _write_buffer(file_out, block, 0x690);
                    free(block);
                    break;
            }

        }

        free(eid2);
    }
}

void eid2_decrypt_block(u8 *block, u32 length) {
    u8 tmp[0x08], iv[0x08];
    int block_size = 8;
    int num_blocks = (int) (length / block_size);

    memcpy(iv, eid2_des_iv, 0x08);

    if (num_blocks > 0) {
        int i, j;
        des_context ctx;
        des_setkey_dec(&ctx, eid2_des_key);
        for (i = 0; i < num_blocks - 1; ++i) {
            u8 *ptr = block + i * block_size;
            memcpy(tmp, ptr, block_size);
            des_crypt_ecb(&ctx, ptr, ptr);
            if (i > 0) {
                for (j = 0; j < block_size; ++j)
                    ptr[j] = ptr[j] ^ iv[j];
            }
            memcpy(iv, tmp, block_size);
        }
    }
}

void eid3_decrypt_buffer(u8 *eid3) {
    u8 indiv[INDIV_SIZE];
    u8 key[0x10], iv[0x10];
    aes_context aes_ctxt;

    //Generate individuals.
    indiv_gen(eid3_indiv_seed, NULL, NULL, NULL, indiv);

    //Generate key.
    memset(iv, 0, 0x10);
    aes_setkey_enc(&aes_ctxt, indiv + 0x20, 0x100);
    aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x10, iv, eid3_keyseed, key);

    //Calculate eid3 aes omac1.
    u8 digest[AES_OMAC1_DIGEST_SIZE];
    aes_omac1(digest, eid3, 0xF0, key, 0x80);



    if (memcmp(digest, eid3 + 0xF0, AES_OMAC1_DIGEST_SIZE) != 0)
        printf("warning: eid3 omac1 hash check failed!\n");

    //Decrypt eid3.
    aes_setkey_dec(&aes_ctxt, key, 0x80);
    memcpy(iv, eid3 + 0x10, 0x10);
    aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0xD0, iv, eid3 + 0x20, eid3 + 0x20);

    //Decrypt second layer.
    memset(iv, 0, 0x10);
    aes_setkey_dec(&aes_ctxt, eid3_static_key, 0x80);
    aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0xD0, iv, eid3 + 0x20, eid3 + 0x20);


    u8 sha1_digest[20];
    sha1(eid3 + 0x20, 0xB8, sha1_digest);



    if (memcmp(sha1_digest, eid3 + 0x20 + 0xB8, 20) != 0)
        printf("warning: eid3 sha1 hash check failed!\n");
}

void eid3_decrypt(s8 *file_in, s8 *file_out) {
    u32 length;
    u8 *eid3 = _read_buffer(file_in, &length);

    if (eid3 != NULL) {
        eid3_decrypt_buffer(eid3);
        _write_buffer(file_out, eid3, EID3_SIZE);
        free(eid3);
    }
}

void eid4_decrypt_buffer(u8 *eid4) {
    u8 indiv[INDIV_SIZE];
    aes_context aes_ctxt;

    //Generate individuals.
    indiv_gen(eid4_indiv_seed, NULL, NULL, NULL, indiv);

    //Calculate eid4 aes omac1.
    u8 digest[AES_OMAC1_DIGEST_SIZE];
    aes_omac1(digest, eid4, 0x20, indiv + INDIV_EID4_KEY_OFFSET, 0x100);

    if (memcmp(digest, eid4 + 0x20, AES_OMAC1_DIGEST_SIZE) != 0)
        printf("warning: eid4 hash check failed!\n");

    //Decrypt eid4.
    aes_setkey_dec(&aes_ctxt, indiv + INDIV_EID4_KEY_OFFSET, 0x100);
    aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0x20, indiv + INDIV_EID4_IV_OFFSET, eid4, eid4);
}

void eid4_decrypt(s8 *file_in, s8 *file_out) {
    u32 length;
    u8 *eid4 = _read_buffer(file_in, &length);

    if (eid4 != NULL) {
        eid4_decrypt_buffer(eid4);
        _write_buffer(file_out, eid4, EID4_SIZE);
        free(eid4);
    }
}
