/*
 * Copyright (c) 2011-2012 by ps3dev.net
 * This file is released under the GPLv2.
 */

#ifndef _EID_
#define _EID_

#include "types.h"

/*! Sizes. */
/*! Size of EID0 section 0. */
#define EID0_SECTION_0_SIZE 0xC0
/*! Size of EID0 section 6. */
#define EID0_SECTION_6_SIZE 0xC0
/*! Size of EID0 section A. */
#define EID0_SECTION_A_SIZE 0xC0
/*! Size of EID3. */
#define EID3_SIZE 0x100
/*! Size of EID4. */
#define EID4_SIZE 0x30

/*! EID2 block types. */
/*! EID2 P block. */
#define EID2_BLOCKTYPE_P 1
/*! EID2 S block. */
#define EID2_BLOCKTYPE_S 2

/*! EID header */
typedef struct _eid_header {
    /*! Entry count. */
    u32 entcnt;
    /*! EID size. */
    u32 size;
    /*! Unknown 0. */
    u64 unk0;
} eid_header_t;

/*! EID entry */
typedef struct _eid_entry {
    /*! Entry offset. */
    u32 offset;
    /*! Size. */
    u32 size;
    /*! Entry number. */
    u64 entnum;
} eid_entry_t;

/*! EID0/EID5 section. */
typedef struct _eid05_section {
    u8 data[0x60];
    u8 common[0x30];
    u8 unk[0x18];
    u8 omac[0x10];
    u8 pad[0x08];
} eid05_section_t;

/*! EID2 header. */
typedef struct _eid2_header {
    /*! P block length. */
    u16 p_len;
    /*! S block length. */
    u16 s_len;
    /*! Padding. */
    u8 padding[28];
} eid2_header_t;

/*!
 * \brief Endian swap for EID2 header.
 * \param h Pointer to EID2 header.
 */
static inline void _es_eid2_header(eid2_header_t *h) {
    h->p_len = _ES16(h->p_len);
    h->s_len = _ES16(h->s_len);
}

/*!
 * \brief Endian swap for EID header.
 * \param h Pointer to EID header.
 */
static inline void _es_eid_header(eid_header_t *h) {
    h->entcnt = _ES32(h->entcnt);
    h->size = _ES32(h->size);
    //Ignore unk0.
    //h->unk0 = _ES64(h->unk0);
}

/*!
 * \brief Endian swap for EID entry.
 * \param e Pointer to EID entry.
 */
static inline void _es_eid_entry(eid_entry_t *e) {
    e->offset = _ES32(e->offset);
    e->size = _ES32(e->size);
    e->entnum = _ES64(e->entnum);
}

/*!
 * \brief Unpack EID file.
 * \param file EID filename.
 */
void eid_unpack(s8 *file);

/*!
 * \brief Get EID entry.
 * \param file EID filename.
 * \param entnum EID entry number.
 */
u8 *eid_get_entry(s8 *file, u64 entnum);

/*!
 * \brief Decrypt section 0 of EID0.
 * \param eid0_in Input EID0.
 * \param section_out Output section.
 * \param i Section number.
 */
void eid0_decrypt_section(u8 *eid0_in, u8 *section_out, int i);

/*!
 * \brief Hash and encrypt section 0 of EID0.
 * \param section_in Input section.
 * \param section_out Output section.
 */
void eid0_hash_encrypt_section_0(u8 *section_in, u8 *section_out);

/*!
 * \brief Hash and encrypt section 6 of EID0.
 * \param section_in Input section.
 * \param section_out Output section.
 */
void eid0_hash_encrypt_section_6(u8 *section_in, u8 *section_out);

/*!
 * \brief Hash and encrypt section A of EID0.
 * \param section_in Input section.
 * \param section_out Output section.
 */
void eid0_hash_encrypt_section_A(u8 *section_in, u8 *section_out);

/*!
 * \brief Decrypt EID0.
 * \param file_in Input EID0.
 * \param file_out Prefix for decrypted EID0 sections.
 */
void eid0_decrypt(s8 *file_in, s8 *file_out);

/*!
 * \brief Encrypt EID0.
 * \param file_in Input EID0.
 * \param file_out Prefix for decrypted EID0 sections.
 */
void eid0_encrypt_section_0(s8 *file_in, s8 *file_out);

/*!
 * \brief Encrypt EID0.
 * \param file_in Input EID0.
 * \param file_out Prefix for decrypted EID0 sections.
 */
void eid0_encrypt_section_6(s8 *file_in, s8 *file_out);

/*!
 * \brief Encrypt EID0.
 * \param file_in Input EID0.
 * \param file_out Prefix for decrypted EID0 sections.
 */
void eid0_encrypt_section_A(s8 *file_in, s8 *file_out);

/*!
 * \brief List infos on EID0.
 * \param file_in Input EID0.
 */
void eid0_list_infos(s8 *file_in);

/*!
 * \brief Decrypt EID1 buffer.
 * \param eid1 Input/Output EID1.
 */
void eid1_decrypt_buffer(u8 *eid1);

/*!
 * \brief Decrypt EID1.
 * \param file_in Input EID1.
 * \param file_out Decrypted EID1 output.
 */
void eid1_decrypt(s8 *file_in, s8 *file_out);

/*!
 * \brief Generate P/S block buffer from EID2.
 * \param eid2 Input EID2.
 * \param blocktype Type of block to generate.
 */
u8 *eid2_generate_block_buffer(u8 *eid2, u32 blocktype);

/*!
 * \brief Generate P/S block from EID2.
 * \param file_in Input EID2.
 * \param blocktype Type of block to generate.
 * \param file_out Output file.
 */
void eid2_generate_block(s8 *file_in, u32 blocktype, s8 *file_out);

/*!
 * \brief Decrypt EID2 block.
 * \block EID2 block.
 * \length Block length.
 */
void eid2_decrypt_block(u8 *block, u32 length);

/*!
 * \brief Decrypt EID3 buffer.
 * \param eid3 Input/Output EID3.
 */
void eid3_decrypt_buffer(u8 *eid3);

/*!
 * \brief Decrypt EID3.
 * \param file_in Input EID3.
 * \param file_out Decrypted EID3 output.
 */
void eid3_decrypt(s8 *file_in, s8 *file_out);

/*!
 * \brief Decrypt EID4 buffer.
 * \param eid4 Input/Output EID4.
 */
void eid4_decrypt_buffer(u8 *eid4);

/*!
 * \brief Decrypt EID4.
 * \param file_in Input EID4.
 * \param file_out Decrypted EID4 output.
 */
void eid4_decrypt(s8 *file_in, s8 *file_out);

#endif
