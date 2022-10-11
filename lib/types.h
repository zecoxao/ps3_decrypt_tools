/*
 * Copyright (c) 2011-2012 by ps3dev.net
 * This file is released under the GPLv2.
 */

#ifndef _TYPES_H_
#define _TYPES_H_

typedef char s8;
typedef unsigned char u8;
typedef short s16;
typedef unsigned short u16;
typedef int s32;
typedef unsigned int u32;
#ifdef _WIN32
typedef __int64 s64;
typedef unsigned __int64 u64;
#else
typedef long long int s64;
typedef unsigned long long int u64;
#endif

/*! Size of one sector. */
#define SECTOR_SIZE 0x200

#define BOOL int
#define TRUE 1
#define FALSE 0

//Endian swap for u16.
#define _ES16(val) \
	((u16)(((((u16)val) & 0xff00) >> 8) | \
	       ((((u16)val) & 0x00ff) << 8)))

//Endian swap for u32.
#define _ES32(val) \
	((u32)(((((u32)val) & 0xff000000) >> 24) | \
	       ((((u32)val) & 0x00ff0000) >> 8 ) | \
	       ((((u32)val) & 0x0000ff00) << 8 ) | \
	       ((((u32)val) & 0x000000ff) << 24)))

//Endian swap for u64.
#define _ES64(val) \
	((u64)(((((u64)val) & 0xff00000000000000ull) >> 56) | \
	       ((((u64)val) & 0x00ff000000000000ull) >> 40) | \
	       ((((u64)val) & 0x0000ff0000000000ull) >> 24) | \
	       ((((u64)val) & 0x000000ff00000000ull) >> 8 ) | \
	       ((((u64)val) & 0x00000000ff000000ull) << 8 ) | \
	       ((((u64)val) & 0x0000000000ff0000ull) << 24) | \
	       ((((u64)val) & 0x000000000000ff00ull) << 40) | \
	       ((((u64)val) & 0x00000000000000ffull) << 56)))

#endif
