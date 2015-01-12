/*
 *  (C) Copyright 2001-2007 "Beale Screamer"
 *                           Michal Majchrowicz
 *
 *  This file is part of FreeMe2.
 *
 *  FreeMe2 is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  any later version.
 *
 *  Foobar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#if !defined( _MSDRM_H_ )
#define _MSDRM_H_
#ifdef WIN32
    #define SCHAR '\\'
    #define SCHAR2 "\\"
    #define SCHAR3 L"\\"
#else
    #define SCHAR '/'
    #define SCHAR2 "/"
    #define SCHAR3 L"/"
	 #define MAX_PATH 256*256
#endif
#include "ecc.h"

typedef unsigned char uchar;
//#ifdef WIN32
   //typedef uchar fGUID[16];
   //#define GUID fGUID
//#else
    typedef uchar GUID[16];
//#endif

#define MS_BN_LEN 20

typedef struct ms_bn_st {
	uchar d[MS_BN_LEN];
} MS_BN;

typedef struct ms_eccpt_st {
	MS_BN x, y;
} MS_ECCpt;

typedef struct contkey_st {
	uchar ckey[MS_BN_LEN];
	int ckeylen;
	uchar keyhash[20];
} CONTKEY;

wchar_t *get_element(const wchar_t * tag, const wchar_t * str);
void MSDRM_decr_packet(uchar * data, int len, CONTKEY * ckey);
CONTKEY *MSDRM_init(wchar_t * license);

extern struct globalinfo_st {
	int verbose;
	int engine;
	int asksid;
	int fileheader;
	char *ofname;
	int packetlen;
	int numpackets;
	CONTKEY *content_key;
	wchar_t *kid;
	wchar_t *checksum;
	int hasV1header;
	int hasV2header;
} globalinfo;

#endif
