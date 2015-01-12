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



#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <openssl/sha.h>
#include "ecc.h"
#include "msdrm.h"
#include "asf.h"

extern void error_exit(const char *msg);
extern void printwcs(const wchar_t * msg);
extern void add_p_dir(char *out,const char *file);

typedef struct bboxobj_st {
	void *jtable;
	void *jtbl2;
	void *jtbl3;
	MS_BN ecprivkey;
	MS_ECCpt ecpt1;
	uchar clientid[84];	/* First part is public key */
	uchar hwid[20];
	uchar rc4key[6];
	uchar pad1[2];
	int numkeypairs;
	uchar *keypairs;
} BBOXOBJ;

#define MAXKEYPAIRS 50

struct keypair_st {
	MS_ECCpt public;
	MS_BN private;
} keypair[MAXKEYPAIRS];
int numkeypairs = 0;

static const MS_BN msec_mod = {
	{0xf7, 0x24, 0x14, 0x14, 0x26, 0x59, 0x41, 0x31, 0x18, 0x28,
	 0x18, 0x27, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89}
};

static const MS_BN msec_a = {
	{0x97, 0x14, 0xe4, 0xeb, 0x09, 0xc0, 0x80, 0x47, 0x3d, 0xff,
	 0x32, 0x76, 0xe8, 0xbc, 0x77, 0xd2, 0xcc, 0xab, 0xa5, 0x37}
};

static const MS_BN msec_b = {
	{0x9e, 0x23, 0x28, 0x93, 0xdf, 0xde, 0x8f, 0xd7, 0x1a, 0x5f,
	 0xe8, 0x28, 0x32, 0x2f, 0x5e, 0x72, 0xbf, 0xda, 0xd8, 0x0d}
};

static const MS_BN msec_gx = {
	{0x20, 0xa1, 0x9f, 0x10, 0xf0, 0xda, 0x38, 0xba, 0x7d, 0xc0,
	 0x10, 0x35, 0xe5, 0xa1, 0xa3, 0xd6, 0x7f, 0x94, 0x23, 0x87}
};

static const MS_BN msec_gy = {
	{0x6f, 0x93, 0x79, 0xa3, 0xcd, 0x7a, 0xed, 0xd4, 0x56, 0x58,
	 0x3c, 0x8c, 0x2d, 0x52, 0x75, 0x10, 0x91, 0x44, 0x57, 0x44}
};


static void printMSBN(const MS_BN * num)
{
	int i;
	for (i = MS_BN_LEN - 1; i >= 0; i--)
		fprintf(stderr, "%02x", num->d[i]);
}


static BIGNUM *MS_BN_to_BN(const MS_BN * msnum, BIGNUM * r)
{
	uchar bigendian[MS_BN_LEN];
	int i;

	for (i = 0; i < MS_BN_LEN; i++)
		bigendian[i] = msnum->d[MS_BN_LEN - 1 - i];

	return BN_bin2bn(bigendian, MS_BN_LEN, r);
}


static void MS_ECCpt_to_ECCpt(const MS_ECCpt * mspt, ECCpt * r)
{
	MS_BN_to_BN(&mspt->x, r->x);
	MS_BN_to_BN(&mspt->y, r->y);
}


static ECC *MSECC_new_set()
{
	BIGNUM *tmod, *ta, *tb;
	ECC *ecc;
	ECCpt tg;

	tmod = BN_new();
	ta = BN_new();
	tb = BN_new();
	ECCpt_init(&tg);

	MS_BN_to_BN(&msec_mod, tmod);
	MS_BN_to_BN(&msec_a, ta);
	MS_BN_to_BN(&msec_b, tb);
	MS_BN_to_BN(&msec_gx, tg.x);
	MS_BN_to_BN(&msec_gy, tg.y);

	ecc = ECC_new_set(tmod, ta, tb, tg);

	BN_free(tmod);
	BN_free(ta);
	BN_free(tb);
	ECCpt_free(&tg);

	return ecc;
}


static void MSECC_set_privkey(const MS_BN * pk, ECC * ecc)
{
	if (ecc->privkey == NULL)
		ecc->privkey = BN_new();
	MS_BN_to_BN(pk, ecc->privkey);
}


static void BN_to_MS_BN(const BIGNUM * in, MS_BN * out)
{
	MS_BN tmp;
	int bytelen, i;

	bytelen = BN_num_bytes(in);
	if (bytelen > MS_BN_LEN)
		error_exit
		    ("Bug in code:  Result is too big in BN_to_MS_BN");

	memset(&tmp, 0, sizeof(MS_BN));
	BN_bn2bin(in, (uchar *) & tmp.d[MS_BN_LEN - bytelen]);

	for (i = 0; i < MS_BN_LEN; i++)
		out->d[i] = tmp.d[MS_BN_LEN - 1 - i];
}


static void MSECC_decrypt(MS_ECCpt * r, const MS_ECCpt * ctext, ECC * ecc)
{
	ECCpt u, v;

	if (ecc->privkey == NULL)
		error_exit
		    ("Bug in code:  MSECC_decrypt called with no private key!");

	ECCpt_init(&u);
	ECCpt_init(&v);
	MS_ECCpt_to_ECCpt(&ctext[0], &u);
	MS_ECCpt_to_ECCpt(&ctext[1], &v);

	ECCpt_mul(&u, &u, ecc->privkey, ecc);
	BN_sub(u.y, ecc->modulus, u.y);
	ECCpt_add(&v, &v, &u, ecc);

	BN_to_MS_BN(v.x, &r->x);
	BN_to_MS_BN(v.y, &r->y);

	ECCpt_free(&u);
	ECCpt_free(&v);
}

static void MS_Base64toBase64(wchar_t *str)
{
    while(*str++!=L'\0')
    {
        if(*str == L'!')
            *str='+';
        else if(*str == L'*')
            *str='/';
    }

}
static int MS_Base64Decode(const wchar_t * str, char **buff)
{
	const wchar_t *cp;
	char *ocp;
	int len, val, count, block;

	len = wcslen(str);
	if ((*buff = malloc((len * 3) / 4)) == NULL)
		error_exit("Memory allocation failed in MS_Base64Decode.");

	ocp = *buff;
	count = 0;
	block = 0;
	for (cp = str; *cp != L'\0' && *cp != L'='; cp++) {
		if ((*cp >= L'A') && (*cp <= L'Z'))
			val = *cp - L'A';
		else if ((*cp >= L'a') && (*cp <= L'z'))
			val = *cp - L'a' + 26;
		else if ((*cp >= L'0') && (*cp <= L'9'))
			val = *cp - L'0' + 52;
		else if ((*cp == L'+') || (*cp == L'!'))
			val = 62;
		else if ((*cp == L'/') || (*cp == L'*'))
			val = 63;
		else
			continue;

		block = (block << 6) | val;
		if (count & 3)
			*ocp++ = block >> (6 - 2 * (count & 3));
		count++;
	}

	return ocp - *buff;
}
static int MS_Base64Encode(const unsigned char *src, char **dst,int len)
{
    char *ocp;
	static const char base64[64] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int bits = 0;
    int bits_avail = 0;
    if (len >= 0xffffffff / 4)
        error_exit("len too big in MS_Base64Encode.");
    *dst = ocp = malloc(len / 3 * 4 + 5);
    if (!ocp)
		error_exit("Memory allocation failed in MS_Base64Encode.");
    while (len--) {
        bits = (bits << 8) | *src++;
        bits_avail += 8;
        do {
            bits_avail -= 6;
            *ocp++ = base64[(bits >> bits_avail) & 63];
        } while (bits_avail > 6);
    }
    if (bits_avail)
        *ocp++ = base64[(bits << (6 - bits_avail)) & 63];
    while ((ocp - *dst) & 3)
        *ocp++ = '=';
    *ocp++ = 0;
    return ocp - *dst;
}


static void MSDRM_setup(const MS_BN * privkey, const wchar_t * value, CONTKEY * out)
{
	ECC *msecc;
	MS_ECCpt dec;
	int len,i;
	wchar_t tmpSID[128];
	const wchar_t *w_sid;
	char *dynbuff,*sid,*checksum;
	char hash[30];
	char hash2[30];
    if(value && ((long)privkey)!=1)
    {
        msecc = MSECC_new_set();
        MSECC_set_privkey(privkey, msecc);

        len = MS_Base64Decode(value, &dynbuff);
        MSECC_decrypt(&dec, (MS_ECCpt *) dynbuff, msecc);
        free(dynbuff);

        ECC_free(msecc);
        msecc = NULL;

        if ((uchar) dec.x.d[0] > MS_BN_LEN - 1)
        {
            fprintf(stderr,"Decrypted content key is too big!\n");
            goto get_sid;
        }

        out->ckeylen = (uchar) dec.x.d[0];
        memcpy(out->ckey, &dec.x.d[1], out->ckeylen);

        if (globalinfo.verbose) {
            fprintf(stderr, "Content key:");
            for (i = 0; i < out->ckeylen+1; i++)
                fprintf(stderr, " %02x", dec.x.d[i]);
            fprintf(stderr, "\n");
        }
 		SHA1(out->ckey, out->ckeylen, out->keyhash);
		memset(hash,0,sizeof(hash));
		memcpy(hash,out->ckey,out->ckeylen);
		for(i=0;i<5;i++)
		{
			SHA1(hash,21,hash2);
			memcpy(hash,hash2,21);
		}
		MS_Base64Encode(hash,&checksum,7);
        if(globalinfo.verbose)
		{
        	fprintf(stderr, "<CHECKSUM>%s</CHECKSUM>\n",checksum);
		}
    }
    else if (privkey)
    {
        len=MS_Base64Decode(value, &dynbuff);
        if(len!=20)
            error_exit("Wrong size of SID!");
        memcpy(out->keyhash,dynbuff,20);
    }
    else
    {
get_sid:
        fprintf(stderr,"Enter SID for this file:\n");
        fgetws(tmpSID,sizeof(tmpSID),stdin);
        if(wcsstr(tmpSID,L"<SID>"))
        {
            if((w_sid=get_element(L"SID",tmpSID))==NULL)
                error_exit("Unable to read SID!");
            len=MS_Base64Decode(w_sid, &dynbuff);
        }
        else
            len=MS_Base64Decode(tmpSID, &dynbuff);
        if(len!=20 && len!=21)
		{
			fprintf(stderr,"Size of SID:%d\n",len);
            error_exit("Wrong size of SID!");
		}
        memcpy(out->keyhash,dynbuff,20);
    }
	MS_Base64Encode(out->keyhash,&sid,20);
    if (globalinfo.verbose) {
        fprintf(stderr, "<SID>%s</SID>\n",sid);
        fprintf(stderr, "SID in Hex: ");
		for (i = 0; i < 20; i++)
                fprintf(stderr, "%02x", out->keyhash[i]);
            fprintf(stderr, "\n");
	}
}


/* Stupid little fake XML parser. */

static const wchar_t *find_close(const wchar_t * str)
{
	while ((*str != L'\0') && (*str != L'>')) {
		if (*str == L'"') {
			if ((str = wcschr(str + 1, L'"')) == NULL)
				return NULL;
		}
		str++;
	}

	if (*str == L'\0')
		return NULL;
	else
		return str + 1;
}


wchar_t *get_element(const wchar_t * tag, const wchar_t * str)
{
	int len = wcslen(tag);
	wchar_t *tmptag;
	wchar_t *start, *end;
	wchar_t *rval = NULL;
	if ((tmptag = malloc((len + 4) * sizeof(wchar_t))) == NULL)
		error_exit("Memory allocation failed in get_element (1)");

	wcscpy(tmptag,L"<");
	wcscat(tmptag,tag);
	while (1) {
		if ((start = wcsstr(str, tmptag)) == NULL)
			goto exit;
		if (!iswalnum(start[len + 1]))
			break;
		str = start + len + 1;
	}
	wcscpy(tmptag,L"</");
	wcscat(tmptag,tag);
	wcscat(tmptag,L">");
	end = wcsstr(str, tmptag);

	if (end == NULL) {
		goto exit;
	} else {
		const wchar_t *realstart = find_close(start);
		if ((realstart == NULL) || (realstart > end)) {
			goto exit;
		} else {
            wchar_t *tmp =
			    malloc((end - realstart +
				    1) * sizeof(wchar_t));
			if (tmp == NULL)
				error_exit
				    ("Memory allocation failed in get_element (2)");
			memcpy(tmp, realstart,
			       (end - realstart) * sizeof(wchar_t));
			tmp[end - realstart] = L'\0';
			rval = tmp;
		}
	}

exit:
	free(tmptag);
	return rval;
}



/*
 * getDRMDataPath allocates extra room on the end (20 wchars) for
 * appending a filename
 */
#ifdef WIN32
long __stdcall RegOpenKeyExA(unsigned long,char *,long,long,unsigned long *);
long __stdcall RegQueryValueExA(unsigned long,char*,long*,long*,unsigned char *,unsigned long*);
long __stdcall RegCloseKey(unsigned long);
#define FAILED(Status) ((long)(Status)<0)
#define HKEY_LOCAL_MACHINE 0x80000002
static wchar_t *getDRMDataPath()
{
	unsigned key_drm;
	int stat;
	unsigned dtype, dlen;
	wchar_t *buff;
	stat =
	    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\DRM", 0,
			 0x20019 , &key_drm);
	if (FAILED(stat))
		return NULL;

	stat =
	    RegQueryValueExA(key_drm, "DataPath", NULL, NULL, NULL, &dlen);
	if (FAILED(stat))
		return NULL;

	if ((buff =
	     (wchar_t *) malloc(dlen + 20 * sizeof(wchar_t))) == NULL)
		error_exit("Memory allocation failed in getDRMDataPath");

	stat =
	    RegQueryValueExA(key_drm, "DataPath", NULL, &dtype,
			    (uchar *) buff, &dlen);
	if (FAILED(stat)) {
		free(buff);
		return NULL;
	}

	RegCloseKey(key_drm);

	return buff;
}
#endif



static int fileExistsA(const char *fname)
{
    FILE *fp=fopen(fname,"r");
    if(fp==NULL)
        return 0;
    fclose(fp);
	return 1;
}

static int fileExistsW(const wchar_t * fname)
{
	char buffer[MAX_PATH];
	int len;
	len = wcslen(fname);
	if(len >= MAX_PATH)
        return 0;
	if(wcstombs(buffer,fname,MAX_PATH)==(size_t)-1)
        return 0;

	return fileExistsA(buffer);
}
/*
static void getKSFilename(wchar_t * ksname, char *libname)
{
	wchar_t *basepath = getDRMDataPath();
	wchar_t currks[MAX_PATH], lastks[MAX_PATH];
	char abasepath[MAX_PATH];
	char currlib[MAX_PATH], lastlib[MAX_PATH];
	int fnum;

	if (basepath != NULL) {
		WideCharToMultiByte(CP_ACP, 0, basepath,
				    wcslen(basepath) + 1, abasepath,
				    MAX_PATH, NULL, NULL);
		swprintf(lastks, L"%s\\v2ks.bla", basepath);
		swprintf(currks, L"%s\\v2ksndv.bla", basepath);
		sprintf(lastlib, "BlackBox.dll");
		sprintf(currlib, "%s\\IndivBox.key", abasepath);
		fnum = 1;
		while (fileExistsW(currks) && (fileExistsA(currlib))) {
			fnum++;
			wcscpy(lastks, currks);
			swprintf(currks, L"%s\\v2ks%03x.bla", basepath,
				 fnum);
			strcpy(lastlib, currlib);
			sprintf(currlib, "%s\\Indiv%03x.key", basepath,
				fnum);
		}
		wcscpy(ksname, lastks);
		strcpy(libname, lastlib);
		free(basepath);
	}
}


static int getkeypairs()
{
	HMODULE mylib;
	int rval;
	BBOXOBJ *bbobj;
	char errmsg[100];
	wchar_t KSFilename[MAX_PATH];
	char BBoxLib[MAX_PATH];
	int i;

	getKSFilename(KSFilename, BBoxLib);
	if (globalinfo.verbose) {
		fprintf(stderr, "BlackBox library to use: %s\n", BBoxLib);
		fprintf(stderr, "Keystore to use: ");
		printwcs(KSFilename);
		fprintf(stderr, "\n");
	}
	mylib = LoadLibraryA(BBoxLib);
	if (mylib == NULL) {
		DWORD err = GetLastError();
		sprintf(errmsg, "Failed loading library. Err code %08x",
			err);
		error_exit(errmsg);
	} else {
		typedef int (WINAPI * createfn) (BBOXOBJ **,
						 unsigned short *);
		createfn create =
		    (createfn) GetProcAddress(mylib,
					      "IBlackBox_CreateInstance2");
		if (create == NULL)
			error_exit("Failed finding proc address.");
		else {
			rval = (*create) (&bbobj, KSFilename);

			if (bbobj == NULL) {
				sprintf(errmsg,
					"Failed to create a black box object (err code %08x)\n",
					rval);
				error_exit(errmsg);
			}

			if (globalinfo.verbose) {
				fprintf(stderr,
					"Created BlackBox instance - extracting key pairs\n");
			}

			memcpy(&keypair[0].private, &bbobj->ecprivkey, 20);
			memcpy(&keypair[0].public, bbobj->clientid, 40);
			numkeypairs = bbobj->numkeypairs + 1;
			for (i = 0; i < bbobj->numkeypairs; i++) {
				memcpy(&keypair[i + 1].public,
				       bbobj->keypairs + 60 * i, 40);
				memcpy(&keypair[i + 1].private,
				       bbobj->keypairs + 60 * i + 40, 20);
			}

			if (globalinfo.verbose) {
				fprintf(stderr, "\n");
				for (i = 0; i < numkeypairs; i++) {
					fprintf(stderr,
						"Public key %d x: ",
						i + 1);
					printMSBN(&keypair[i].public.x);
					fprintf(stderr,
						"\nPublic key %d y: ",
						i + 1);
					printMSBN(&keypair[i].public.y);
					fprintf(stderr,
						"\nPrivate key %d:  ",
						i + 1);
					printMSBN(&keypair[i].private);
					fprintf(stderr, "\n\n");
				}
			}
		}
		FreeLibrary(mylib);
	}
	return 0;
}
*/

static int getIBXprivKey(wchar_t *pubkey,wchar_t *privkey)
{
    FILE *fp;
    wchar_t tmpPub[100];
    char tmpPubA[100];
    char privkeyA[100];
	char fpath[MAX_PATH];
	add_p_dir(fpath,"blackbox-keys.txt");
    if((fp=fopen(fpath,"r"))==NULL)
    {
        if (globalinfo.verbose)
        {
            fprintf(stderr,"Couldn't open blackbox-keys.txt file\n");
        }
        return 0;
    }
    MS_Base64toBase64(pubkey);
    while(fscanf(fp,"%s",tmpPubA)==1 && fscanf(fp,"%s",privkeyA)==1)
    {
        MS_Base64toBase64(tmpPub);
		int i;
		for(i=0;i<100;i++)
		{
			tmpPub[i]=tmpPubA[i];
			privkey[i]=privkeyA[i];
		}
        if(!wcscmp(tmpPub,pubkey))
        {
            if (globalinfo.verbose)
            {
                fprintf(stderr,"Matched public key!  Proceeding...\n");
            }
            return 1;
        }
        if (globalinfo.verbose)
        {
            fprintf(stderr,"Couldn't match public key\n");
        }
        return 0;
    }
    fclose(fp);
    return 0;
}
static const wchar_t *getSIDFromFile(const wchar_t *kid, const char *sFile)
{
	FILE *fp;
	int fsize;
    const wchar_t *sid=0,*SIDpos;
    wchar_t *drm2keyW;
    char kidA[1024];
    char *drm2key;
    char fpath[MAX_PATH];
	add_p_dir(fpath,sFile);
	if((fp=fopen(fpath,"r"))==NULL)
        return 0;
    fseek(fp,0,SEEK_END);
    fsize=ftell(fp);
    fseek(fp,0,SEEK_SET);
    wcstombs(kidA,kid,1024);
    if((drm2key=malloc(fsize))==NULL)
		error_exit("Couldn't allocate space for drm2.key file!");
    if((drm2keyW=malloc(fsize*sizeof(wchar_t)))==NULL)
		error_exit("Couldn't allocate space for drm2.key file!");
    fread(drm2key,fsize,1,fp);
    mbstowcs(drm2keyW,drm2key,fsize);
    mbstowcs(drm2keyW,drm2key,fsize);
    if((SIDpos=wcsstr(drm2keyW,kid)))
	{
        sid=get_element(L"SID",SIDpos);
	}
    fclose(fp);
    return sid;
}
static const wchar_t *getSIDFromFiles(wchar_t *kid)
{
	char ch,buf[256];
    const wchar_t *sid=0;
	int i;
	for(i=0;i<wcslen(kid);i++)
	{
		if(kid[i]==L'@')
			kid[i]=L'/';
	}
    sid=getSIDFromFile(kid,"drm2.key");
	if(sid)
		return sid;
	for(ch='a';ch<='z';ch++)
	{
		sprintf(buf,"drm2%cdrm2-%c.key",SCHAR,ch);
		sid=getSIDFromFile(kid,buf);
		if(sid)
			return sid;
	}
	return 0;

}
static CONTKEY *checkLicense(const wchar_t * license)
{
	wchar_t *ebits = NULL;
	wchar_t *pubkey = NULL;
	wchar_t *value = NULL;
	wchar_t buf[100];
	MS_BN *privkey = NULL;
	CONTKEY *ckey = NULL;
	MS_BN *thispubkey;

	if ((ebits = get_element(L"ENABLINGBITS", license)) == NULL)
		error_exit("No ENABLINGBITS element in license!");

	if ((pubkey = get_element(L"PUBKEY", ebits)) == NULL)
		error_exit("No PUBKEY element in license!");

	if ((value = get_element(L"VALUE", ebits)) == NULL)
		error_exit("No VALUE element in license!");
	MS_Base64Decode(pubkey, (char **) &thispubkey);
	if (globalinfo.verbose) {
		fprintf(stderr, "Checking license with PUBKEY ");
		printMSBN(thispubkey);
		fprintf(stderr, "\n");
	}
	if(!getIBXprivKey(pubkey,buf))
	{
        puts("Enter IBX private key or hit enter:");
        fgetws(buf,sizeof(buf),stdin);
	}

	MS_Base64Decode(buf, (char **) &privkey);
	if (privkey != NULL) {
		if ((ckey = malloc(sizeof(CONTKEY))) == NULL)
			error_exit
			    ("Memory allocation failed in checkLicense");
		MSDRM_setup(privkey, value, ckey);
	}

	free(thispubkey);
	free(value);
	free(pubkey);
	free(ebits);

	return ckey;
}


static CONTKEY *getContKey(const wchar_t * licFile, wchar_t * kid)
{
	int fsize,i,j;
	wchar_t license[4096*2],*tmpKid;
	char *licFileA,*licenseA;
	CONTKEY *ckey;
    FILE *fp;
	for(i=0;i<wcslen(kid);i++)
	{
		if(kid[i]==L'@')
			kid[i]=L'/';
	}
    if((licFileA=malloc(MAX_PATH))==NULL)
		error_exit("Couldn't allocate space for license name!");
    wcstombs(licFileA,licFile,MAX_PATH);
    fp=fopen(licFileA,"rb");
    fseek(fp,0,SEEK_END);
    fsize=ftell(fp);
    fseek(fp,0,SEEK_SET);
    if((licenseA=malloc(fsize))==NULL)
		error_exit("Couldn't allocate space for license file!");
    fread(licenseA,fsize,1,fp);
    for(i=0;i<fsize;i++)
    {
		if(licenseA[i]=='<' && licenseA[i+2]=='?' && licenseA[i+4]=='x' && licenseA[i+6]=='m')
        {
			for(j=0;j<4096*2 && j*2+i<fsize;j++)
			{
				license[j]=licenseA[i+j*2];
			}
            tmpKid=get_element(L"KID",license);
            if(!wcscmp(kid,tmpKid))
            {
                ckey=checkLicense(license);
                return ckey;
            }
        }
    }
    fclose(fp);
	return NULL;
}


static void convertKID(wchar_t * kid)
{
	while (*kid != L'\0') {
		if (*kid == L'/')
			*kid = L'@';
		else if (*kid == L'!')
			*kid = L'%';
		kid++;
	}
}


CONTKEY *MSDRM_init(wchar_t * kid)
{
	CONTKEY *ckey=NULL;
	const wchar_t *sid;
    if((ckey = malloc(sizeof(CONTKEY))) == NULL)
        error_exit("Memory allocation failed in MSDRM_init");
	if(globalinfo.asksid)
	{
        if((ckey = malloc(sizeof(CONTKEY))) == NULL)
			error_exit("Memory allocation failed in MSDRM_init");
		MSDRM_setup(NULL,NULL,ckey);
	}
    else if((sid=getSIDFromFiles(kid)))
    {
        MSDRM_setup((MS_BN*)1,sid,ckey);
    }
    else
    {
			wchar_t tmpPath[256*256];
			#ifdef WIN32
				wchar_t *licfile = getDRMDataPath();
			#else
				char licfileA[256*256];
				wchar_t *licfile=(wchar_t*)malloc(256*256*2);
				add_p_dir(licfileA,"");
				if(strlen(licfileA))
					licfileA[strlen(licfileA)-1]=0;
				mbstowcs(licfile,licfileA,256*255);
			#endif
                convertKID(kid);
                wcscpy(tmpPath,licfile);
        		wcscat(tmpPath,SCHAR3);
                wcscat(tmpPath,L"drmstore.hds");
                wcscat(licfile, SCHAR3);
                wcscat(licfile, L"drmv2.lic");
                if(fileExistsW(tmpPath))
                    wcscpy(licfile,tmpPath);
                if(fileExistsW(licfile))
                {
                    if (globalinfo.verbose) {
                        fprintf(stderr, "License file full path: ");
                        printwcs(licfile);
                        fprintf(stderr, "\n");
                    }
                    ckey = getContKey(licfile, kid);
                }
				else
					ckey=NULL;
        		free(licfile);
        if (ckey == NULL)
        {
            if((ckey = malloc(sizeof(CONTKEY))) == NULL)
                error_exit("Memory allocation failed in MSDRM_init");
            MSDRM_setup(NULL,NULL,ckey);
        }

    }

	return ckey;
}
