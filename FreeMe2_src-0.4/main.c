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

/*
 *  FreeMe main.c -- mostly a wma/asf file processor, with DRM part
 *  put off into msdrm.c
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <wchar.h>
#include "avemul.h"
#include "msdrm.h"
#include "asf.h"
#include "asfcrypt.h"

#pragma pack(1)

static int fread_le16(uint16_t *dst, FILE *fp) {
	if (fread(dst, 2, 1, fp) != 1)
		return 0;
	*dst = le2me_16(*dst);
	return 1;
}

static int fwrite_le16(uint16_t v, FILE *fp) {
	v = le2me_16(v);
	return fwrite(&v, 2, 1, fp) == 1;
}

static int fread_le32(uint32_t *dst, FILE *fp) {
	if (fread(dst, 4, 1, fp) != 1)
		return 0;
	*dst = le2me_32(*dst);
	return 1;
}

static int fwrite_le32(uint32_t v, FILE *fp) {
	v = le2me_32(v);
	return fwrite(&v, 4, 1, fp) == 1;
}

static int fread_le64(uint64_t *dst, FILE *fp) {
	if (fread(dst, 8, 1, fp) != 1)
		return 0;
	*dst = le2me_64(*dst);
	return 1;
}

static int fwrite_le64(uint64_t v, FILE *fp) {
	v = le2me_64(v);
	return fwrite(&v, 8, 1, fp) == 1;
}

typedef struct chunk_save_st {
	GUID guid;
	uint64_t len;
	uint8_t *data;
	struct chunk_save_st *next;
} CHUNKSAVE;

static int fread_chunk(CHUNKSAVE *chunk, FILE *fp) {
	if (fread(&chunk->guid, sizeof(chunk->guid), 1, fp) != 1)
		return 0;
	return fread_le64(&chunk->len, fp);
}

static int fwrite_chunk(CHUNKSAVE *chunk, FILE *fp) {
	if (fwrite(&chunk->guid, sizeof(chunk->guid), 1, fp) != 1)
		return 0;
	return fwrite_le64(chunk->len, fp);
}

typedef int (*GUIDHANDLER) (FILE * fp, CHUNKSAVE * savep);

CONTKEY g_ckey;
char p_dir[MAX_PATH];
typedef struct guidaction_st {
	const GUID *guid;
	const char *name;
	GUIDHANDLER fn;
} GUIDACTION;

typedef struct fileheader_st {
	GUID clientGUID;
	uint64_t filesize;
	uint64_t fileCreateTime;
	uint64_t numPackets;
	uint64_t timeAtEnd;
	uint64_t playDuration;
	uint32_t timeAtStart;
	uint32_t unknown1;
	uint32_t unknown2;
	uint32_t packetSize;
	uint32_t packetSize2;
	uint32_t uncompressedSize;
} FILEHEADER;

static int handle_chunk(FILE * fp, CHUNKSAVE * chunk);
static int handle_header(FILE * fp, CHUNKSAVE * chunk);
static int handle_file_header(FILE * fp, CHUNKSAVE * chunk);
static int handle_data(FILE * fp, CHUNKSAVE * chunk);
static int handle_copy(FILE * fp, CHUNKSAVE * chunk);
static int handle_stream(FILE * fp, CHUNKSAVE * chunk);
static int handle_drmv1(FILE * fp, CHUNKSAVE * chunk);
static int handle_drmv2(FILE * fp, CHUNKSAVE * chunk);

struct globalinfo_st globalinfo;

static const GUID HeaderGUID = {
  0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
  0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
};

static const GUID DataGUID = {
  0x36, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
  0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
};

static const GUID IndexGUID= {
  0xd3, 0x29, 0xe2, 0xd6, 0xda, 0x35, 0xd1, 0x11,
  0x90, 0x34, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xbe
};


static const GUID FileHeaderGUID = {
  0xa1, 0xdc, 0xab, 0x8c, 0x47, 0xa9, 0xcf, 0x11,
  0x8e, 0xe4, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65
};

static const GUID StreamHeaderGUID = {
  0x91, 0x07, 0xdc, 0xb7, 0xb7, 0xa9, 0xcf, 0x11,
  0x8e, 0xe6, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65
};

static const GUID AudioStreamGUID = {
  0x40, 0x9e, 0x69, 0xf8, 0x4d, 0x5b, 0xcf, 0x11,
  0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b
};

static const GUID Unknown1GUID = {
  0xb5, 0x03, 0xbf, 0x5f, 0x2e, 0xa9, 0xcf, 0x11,
  0x8e, 0xe3, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65
};

static const GUID Unknown2GUID = {
  0x40, 0x52, 0xd1, 0x86, 0x1d, 0x31, 0xd0, 0x11,
  0xa3, 0xa4, 0x00, 0xa0, 0xc9, 0x03, 0x48, 0xf6
};

static const GUID DRMv2HeaderGUID = {
  0x14, 0xe6, 0x8a, 0x29, 0x22, 0x26, 0x17, 0x4c,
  0xb9, 0x35, 0xda, 0xe0, 0x7e, 0xe9, 0x28, 0x9c
};

static const GUID DRMv1HeaderGUID2 = {
  0xfc, 0xb3, 0x11, 0x22, 0x23, 0xbd, 0xd2, 0x11,
  0xb4, 0xb7, 0x00, 0xa0, 0xc9, 0x55, 0xfc, 0x6e
};


static const GUID DRMv1HeaderGUID = {
  0xfb, 0xb3, 0x11, 0x22, 0x23, 0xbd, 0xd2, 0x11,
  0xb4, 0xb7, 0x00, 0xa0, 0xc9, 0x55, 0xfc, 0x6e
};

static const GUID UknownGUID4 = {
  0xce, 0x75, 0xf8, 0x7b, 0x8d, 0x46, 0xd1, 0x11,
  0x8d, 0x82, 0x00, 0x60, 0x97, 0xc9, 0xa2, 0xb2
};
static const GUID ContentDescrGUID = {
  0x33, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
  0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
};

static const GUID PropertyListGUID = {
  0x40, 0xa4, 0xd0, 0xd2, 0x07, 0xe3, 0xd2, 0x11,
  0x97, 0xf0, 0x00, 0xa0, 0xc9, 0x5e, 0xa8, 0x50
};

static const GUID PaddingGUID = {
  0x74, 0xd4, 0x06, 0x18, 0xdf, 0xca, 0x09, 0x45,
  0xb7, 0xb4, 0x9a, 0xab, 0xcb, 0x96, 0xaa, 0xe8
};

static const GUID PaddingGUID2 = {
  0x74, 0xd4, 0x06, 0x18, 0xdf, 0xca, 0x09, 0x45,
  0xa4, 0xba, 0x9a, 0xab, 0xcb, 0x96, 0xaa, 0xe8
};


static const GUIDACTION known_guids[] = {
	{&HeaderGUID, "Header", handle_header},
	{&DataGUID, "Data", handle_data},
	{&IndexGUID, "Index", handle_copy},
	{&FileHeaderGUID, "File Header", handle_file_header},
	{&StreamHeaderGUID, "Stream Header", handle_stream},
	{&Unknown1GUID, "Header subchunk - unknown 1", handle_copy},
	{&Unknown2GUID, "Header subchunk - unknown 2", handle_copy},
	{&DRMv2HeaderGUID, "DRMV2 ContentHeader", handle_drmv2},
	{&DRMv1HeaderGUID, "DRMv1 header", handle_drmv1},
	{&DRMv1HeaderGUID2, "DRMv1 header", handle_drmv1},
	{&ContentDescrGUID, "Content Description", handle_copy},
	{&PaddingGUID, "Padding", handle_copy},
	{&PaddingGUID, "Padding 2", handle_copy},
	{&UknownGUID4, "Unknown", handle_copy},
	{&PropertyListGUID, "Property List", handle_copy},
	{NULL, NULL, NULL}
};

static int(*pfn_handle_packet)(FILE * fp, int packetlen);
void error_exit(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	fprintf(stderr, "\n   Press <ENTER> to acknowledge error.\n");
	getchar();
	exit(1);
}

void printwcs(const wchar_t * msg)
{
	int len, rval;
	char *buff;
	buff=(char*)msg;
	len = wcslen(msg);
	if ((buff = malloc(len + 1)) == NULL)
		error_exit("Memory allocation failed in printwcs");
	rval = wcstombs(buff, msg, len+1);
	if (rval == -1)
		error_exit("WideCharToMultiByte failed in printwcs");
	fputs(buff,stderr);
	free(buff);
}


static GUIDHANDLER find_guid(GUID * guid)
{
	const GUIDACTION *curr;
	for (curr = known_guids; curr->guid != NULL; curr++)
		if (memcmp(curr->guid, guid, sizeof(GUID)) == 0)
			return curr->fn;
	return NULL;
}
void add_p_dir(char *out,const char *file)
{
    strcpy(out,p_dir);
    strcat(out,file);
}
static int handle_stream(FILE * fp, CHUNKSAVE * chunk)
{
	if (chunk->len < 24 + 49 + 1)
		return 0;
	if (!handle_copy(fp, chunk))
		return 0;
    ((unsigned char*)chunk->data)[49]=0;
	return 1;
}
static int handle_copy(FILE * fp, CHUNKSAVE * chunk)
{
	unsigned datalen = chunk->len - 24;

	chunk->data = malloc(datalen);

	if (chunk->data == NULL)
		error_exit("Memory allocation failed in handle_copy");

	if (fread(chunk->data, datalen, 1, fp) != 1) {
		free(chunk->data);
		chunk->data = NULL;
		return 0;
	}

	return 1;
}


static int handle_drmv1(FILE * fp, CHUNKSAVE * chunk)
{
	if (!handle_copy(fp, chunk))
		return 0;
	memcpy(&chunk->guid, PaddingGUID2, sizeof(GUID));
	memset(chunk->data,0,chunk->len-24);

	globalinfo.hasV1header = 1;
	if (globalinfo.verbose)
		fprintf(stderr, "Found DRMv1 header object.\n");
	return 1;
}

static wchar_t *read_wchar(FILE *fp, int len) {
	wchar_t *res;
	int i;
	if (len < 0) return NULL;
	len >>= 1;
	res = calloc(len, sizeof(wchar_t));
	if (!res) return NULL;
	for (i = 0; i < len; i++) {
		res[i] = fgetc(fp);
		res[i] |= fgetc(fp) << 8;
	}
	// ensure 0-termination
	res[len - 1] = 0;
	if (!feof(fp)) return res;
	free(res);
	return NULL;
}

static int handle_drmv2(FILE * fp, CHUNKSAVE * chunk)
{
	unsigned datalen = chunk->len - 24;
	wchar_t *data;
	int fpos = ftell(fp);
	if (!handle_copy(fp, chunk))
		return 0;
	memcpy(&chunk->guid, PaddingGUID2, sizeof(GUID));
	memset(chunk->data,0,chunk->len-24);
	fseek(fp, fpos, SEEK_SET);
	if (globalinfo.verbose)
		fprintf(stderr, "Found DRMv2 header object.\n");

	fseek(fp, 6, SEEK_CUR);
	data = read_wchar(fp, datalen - 6);
	if (!data)
		error_exit("Data read in handle_drmv2 failed.");
        globalinfo.kid = get_element(L"KID", data);
        globalinfo.checksum = get_element(L"CHECKSUM", data);
        globalinfo.hasV2header = 1;

	if (globalinfo.verbose || globalinfo.asksid) {
		if (globalinfo.kid == NULL) {
			fprintf(stderr,
				"KID not found in header object!\n");
		} else {
			fprintf(stderr, "Found KID (");
			printwcs(globalinfo.kid);
			fprintf(stderr, ")\n");
		}
		if(globalinfo.checksum)
		{
			fprintf(stderr, "Found CHECKSUM (");
			printwcs(globalinfo.checksum);
			fprintf(stderr, ")\n");
		}	
	}
	free(data);
	return 1;
}


static int handle_packet2(FILE * fp, int packetlen)
{
	ASFContext asf;
	uchar *data;
	asf.key = globalinfo.content_key->keyhash;
    if ((data = malloc(packetlen)) == NULL)
		error_exit("Memory allocation failed in handle_packet.");
	asf_reset_header(&asf);
	asf.packet_size=packetlen;
	if (fread(data, packetlen, 1, fp) != 1)
		goto exit;
	if(!asf_get_packet(&asf,data))
		goto exit;
	while(asf.packet_segments>0)
	{
		asf_read_frame_header(&asf,data);
		asf_read_packet(&asf,data);
	}
	fwrite(data, packetlen, 1, stdout);
	free(data);
	return 1;
	exit:
	free(data);
	return 0;
}
static int handle_packet(FILE * fp, int packetlen)
{
	struct packethead_st {
		uchar id;
		short unknown1;
		uchar flags;
		uchar segTypeID;
		short psize;
	} *info;
	uchar *data;
	int flagoffset = 13;
	int objlen;
	int padding=0;
	int dataoffset;
	int paddingoffset=5;
	int numofsegsoffset=11;
    int numofsegs=1;
	int rval = 0,i,pos,gstart,gsize,g_total;
	CONTKEY *ckey;
    ckey=malloc(sizeof(CONTKEY));
    memcpy(ckey,globalinfo.content_key,sizeof(CONTKEY));
	if ((data = malloc(packetlen)) == NULL)
		error_exit("Memory allocation failed in handle_packet.");

    pos=ftell(fp);
	//fprintf(stderr, "POS: 0x%08X\n",pos);
	if (fread(data, packetlen, 1, fp) != 1)
		goto exit;
    memcpy(globalinfo.content_key,ckey,sizeof(CONTKEY));
    free(ckey);
  	//	for (i = 20; i < 32; i++)
		//	fprintf(stderr, " %02x", data[i]);
		//fprintf(stderr, "%d\n",padding);

	info = (struct packethead_st *) data;
	if (info->id != 0x82)
		error_exit("Unknown packet id - don't know what to do!");

	if (info->flags & 0x40)
	{
		flagoffset += 2;
		paddingoffset+=2;
		numofsegsoffset+=2;
	}
	//if (info->flags & 0x01)
	//	flagoffset += 2;
	if (info->flags & 0x10)
	{
		numofsegsoffset+=2;
        flagoffset += 2;
		padding=*(short *)&data[paddingoffset];
	}
	else if (info->flags & 0x08)
	{
		flagoffset += 1;
		numofsegsoffset+=1;
		padding=data[paddingoffset];
	}
	if (info->flags & 0x01)
		flagoffset += 1;

	if (info->segTypeID == 0x55)
		flagoffset += 1;
	else if (info->segTypeID == 0x59)
		flagoffset += 2;
	else if (info->segTypeID == 0x5d)
		flagoffset += 4;
    for(i=0;i<numofsegs;i++)
    {
        dataoffset = flagoffset + 9;
        if (info->flags &0x01)
        {
            numofsegs=data[numofsegsoffset];

            if (data[flagoffset] & 0x08)
            {
                dataoffset += 2;
                if ((data[flagoffset] & 0x02))
                {
                    dataoffset += 2;
                    if(numofsegs&0x80)
                    {
                            objlen = *(short *)&data[flagoffset+1+8+2];
                    }
                    else if(numofsegs&0x40)
                            objlen = data[flagoffset+1+8+2];
                }
                else
                {
                    if(numofsegs&0x80)
                            objlen = *(short *)&data[flagoffset+1+8];
                    else if(numofsegs&0x40)
                            objlen = data[flagoffset+1+8];
                }
            }
            else if ((data[flagoffset] & 0x01))
            {
                dataoffset = flagoffset+5;
                if(numofsegs&0x80)
                {
                    objlen = *(short *)&data[flagoffset+2];
                        //objlen=0x6f;
                }
                else if(numofsegs&0x40)
                    objlen = data[flagoffset+2];
                else
                    objlen = *(short *)&data[flagoffset+2];
                gstart=dataoffset;
                g_total=0;
                while(g_total < objlen)
                {
                    gsize=data[gstart-1];
                    //fprintf(stderr,"GS: %x\n",gsize);
                    //fprintf(stderr,"D1: %x\n",data[gstart]);
                    ff_asfcrypt_dec(globalinfo.content_key->keyhash,
                                    data + gstart, gsize);
                    //fprintf(stderr,"D2: %x\n",data[gstart]);
                    gstart+=1+gsize;
                    g_total+=1+gsize;
                }
                numofsegs=numofsegs&0x3f;
                //fprintf(stderr,"OUT: %x SEGS: %d I: %d\n",objlen,numofsegs,i);
                flagoffset=dataoffset+objlen+1;
                if (info->segTypeID == 0x55)
                    flagoffset += 1;
                else if (info->segTypeID == 0x59)
                    flagoffset += 2;
                else if (info->segTypeID == 0x5d)
                    flagoffset += 4;
                //fprintf(stderr,"FPOS: %x\n",pos+flagoffset);
                continue;

            }
            else
                objlen = *(short *)&data[flagoffset+1];
        }
        else if(info->flags == 0x40)
        {
                if (data[flagoffset] & 0x02)
                    dataoffset += 2;
                objlen = info->psize-dataoffset;
        }
        else if(info->flags & 0x08 || info->flags & 0x10)
        {
            dataoffset=flagoffset+9;
            if(data[flagoffset]&0x02)
                dataoffset+=2;
            objlen=packetlen-dataoffset-padding;
        }
        else
        {
            if(info->flags & 0x40)
            {
                if (data[flagoffset] & 0x02)
                    dataoffset += 2;
                objlen = info->psize;//-dataoffset;
            }
            else
            {
                objlen = *(short *)&data[flagoffset+1];
//                objlen = *(short *)&data[flagoffset+1+8];
            }
        }
        numofsegs=numofsegs&0x3f;
      //  fprintf(stderr,"S:0x%08x\n",objlen);
        //fprintf(stderr,"F:0x%08x\n",data[flagoffset]);
        //fprintf(stderr,"FPOS:0x%08x\n",pos+flagoffset);
        //fprintf(stderr,"D:0x%08x\n",*(unsigned*)&data[dataoffset]);
        ff_asfcrypt_dec(globalinfo.content_key->keyhash, data + dataoffset, objlen);
        flagoffset=dataoffset+objlen;
        //fprintf(stderr,"F2_2:0x%08x\n",*(unsigned*)&data[flagoffset-2]);
        //if(data[flagoffset]==0x82)
          //  fprintf(stderr,"Found new header!\n");
        if(data[flagoffset]==0x1b)
            flagoffset=dataoffset+objlen+3;
        else
            flagoffset=dataoffset+objlen+2;
        if (info->segTypeID == 0x55)
            flagoffset += 1;
        else if (info->segTypeID == 0x59)
            flagoffset += 2;
        else if (info->segTypeID == 0x5d)
            flagoffset += 4;
      //  fprintf(stderr,"In for\n");
    }

	fwrite(data, packetlen, 1, stdout);
	rval = 1;
	//if (info->flags==0x40)
//	{
  //    fprintf(stderr,"More than one segment found!\n");
        //fprintf(stderr,"0x%08x\n",objlen);
     //   exit(0);
//	}

exit:
	free(data);
	return rval;
}


static int handle_data(FILE * fp, CHUNKSAVE * chunk)
{
	uint8_t datahead[26];
	int packetcount = 0;
	int lastpercent = -1;
	int fpos;

	if(globalinfo.engine==2)
		pfn_handle_packet=handle_packet;
	else
		pfn_handle_packet=handle_packet2;

	if (fread(&datahead, sizeof(datahead), 1, fp) != 1)
		return 0;
	fwrite_chunk(chunk, stdout);
	fwrite(&datahead, sizeof(datahead), 1, stdout);
	if (globalinfo.verbose) {
		fprintf(stderr, "Starting to process data packets\n");
		fprintf(stderr, "%d packets of length %d\n",
			globalinfo.numpackets, globalinfo.packetlen);
	}

	fpos = ftell(fp);
	while (pfn_handle_packet(fp, globalinfo.packetlen)) {
		packetcount++;
		if (globalinfo.numpackets != 0) {
			int percent, i;
			percent =
			    ((packetcount * 200) / globalinfo.numpackets +
			     1) / 2;
			if (percent != lastpercent) {
				fprintf(stderr, "|");
				for (i = 0; i < percent / 2; i++)
					fprintf(stderr, "#");
				for (; i < 50; i++)
					fprintf(stderr, " ");
				fprintf(stderr, "|  ");
				fprintf(stderr, "%3d%%\r", percent);
				lastpercent = percent;
			}
		}
		fpos = ftell(fp);
	}
	fseek(fp, fpos, SEEK_SET);
	fprintf(stderr, "\n");

	return 0;
}


static int handle_header(FILE * fp, CHUNKSAVE * chunk)
{
	struct header_st {
		uint32_t numchunks;
		uint16_t unknown;
	} header;
	int i;
	CHUNKSAVE *subchunk = NULL;
	int savecount = 0;
	CHUNKSAVE *head = NULL, *tail = NULL;
	uint64_t bytesremoved = 0;
	if (!fread_le32(&header.numchunks, fp) ||
	    !fread_le16(&header.unknown, fp))
		return 0;

	for (i = 0; i < header.numchunks; i++) {
		if (subchunk == NULL) {
			if ((subchunk = malloc(sizeof(CHUNKSAVE))) == NULL)
				error_exit
				    ("Memory allocation failed in handle_header");
		}
		if (!handle_chunk(fp, subchunk))
			return 0;
		if (subchunk->data != NULL) {
			if (tail == NULL)
				head = subchunk;
			else
				tail->next = subchunk;
			subchunk->next = NULL;
			tail = subchunk;

			if ((subchunk = malloc(sizeof(CHUNKSAVE))) == NULL)
				error_exit
				    ("Memory allocation failed in handle_header");

			savecount++;
		} else {
			bytesremoved += subchunk->len;
		}
	}

	if (!globalinfo.fileheader) {
		error_exit("Didn't see file header!");
	} else {
		CHUNKSAVE *currchunk, *nextchunk;

		if (!globalinfo.hasV2header) {
			if (globalinfo.hasV1header)
				error_exit
				    ("This file is version 1 protected, not version 2.");
			else
				error_exit
				    ("This file doesn't seem to be protected!");
		}

		if (!globalinfo.kid)
			error_exit
			    ("Version 2 protected, but no KID found!");
		if (globalinfo.verbose)
			fprintf(stderr, "Starting to look for license.\n");
		globalinfo.content_key = MSDRM_init(globalinfo.kid);
		memcpy(&g_ckey,globalinfo.content_key,sizeof(CONTKEY));
		globalinfo.content_key=&g_ckey;
		if (globalinfo.content_key == NULL)
			error_exit("Couldn't find a valid license!");

		if (freopen(globalinfo.ofname, "wb", stdout) == NULL)
			error_exit("Couldn't open output file.");

		if (globalinfo.verbose)
			fprintf(stderr, "Opened output file <%s>\n",
				globalinfo.ofname);

		currchunk = head;
		header.numchunks = savecount;
		chunk->len -= bytesremoved;
		fwrite_chunk(chunk, stdout);
		fwrite_le32(header.numchunks, stdout);
		fwrite_le16(header.unknown, stdout);
		while (currchunk != NULL) {
			fwrite_chunk(currchunk, stdout);
			fwrite(currchunk->data,
			       currchunk->len - 24, 1,
			       stdout);
			nextchunk = currchunk->next;
			free(currchunk->data);
			free(currchunk);
			currchunk = nextchunk;
		}
	}

	return 1;
}


static int handle_file_header(FILE * fp, CHUNKSAVE * chunk)
{
	if (chunk->len < 24 + 68 + 4)
		return 0;
	if (!handle_copy(fp, chunk))
		return 0;

	globalinfo.fileheader = 1;
	globalinfo.packetlen = AV_RL32(chunk->data + 68);
	globalinfo.numpackets = AV_RL64(chunk->data + 32);
	if(globalinfo.numpackets == -1) {
		int fsize, fpos;
		fpos = ftell(fp);
		fseek(fp, 0, SEEK_END);
		fsize = ftell(fp);
		fseek(fp, fpos, SEEK_SET);
		globalinfo.numpackets = fsize / globalinfo.packetlen;
	}

	return 1;
}


static int handle_chunk(FILE * fp, CHUNKSAVE * chunk)
{
	GUIDHANDLER handler;

	chunk->data = NULL;

	if (!fread_chunk(chunk, fp))
		return 0;

	handler = find_guid(&chunk->guid);
	if (handler)
		return handler(fp, chunk);
	return handle_copy(fp, chunk);
}


int main(int argc, char *argv[])
{
	CHUNKSAVE chunk;
	int more = 1;
	FILE *ifp;
	char *fnamestart;
	static char ofname[1000];
	static char p_path[1000];

	globalinfo.verbose = 0;
	globalinfo.engine= 1;
	globalinfo.asksid = 0;
	globalinfo.fileheader = 0;
	globalinfo.kid = NULL;
	globalinfo.checksum = NULL;
	globalinfo.hasV1header = 0;
	globalinfo.hasV2header = 0;
	globalinfo.ofname = ofname;

	if ((argc < 2) || (argc > 3))
		error_exit("Usage: FreeMe2 [-vs2] protectedfile");

	//if ((strcmp(argv[1], "-v") != 0) && (argc == 3))
	//	error_exit("Usage: FreeMe2 [-vs] protectedfile");

	if (argc == 3)
	{
		if(strstr(argv[1],"2"))
			globalinfo.engine= 2;
		if(strstr(argv[1],"v"))
			globalinfo.verbose = 1;
		if(strstr(argv[1],"s"))
			globalinfo.asksid= 1;

	}
	if ((ifp = fopen(argv[argc - 1], "rb")) == NULL) {
		sprintf(ofname, "Couldn't open input file (%s)",
			argv[argc - 1]);
		error_exit(ofname);
	}

	ofname[0] = '\0';
	if ((fnamestart = strrchr(argv[argc - 1], SCHAR)) != NULL) {
		memcpy(ofname, argv[argc - 1],
		       fnamestart - argv[argc - 1] + 1);
		ofname[fnamestart - argv[argc - 1] + 1] = '\0';
	}
	strcpy(p_path,argv[0]);
	if(strrchr(p_path,SCHAR))
        *(strrchr(p_path,SCHAR)+1)=0;
    else
        p_path[0]=0;
    strcpy(p_dir,p_path);
	strcat(ofname, "Freed-");
	strcat(ofname, (fnamestart ? fnamestart + 1 : argv[argc - 1]));

	while (!feof(ifp)) {
		chunk.data = NULL;
		more = handle_chunk(ifp, &chunk);
		if (chunk.data) {
			fwrite_chunk(&chunk, stdout);
			fwrite(chunk.data, chunk.len - 24, 1, stdout);
			free(chunk.data);
		}
	}

	return 0;
}
