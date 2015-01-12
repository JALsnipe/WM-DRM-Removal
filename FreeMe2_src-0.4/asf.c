/*
 * ASF compatible demuxer
 * Copyright (c) 2000, 2001 Fabrice Bellard.
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "asf.h"
#include "asfcrypt.h"
#include <stdio.h>

#define FRAME_HEADER_SIZE 17
// Fix Me! FRAME_HEADER_SIZE may be different.
int gpos;

void url_fskip(unsigned char *pb,int fskip)
{
	gpos+=fskip;
}
unsigned char get_byte(unsigned char *pb)
{
	return pb[gpos++];
}

unsigned int get_le16(unsigned char *s)
{
    unsigned int val;
    val = get_byte(s);
    val |= get_byte(s) << 8;
    return val;
}

unsigned int get_le24(unsigned char *s)
{
    unsigned int val;
    val = get_le16(s);
    val |= get_byte(s) << 16;
    return val;
}

unsigned int get_le32(unsigned char *s)
{
    unsigned int val;
    val = get_le16(s);
    val |= get_le16(s) << 16;
    return val;
}

uint64_t get_le64(unsigned char *s)
{
    uint64_t val;
    val = (uint64_t)get_le32(s);
    val |= (uint64_t)get_le32(s) << 32;
    return val;
}

#define DO_2BITS(bits, var, defval) \
    switch (bits & 3) \
    { \
    case 3: var = get_le32(pb); rsize += 4; break; \
    case 2: var = get_le16(pb); rsize += 2; break; \
    case 1: var = get_byte(pb); rsize++; break; \
    default: var = defval; break; \
    }

/**
 *
 * @return <0 in case of an error
 */
int asf_get_packet(ASFContext *asf,unsigned char *pb)
{
    uint32_t packet_length, padsize;
    int rsize = 8;
    int c, d, e, off;

    off=3;

    c=d=e=-1;
    while(off-- > 0){
        c=d; d=e;
        e= get_byte(pb);
        if(c == 0x82 && !d && !e)
            break;
    }

    if (c != 0x82) {
		return 0;
    }
    if ((c & 0x8f) == 0x82) {
        if (d || e) {
	   		error_exit("ff asf bad non zero - don't know what to do!");
        }
        c= get_byte(pb);
        d= get_byte(pb);
        rsize+=3;
    }

    asf->packet_flags    = c;
    asf->packet_property = d;

    DO_2BITS(asf->packet_flags >> 5, packet_length, asf->packet_size);
    DO_2BITS(asf->packet_flags >> 1, padsize, 0); // sequence ignored
    DO_2BITS(asf->packet_flags >> 3, padsize, 0); // padding length

    //the following checks prevent overflows and infinite loops
    if(packet_length >= (1U<<29)){
	   	fprintf(stderr,"\rinvalid packet_length (0x%08X) - don't know what to do!\n",packet_length);
	   	fprintf(stderr,"Output pos: 0x%08X\n",ftell(stdout));
		return 0;
    }
    if(padsize >= packet_length){
	   	error_exit("invalid padsize - don't know what to do!");
    }

    asf->packet_timestamp = get_le32(pb);
    get_le16(pb); /* duration */
    // rsize has at least 11 bytes which have to be present

    if (asf->packet_flags & 0x01) {
        asf->packet_segsizetype = get_byte(pb); rsize++;
        asf->packet_segments = asf->packet_segsizetype & 0x3f;
    } else {
        asf->packet_segments = 1;
        asf->packet_segsizetype = 0x80;
    }
    asf->packet_size_left = packet_length - padsize - rsize;
    if (packet_length < asf->hdr.min_pktsize)
        padsize += asf->hdr.min_pktsize - packet_length;
    asf->packet_padsize = padsize;
   return 1;
}

/**
 *
 * @return <0 if error
 */
int asf_read_frame_header(ASFContext *asf,unsigned char *pb){
    int rsize = 1;
    int num = get_byte(pb);
    int64_t ts0, ts1;

    asf->packet_segments--;
    asf->packet_key_frame = num >> 7;
    asf->stream_index = asf->asfid2avid[num & 0x7f];
    // sequence should be ignored!
    DO_2BITS(asf->packet_property >> 4, asf->packet_seq, 0);
    DO_2BITS(asf->packet_property >> 2, asf->packet_frag_offset, 0);
    DO_2BITS(asf->packet_property, asf->packet_replic_size, 0);
//printf("key:%d stream:%d seq:%d offset:%d replic_size:%d\n", asf->packet_key_frame, asf->stream_index, asf->packet_seq, //asf->packet_frag_offset, asf->packet_replic_size);
    if (asf->packet_replic_size >= 8) {
        asf->packet_obj_size = get_le32(pb);
        if(asf->packet_obj_size >= (1<<24) || asf->packet_obj_size <= 0){
	   		error_exit("packet_obj_size invalid - don't know what to do!");
        }
        asf->packet_frag_timestamp = get_le32(pb); // timestamp
        if(asf->packet_replic_size >= 8+38+4){
//            for(i=0; i<asf->packet_replic_size-8; i++)
//                av_log(s, AV_LOG_DEBUG, "%02X ",get_byte(pb));
//            av_log(s, AV_LOG_DEBUG, "\n");
            url_fskip(pb, 10);
            ts0= get_le64(pb);
            ts1= get_le64(pb);
            url_fskip(pb, 12);
            get_le32(pb);
            url_fskip(pb, asf->packet_replic_size - 8 - 38 - 4);
            if(ts0!= -1) asf->packet_frag_timestamp= ts0/10000;
            else         asf->packet_frag_timestamp= 0;
        }else
            url_fskip(pb, asf->packet_replic_size - 8);
        rsize += asf->packet_replic_size; // FIXME - check validity
    } else if (asf->packet_replic_size==1){
        // multipacket - frag_offset is beginning timestamp
        asf->packet_time_start = asf->packet_frag_offset;
        asf->packet_frag_offset = 0;
        asf->packet_frag_timestamp = asf->packet_timestamp;

        asf->packet_time_delta = get_byte(pb);
        rsize++;
    }else if(asf->packet_replic_size!=0){
	   		error_exit("unexpected packet_replic_size - don't know what to do!");
    }
    if (asf->packet_flags & 0x01) {
        DO_2BITS(asf->packet_segsizetype >> 6, asf->packet_frag_size, 0); // 0 is illegal
        if(asf->packet_frag_size > asf->packet_size_left - rsize){
	   		error_exit("packet_frag_size is invalid - don't know what to do!");
        }
        //printf("Fragsize %d\n", asf->packet_frag_size);
    } else {
        asf->packet_frag_size = asf->packet_size_left - rsize;
        //printf("Using rest  %d %d %d\n", asf->packet_frag_size, asf->packet_size_left, rsize);
    }
    if (asf->packet_replic_size == 1) {
        asf->packet_multi_size = asf->packet_frag_size;
        if (asf->packet_multi_size > asf->packet_size_left)
            return -1;
    }
    asf->packet_size_left -= rsize;
    //printf("___objsize____  %d   %d    rs:%d\n", asf->packet_obj_size, asf->packet_frag_offset, rsize);

    return 0;
}

int asf_read_packet(ASFContext *asf,unsigned char *pb)
{
    //static int pc = 0;
	int i=0;
    for (;;) {
		i++;
        if (asf->packet_replic_size == 1) {
            // frag_offset is here used as the beginning timestamp
            asf->packet_frag_timestamp = asf->packet_time_start;
            asf->packet_time_start += asf->packet_time_delta;
            asf->packet_obj_size = asf->packet_frag_size = get_byte(pb);
            asf->packet_size_left--;
            asf->packet_multi_size--;
            if (asf->packet_multi_size < asf->packet_obj_size)
            {
                asf->packet_time_start = 0;
                url_fskip(pb, asf->packet_multi_size);
                asf->packet_size_left -= asf->packet_multi_size;
                continue;
            }
            asf->packet_multi_size -= asf->packet_obj_size;
            //printf("COMPRESS size  %d  %d  %d   ms:%d\n", asf->packet_obj_size, asf->packet_frag_timestamp, asf->packet_size_left, asf->packet_multi_size);
        }
//asf->stream_index, asf->packet_key_frame, asf_st->pkt.flags & PKT_FLAG_KEY,
//s->streams[asf->stream_index]->codec->codec_type == CODEC_TYPE_AUDIO, asf->packet_obj_size);
       //}

        //printf("READ PACKET s:%d  os:%d  o:%d,%d  l:%d   DATA:%p\n",
        //       asf->packet_size, asf_st->pkt.size, asf->packet_frag_offset,
        //       asf_st->frag_offset, asf->packet_frag_size, asf_st->pkt.data);
        asf->packet_size_left -= asf->packet_frag_size;
          //get_buffer(pb, asf_st->pkt.data + asf->packet_frag_offset
         //          asf->packet_frag_size);
		 //fprintf(stderr,"0x%08X - %d\n",asf->packet_replic_size,i);
		 //if(asf->packet_frag_offset)
		 //{
		 	//fprintf(stderr,"0x%08X\n",*(unsigned *)&pb[gpos]);
		 	//fprintf(stderr,"0x%08X\n",asf->packet_frag_offset);
		 //}
            ff_asfcrypt_dec(asf->key, &pb[gpos],
                            asf->packet_frag_size);
		 gpos+=asf->packet_frag_size;
         if (asf->packet_replic_size==1)
            continue;
		else
			break;
    }
	//if(asf->packet_frag_offset)
	//	error_exit("test");
    return 0;
}

// Added to support seeking after packets have been read
// If information is not reset, read_packet fails due to
// leftover information from previous reads
void asf_reset_header(ASFContext *asf)
{
	gpos=0;
    asf->packet_nb_frames = 0;
    asf->packet_size_left = 0;
    asf->packet_segments = 0;
    asf->packet_flags = 0;
    asf->packet_property = 0;
    asf->packet_timestamp = 0;
    asf->packet_segsizetype = 0;
    asf->packet_segments = 0;
    asf->packet_seq = 0;
    asf->packet_replic_size = 0;
    asf->packet_key_frame = 0;
    asf->packet_padsize = 0;
    asf->packet_frag_offset = 0;
    asf->packet_frag_size = 0;
    asf->packet_frag_timestamp = 0;
    asf->packet_multi_size = 0;
    asf->packet_obj_size = 0;
    asf->packet_time_delta = 0;
    asf->packet_time_start = 0;
}
