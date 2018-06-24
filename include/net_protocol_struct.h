/*************************************************************************
	> File Name: net_protocol_struct.h
	> Author: Dapiqing
	> Mail:971774262@qq.com 
	> Created Time: Thu Jun  7 15:12:56 2018
 ************************************************************************/

#ifndef _NET_PROTOCOL_STRUCT_H_
#define _NET_PROTOCOL_STRUCT_H_

struct ether_header  
{  
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
} __attribute__ ((__packed__));  

struct linux_cooked
{
	uint16_t packet_type;
	uint16_t addr_type;
	uint16_t addr_len;
	uint8_t  addr[8];
	uint16_t protocol_type;
} __attribute__ ((__packed__));

struct ip_hdr
{
    uint8_t  ip_version:4;
    uint8_t  ip_hdr_len:4;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t src_addr;
    uint32_t dst_addr;
    /*The options start here. */
} __attribute__ ((__packed__));

struct tcp_hdr
{
    uint16_t th_sport;     /* source port */
    uint16_t th_dport;     /* destination port */
    uint32_t th_seq;     /* sequence number */
    uint32_t th_ack;     /* acknowledgement number */
    uint8_t th_off:4;      /* data offset */
    uint8_t th_x2:4;       /* (unused) */
    uint8_t th_flags;
#  define TH_FIN    0x01
#  define TH_SYN    0x02
#  define TH_RST    0x04
#  define TH_PUSH   0x08
#  define TH_ACK    0x10
#  define TH_URG    0x20
    uint16_t th_win;       /* window */
    uint16_t th_sum;       /* checksum */
    uint16_t th_urp;       /* urgent pointer */
} __attribute__ ((__packed__));

#endif