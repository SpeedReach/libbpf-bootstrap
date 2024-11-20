// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define ETH_P_IP    0x0800

#define IP_P_TCP    6
#define IP_P_UDP    17

#define ETH_SIZE    sizeof(struct ethhdr)
#define IP_SIZE	    sizeof(struct iphdr)
#define UDP_SIZE    sizeof(struct udphdr)
#define TCP_SIZE    sizeof(struct tcphdr)

struct hdr {
	struct ethhdr* eth;
	struct iphdr* ip;
	struct tcphdr* tcp;
};

static __always_inline struct hdr try_parse_tcp(void *data, void *data_end);
static __always_inline int handle_tcp(struct __sk_buff *ctx, struct hdr hdr);


SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct hdr hdr = try_parse_tcp(data, data_end);

	if (hdr.tcp != NULL) {
		return handle_tcp(ctx, hdr);
	}

	return TC_ACT_OK;
}


static __always_inline struct hdr try_parse_tcp(void* data, void* data_end){
	if(data + ETH_SIZE > data_end)
		return (struct hdr) {NULL,NULL, NULL};
	
	struct ethhdr* eth = data;
	if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return (struct hdr) {NULL,NULL, NULL};

	if(data + ETH_SIZE + IP_SIZE > data_end)
		return (struct hdr) {NULL,NULL, NULL};
	
	struct iphdr* ip = data + ETH_SIZE;
	if(ip->protocol != IP_P_UDP)
		return (struct hdr) {NULL,NULL, NULL};
	
	if(data + ETH_SIZE + IP_SIZE + TCP_SIZE > data_end)
		return (struct hdr) {NULL,NULL, NULL};
	
	struct tcphdr* tcp = data + ETH_SIZE + IP_SIZE;
	return (struct hdr){eth,ip, tcp};
}



uint16_t server_port = 7070;
uint16_t redirct_port= 7071;


static __always_inline int handle_tcp(struct __sk_buff *ctx, struct hdr hdr)
{
	const u32 key = 0;
	const u32 initial_value = 1;

	if (bpf_ntohs(hdr.tcp->dest) == redirct_port) {
		u16 new_port = bpf_htons(server_port);
		int ret = bpf_skb_store_bytes(
			ctx, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &new_port,
			sizeof(u16), BPF_F_RECOMPUTE_CSUM);
		bpf_printk("store port %d", ret);
		int ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
		bpf_printk("redirect %d", ret);
		return TC_ACT_SHOT;
	}

	if (bpf_ntohs(hdr.tcp->source) == server_port) {
		u16 new_port = bpf_htons(redirct_port);
		int ret = bpf_skb_store_bytes(
			ctx, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, source), &new_port,
			sizeof(u16), BPF_F_RECOMPUTE_CSUM);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}


char __license[] SEC("license") = "GPL";
