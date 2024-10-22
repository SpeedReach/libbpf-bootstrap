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
	struct iphdr* ip;
	struct udphdr* udp;
};

static __always_inline struct hdr try_parse_udp(void *data, void *data_end);
static __always_inline int handle_udp(struct __sk_buff *ctx, struct hdr hdr);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} counter_map SEC(".maps");

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct hdr hdr = try_parse_udp(data, data_end);

	if (hdr.ip != NULL && hdr.udp != NULL) {
		return handle_udp(ctx, hdr);
	}

	return TC_ACT_OK;
}


static __always_inline struct hdr try_parse_udp(void* data, void* data_end){
	if(data + ETH_SIZE > data_end)
		return (struct hdr) {NULL, NULL};
	
	struct ethhdr* eth = data;
	if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return (struct hdr) {NULL, NULL};

	if(data + ETH_SIZE + IP_SIZE > data_end)
		return (struct hdr) {NULL, NULL};
	
	struct iphdr* ip = data + ETH_SIZE;
	if(ip->protocol != IP_P_UDP)
		return (struct hdr) {NULL, NULL};
	
	if(data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end)
		return (struct hdr) {NULL, NULL};
	
	struct udphdr* udp = data + ETH_SIZE + IP_SIZE;
	return (struct hdr){ip, udp};
}

int udp_dest[5] = { 7073, 8073, 9073, 11073, 10073 };
uint32_t sequencer_addr = (192 << 24) | (168 << 16) | (1 << 8) | 1;
uint32_t server_addr = (192 << 24) | (168 << 16) | (1 << 8) | 2;

static __always_inline int handle_udp(struct __sk_buff *ctx, struct hdr hdr)
{
	const u32 key = 0;
	const u32 initial_value = 1;


	if (bpf_ntohl(hdr.ip->daddr) == sequencer_addr){
		bpf_printk("udp packet received");
		u32 new_addr = bpf_htons(server_addr);
		int ret = bpf_skb_store_bytes(
			ctx, ETH_SIZE + offsetof(struct iphdr, daddr), &new_addr,
			sizeof(u32), BPF_F_RECOMPUTE_CSUM);
		bpf_printk("store addr %d", ret);
		ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
		bpf_printk("redirect %d", ret);
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
