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

	if (hdr.udp != NULL) {
		return handle_udp(ctx, hdr);
	}

	return TC_ACT_OK;
}


static __always_inline struct hdr try_parse_udp(void* data, void* data_end){
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
	
	if(data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end)
		return (struct hdr) {NULL,NULL, NULL};
	
	struct udphdr* udp = data + ETH_SIZE + IP_SIZE;
	return (struct hdr){eth,ip, udp};
}



static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct __sk_buff *ctx)
{
    u16 new_sum = 0;
	bpf_skb_store_bytes(
		ctx, ETH_SIZE + offsetof(struct iphdr, check), &new_sum,
		sizeof(u16), BPF_F_RECOMPUTE_CSUM);

	struct iphdr* iph = try_parse_udp((void *)(long)ctx->data, (void *)(long)ctx->data_end).ip;

    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

uint16_t server_port[5] = { 7073, 8073, 9073, 10073, 11073 };
uint16_t sequencer_port = 7072;
//uint32_t sequencer_addr = (192 << 24) | (168 << 16) | (50 << 8) | 230;
uint32_t sequencer_addr = (127 << 24) | (0 << 16) | (0 << 8) | 1;
uint32_t server_addrs[5] = {
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	(192 << 24) | (168 << 16) | (50 << 8) | 213,
	(192 << 24) | (168 << 16) | (50 << 8) | 213,
};

unsigned char server_mac_addrs[5][6] = {
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	{0x9c, 0x2d, 0xcd, 0x48, 0xb1, 0x04},
	{0x9c, 0x2d, 0xcd, 0x48, 0xb1, 0x04}
};



struct l3_fields
{
    __u32 saddr;
    __u32 daddr;
};


static __always_inline int handle_udp(struct __sk_buff *ctx, struct hdr hdr)
{
	const u32 key = 0;
	const u32 initial_value = 1;

	if (bpf_ntohs(hdr.udp->dest) == sequencer_port) {
		u32 *count = bpf_map_lookup_elem(&counter_map, &key);
		if (count) {
			__sync_fetch_and_add(count, 1);
		} else {
			count = &initial_value;
			bpf_map_update_elem(&counter_map, &key, &initial_value, BPF_ANY);
		}

		struct l3_fields l3_original_fields;

		for (int i = 0; i < 5; i++) {

			bpf_skb_load_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, saddr), &l3_original_fields, sizeof(l3_original_fields));
			u32 new_addr = bpf_htonl(server_addrs[i]);
			int ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + offsetof(struct iphdr, daddr), &new_addr,
				sizeof(u32), BPF_F_RECOMPUTE_CSUM);

			bpf_printk("store addr %d %d", ret, i);
			
			struct l3_fields l3_new_fields = { .saddr = l3_original_fields.saddr, .daddr = new_addr };
			u32 l3sum = bpf_csum_diff((__u32 *)&l3_original_fields, sizeof(l3_original_fields), (__u32 *)&l3_new_fields, sizeof(l3_new_fields), 0);
			int csumret = bpf_l3_csum_replace(ctx, ETH_SIZE + offsetof(struct iphdr, check), 0, l3sum, 0);
			bpf_printk("csumret %d %d", csumret, i);

			u16 new_port = bpf_htons(server_port[i]);
			ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_port,
				sizeof(u16), BPF_F_RECOMPUTE_CSUM);
			bpf_printk("store port %d %d ", ret, i);

			u32 seq = *count;
			ret = bpf_skb_store_bytes(ctx, ctx->data_end - sizeof(u32) - ctx->data,
						  &seq, sizeof(u32), BPF_F_RECOMPUTE_CSUM);
			

			//set mac address
			ret = bpf_skb_store_bytes(
				ctx, offsetof(struct ethhdr, h_dest), server_mac_addrs[i],
				sizeof(server_mac_addrs[i]), 0);
			bpf_printk("store mac %d %d", ret, i);



			bpf_printk("store seq %d %d", ret, i);
			ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
			bpf_printk("redirect %d %d", ret, i);


		}
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}


char __license[] SEC("license") = "GPL";
