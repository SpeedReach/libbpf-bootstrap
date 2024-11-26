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



static inline __u16 compute_ip_checksum(struct iphdr *ip, void *data_end) {
    __u16 *next_ip_u16 = (__u16 *)ip;
    __u16 *end = (__u16 *)data_end;
    __u32 csum = 0;

    // Ensure that `ip` is valid and does not cross data_end
    if ((void *)next_ip_u16 + sizeof(*ip) > data_end) {
        return 0; // Invalid access, return 0
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}

uint16_t server_port[5] = { 7073, 8073, 9073, 10073, 11073 };
uint16_t sequencer_port = 7072;
//uint32_t sequencer_addr = (192 << 24) | (168 << 16) | (50 << 8) | 230;
uint32_t sequencer_addr = (192 << 24) | (168 << 16) | (50 << 8) | 230;
uint32_t server_addrs[5] = {
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	(192 << 24) | (168 << 16) | (50 << 8) | 213,
	(192 << 24) | (168 << 16) | (50 << 8) | 213,
};

unsigned char sequencer_mac_addr[6] = {0x74,0xd4,0xdd, 0x2c, 0xb1, 0x79};
//02:42:2c:a9:b8:45
unsigned char server_mac_addrs[5][6] = {
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	{0x9c, 0x2d, 0xcd, 0x48, 0xb1, 0x04},
	{0x9c, 0x2d, 0xcd, 0x48, 0xb1, 0x04}
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

		for (int i = 0; i < 5; i++) {
			u16 new_port = bpf_htons(server_port[i]);
			int ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_port,
				sizeof(u16), BPF_F_RECOMPUTE_CSUM);
			bpf_printk("store port %d %d ", ret, i);

			u32 seq = *count;
			ret = bpf_skb_store_bytes(ctx, ctx->data_end - sizeof(u32) - ctx->data,
						  &seq, sizeof(u32), BPF_F_RECOMPUTE_CSUM);

			u16 zero16 = 0;
			ret = bpf_skb_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, check),
							&zero16, sizeof(16), 0);

			
			u32 new_daddr = bpf_htonl(server_addrs[i]);
			bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, daddr), &new_daddr,
				sizeof(u32), 0);
			
			u32 new_saddr = bpf_htonl(sequencer_addr);
			bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, saddr), &new_saddr,
				sizeof(u32), 0);

			Elf32_Half check = 0;
			bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
				sizeof(u16), 0);
			hdr = try_parse_udp((void*) ctx->data ,(void*) ctx->data_end);
			if (hdr.udp != NULL)
				check = compute_ip_checksum(hdr.ip, (void*) ctx->data_end);
			bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
				sizeof(u16), 0);

			//set mac address
			ret = bpf_skb_store_bytes(
				ctx, offsetof(struct ethhdr, h_dest), server_mac_addrs[i],
				sizeof(server_mac_addrs[i]), 0);
			bpf_printk("store mac %d %d", ret, i);

			ret = bpf_skb_store_bytes(
				ctx, offsetof(struct ethhdr, h_source), sequencer_mac_addr,
				sizeof(sequencer_mac_addr), 0);

			bpf_printk("store seq %d %d", ret, i);
			ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
			bpf_printk("redirect %d %d", ret, i);


		}
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}


char __license[] SEC("license") = "GPL";
