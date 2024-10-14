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

static __always_inline struct tcphdr *try_parse_tcphdr(void *data, void *data_end);
static __always_inline struct udphdr *try_parse_udphdr(void *data, void *data_end);
static __always_inline int handle_udp(struct __sk_buff *ctx, struct udphdr *udphdr);
static __always_inline int handle_tcp(struct __sk_buff *ctx, struct tcphdr *tcphdr);

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

	struct udphdr *udphdr = try_parse_udphdr(data, data_end);

	if (udphdr) {
		return handle_udp(ctx, udphdr);
	}

    struct tcphdr* tcphdr = try_parse_tcphdr(data, data_end);
    if (tcphdr) {
        return handle_tcp(ctx, tcphdr);
    }

	return TC_ACT_OK;
}

static __always_inline struct udphdr *try_parse_udphdr(void *data, void *data_end)
{
	if (data + ETH_SIZE > data_end)
		return 0;
	struct ethhdr *ethhdr = data;

	if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP)
		return 0;

	if (data + ETH_SIZE + IP_SIZE > data_end)
		return 0;

	struct iphdr *iphdr = data + ETH_SIZE;

	if (iphdr->protocol != IP_P_UDP)
		return 0;

	if (data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end)
		return 0;

	return data + ETH_SIZE + IP_SIZE;
}

static __always_inline struct tcphdr *try_parse_tcphdr(void *data, void *data_end)
{
	if (data + ETH_SIZE > data_end)
		return 0;
	struct ethhdr *ethhdr = data;

	if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP)
		return 0;

	if (data + ETH_SIZE + IP_SIZE > data_end)
		return 0;

	struct iphdr *iphdr = data + ETH_SIZE;

	if (iphdr->protocol != IP_P_TCP)
		return 0;

	if (data + ETH_SIZE + IP_SIZE + TCP_SIZE > data_end)
		return 0;

	return data + ETH_SIZE + IP_SIZE;
}

int udp_dest[5] = { 7073, 8073, 9073, 11073, 10073 };

static __always_inline int handle_udp(struct __sk_buff *ctx, struct udphdr *udphdr)
{
	const u32 key = 0;
	const u32 initial_value = 1;

	if (bpf_ntohs(udphdr->dest) == 7072) {
		u32 *count = bpf_map_lookup_elem(&counter_map, &key);
		if (count) {
			__sync_fetch_and_add(count, 1);
		} else {
			count = &initial_value;
			bpf_map_update_elem(&counter_map, &key, &initial_value, BPF_ANY);
		}

		for (int i = 0; i < 2; i++) {
			u16 new_dest = bpf_htons(udp_dest[i]);
			int ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_dest,
				sizeof(u16), BPF_F_RECOMPUTE_CSUM);
			bpf_printk("store dest %d %d ", ret, i);

			u32 seq = *count;
			ret = bpf_skb_store_bytes(ctx, ctx->data_end - sizeof(u32) - ctx->data,
						  &seq, sizeof(u32), BPF_F_RECOMPUTE_CSUM);
			bpf_printk("store seq %d %d", ret, i);
			ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
			bpf_printk("redirect %d %d", ret, i);
		}
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}


static __always_inline int handle_tcp(struct __sk_buff *ctx, struct tcphdr *udphdr)
{
	const u32 key = 0;
	const u32 initial_value = 1;

	if (bpf_ntohs(udphdr->dest) == 7072) {
		u32 *count = bpf_map_lookup_elem(&counter_map, &key);
		if (count) {
			__sync_fetch_and_add(count, 1);
		} else {
			count = &initial_value;
			bpf_map_update_elem(&counter_map, &key, &initial_value, BPF_ANY);
		}

		for (int i = 0; i < 2; i++) {
			u16 new_dest = bpf_htons(udp_dest[i]);
			int ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &new_dest,
				sizeof(u16), BPF_F_RECOMPUTE_CSUM);
			bpf_printk("store dest %d %d ", ret, i);

			u32 seq = *count;
			ret = bpf_skb_store_bytes(ctx, ctx->data_end - sizeof(u32) - ctx->data,
						  &seq, sizeof(u32), BPF_F_RECOMPUTE_CSUM);
			bpf_printk("store seq %d %d", ret, i);
			ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
			bpf_printk("redirect %d %d", ret, i);
		}
		return TC_ACT_SHOT;
	}

    u16 source = bpf_ntohs(udphdr->source);
    for(int i=0;i<5;i ++) {
        u16 new_src = bpf_htons(7072);
        if (source == udp_dest[i]) {
            int ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, source), &new_src,
				sizeof(u16), BPF_F_RECOMPUTE_CSUM);
            ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);

            return TC_ACT_SHOT;   
        }
    }

	return TC_ACT_OK;
}



char __license[] SEC("license") = "GPL";
