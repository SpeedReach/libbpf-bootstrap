// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ETH_P_IP	0x0800

#define IP_P_TCP 6
#define IP_P_UDP 17

#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define UDP_SIZE sizeof(struct udphdr)
#define TCP_SIZE sizeof(struct tcphdr)


static __always_inline struct tcphdr* try_parse_tcphdr(void* data, void* data_end);
static __always_inline struct udphdr* try_parse_udphdr(void* data, void* data_end);
static __always_inline int handle_udp(struct __sk_buff *ctx, struct udphdr* udphdr);

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;


    struct udphdr* udphdr = try_parse_udphdr(data, data_end);

   	if(udphdr){
       return handle_udp(ctx, udphdr);
    }

	return TC_ACT_OK;
}



static __always_inline struct udphdr* try_parse_udphdr(void* data, void* data_end) {
    if (data + ETH_SIZE > data_end)
        return 0;
    struct ethhdr* ethhdr = data;

    if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP)
        return 0;

    if (data + ETH_SIZE + IP_SIZE > data_end)
        return 0;

    struct iphdr* iphdr = data + ETH_SIZE;

    if (iphdr->protocol != IP_P_UDP)
        return 0;

    if (data + ETH_SIZE + IP_SIZE + UDP_SIZE > data_end)
        return 0;

    return data + ETH_SIZE + IP_SIZE;
}



int udp_dest[2] = {50051, 50052};

static __always_inline int handle_udp(struct __sk_buff *ctx,struct udphdr* udphdr) {

    if(bpf_ntohs(udphdr->dest) == 50050){
		for (int i = 0; i < 2; i++) {
			u16 new_dest = bpf_htons(udp_dest[i]);
        	int ret = bpf_skb_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_dest, sizeof(u16), BPF_F_RECOMPUTE_CSUM);
        	bpf_printk("store dest %d %d ", ret, i);
			u32 seq = i;
			ret = bpf_skb_store_bytes(ctx, ctx->data_end - sizeof(u32) - ctx->data, &seq, sizeof(u32), BPF_F_RECOMPUTE_CSUM);
			bpf_printk("store seq %d %d", ret, i);
			ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
			bpf_printk("redirect %d %d", ret, i);
		}
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}


char __license[] SEC("license") = "GPL";


