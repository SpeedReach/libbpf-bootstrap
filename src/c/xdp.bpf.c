#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


#define ETH_P_IP	0x0800

#define IP_P_TCP 6
#define IP_P_UDP 17

#define ETH_SIZE sizeof(struct ethhdr)
#define IP_SIZE sizeof(struct iphdr)
#define UDP_SIZE sizeof(struct udphdr)
#define TCP_SIZE sizeof(struct tcphdr)


static __always_inline struct tcphdr* try_parse_tcphdr(void* data, void* data_end);
static __always_inline struct udphdr* try_parse_udphdr(void* data, void* data_end);
static __always_inline int handle_tcp(struct xdp_md *ctx, struct tcphdr* tcphdr);
static __always_inline int handle_udp(struct xdp_md *ctx, struct udphdr* udphdr);

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;


    struct udphdr* udphdr = try_parse_udphdr(data, data_end);

   	if(udphdr){
       return handle_udp(ctx, udphdr);
    }

	//struct tcphdr* tcphdr = try_parse_tcphdr(data, data_end);

    //if (tcphdr){
      //  return handle_tcp(ctx, tcphdr);
    //}
	
    return XDP_PASS;
}


static __always_inline int handle_tcp(struct xdp_md *ctx,struct tcphdr* tcphdr) {
    if(bpf_ntohs(tcphdr->dest) == 7072){
        u16 new_dest = bpf_htons(50051);

        int ret = bpf_xdp_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, dest), &new_dest, sizeof(u16));

        bpf_printk("store dest %d", ret);

        return XDP_TX;
    }

    if(bpf_ntohs(tcphdr->source) == 50051){
        u16 new_src = bpf_htons(50050);

        int ret = bpf_xdp_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct tcphdr, source), &new_src, sizeof(u16));

        bpf_printk("store src %d", ret);

        return XDP_TX;
    }

    return XDP_PASS;
}


static __always_inline struct tcphdr* try_parse_tcphdr(void* data, void* data_end) {
    if (data + ETH_SIZE > data_end)
        return 0;
    struct ethhdr* ethhdr = data;

    if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IP)
        return 0;

    if (data + ETH_SIZE + IP_SIZE > data_end)
        return 0;

    struct iphdr* iphdr = data + ETH_SIZE;

    if (iphdr->protocol != IP_P_TCP)
        return 0;

    if (data + ETH_SIZE + IP_SIZE + TCP_SIZE > data_end)
        return 0;

    return data + ETH_SIZE + IP_SIZE;
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

static __always_inline int handle_udp(struct xdp_md *ctx,struct udphdr* udphdr) {
	if(bpf_ntohs(udphdr->dest) == 50051){
		bpf_printk("udp dest 50051");
	}
    if(bpf_ntohs(udphdr->dest) == 50050){
        u16 new_dest = bpf_htons(50051);
        int ret = bpf_xdp_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_dest, sizeof(u16));
        bpf_printk("store dest %d", ret);
		u32 seq = 1;
		ret = bpf_xdp_store_bytes(ctx, ctx->data_end - sizeof(u32) - ctx->data, &seq, sizeof(u32));
		bpf_printk("store seq %d", ret);
        return XDP_TX;
    }

    if(bpf_ntohs(udphdr->source) == 50051){
        u16 new_src = bpf_htons(50050);

        int ret = bpf_xdp_store_bytes(ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, source), &new_src, sizeof(u16));

        bpf_printk("store src %d", ret);

        return XDP_TX;
    }

    return XDP_PASS;
}


char __license[] SEC("license") = "GPL";
