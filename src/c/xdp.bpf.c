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

struct hdr {
	struct ethhdr* eth;
	struct iphdr* ip;
	struct udphdr* udp;
};

static __always_inline struct hdr try_parse_udp(void *data, void *data_end);
static __always_inline int handle_udp(struct xdp_md *ctx, struct hdr hdr);


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} counter_map SEC(".maps");


SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	
	bpf_printk("xdp pass");
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct hdr hdr = try_parse_udp(data, data_end);

	if (hdr.udp != NULL) {
		return handle_udp(ctx, hdr);
	}

	return XDP_PASS;
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

int udp_dest[5] = { 7073, 8073, 9073, 11073, 10073 };
uint32_t sequencer_addr = (192 << 24 ) | (168 << 16 ) | (1<<8) | 1;
uint32_t server_addr = (192 << 24 ) | (168 << 16 ) | (1<<8) | 2;

uint8_t lo_mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


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
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

static __always_inline int handle_udp(struct xdp_md *ctx, struct hdr hdr)
{
	const u32 key = 0;
	const u32 initial_value = 1;
	
	if(bpf_ntohs(hdr.udp->dest) == 7072){
		bpf_printk("handle udp %d, interface %d", bpf_ntohl(hdr.ip->daddr), ctx->ingress_ifindex);
		
	}

	if (bpf_ntohl(hdr.ip->daddr) == sequencer_addr){
		bpf_printk("origin %u", sequencer_addr);
		bpf_printk("udp packet received");
		u32 new_addr = bpf_htonl(server_addr);

		int ret = bpf_xdp_store_bytes(
			ctx, ETH_SIZE + offsetof(struct iphdr, daddr), &new_addr,
			sizeof(u32));

		//ret = bpf_xdp_store_bytes(ctx, offsetof(struct ethhdr, h_dest), (void*) &lo_mac[0], 6);

		hdr.ip->check = iph_csum(hdr.ip);
		return XDP_TX;
	}

	return XDP_PASS;
}


char __license[] SEC("license") = "GPL";
