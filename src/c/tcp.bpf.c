//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

#define ETH_P_IP    0x0800

#define IP_P_TCP    6
#define IP_P_UDP    17

#define ETH_SIZE    sizeof(struct ethhdr)
#define IP_SIZE	    sizeof(struct iphdr)
#define UDP_SIZE    sizeof(struct udphdr)
#define TCP_SIZE    sizeof(struct tcphdr)

#define MAX_ENTRIES_PER_PACKET 20

char __license[] SEC("license") = "Dual MIT/GPL";

struct hdr {
	struct ethhdr* eth;
	struct iphdr* ip;
	struct udphdr* udp;
};

static inline __u16 compute_ip_checksum(struct iphdr *ip, void *data_end);


static __always_inline struct hdr try_parse_udp(void* data, void* data_end);

#define SERVER_COUNT 1

__u16 redirect_port = 12345;
__u16 server_ports[SERVER_COUNT] = {
	12346,
	//12346,
	//12346
};
//192.168.50.224
__u32 server_ips[SERVER_COUNT]={
	(192 << 24) | (168 << 16) | (50 << 8) | 224,
	//(192 << 24) | (168 << 16) | (50 << 8) | 16,
	//(192 << 24) | (168 << 16) | (50 << 8) | 230
};

__u8 server_macs[SERVER_COUNT][6] = {
	{0x9c, 0x2d, 0xcd, 0x3f, 0x67, 0xa4},
	//{0x84, 0x99, 0x31, 0x82, 0xc7, 0xb3},
	//{0x74, 0xd4, 0xdd, 0x2c, 0xb1, 0x79}
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, __u16);
	__type(value, __u16);
} dest_map SEC(".maps");

struct ip_flags {
	uint8_t reserved;
	uint8_t df;
	uint8_t mf;
	uint16_t offset;
};

static __always_inline struct ip_flags extract_flags(uint16_t frag_off)
{
	frag_off = bpf_htons(frag_off);
	// The flags are in the first 3 bits (bits 15-13)
	// No need for htons() in the mask since we're extracting from an already network-ordered value
	uint16_t flags = (frag_off & 0xE000);

	// Right shift to get individual flags
	// Note: frag_off is already in network byte order, so we shift from the correct position
	uint8_t reserved = (flags >> 15) & 0x1; // Bit 15 (leftmost)
	uint8_t df = (flags >> 14) & 0x1; // Bit 14
	uint8_t mf = (flags >> 13) & 0x1; // Bit 13
	uint16_t offset = (flags >> 3) & 0x1FFF;
	return (struct ip_flags){ reserved, df, mf, offset };
}

SEC("tc")
int tcdump(struct __sk_buff *ctx) {
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;


	struct hdr header = try_parse_udp(data, data_end);
	if (header.ip == NULL) {
		return TC_ACT_OK;
	}

	bool is_udp_following = false;
	bool is_udp_head = false;

	const u16 id = bpf_ntohs(header.ip->id);

	if (bpf_map_lookup_elem(&dest_map, &id) != NULL) {
		is_udp_following = true;
		bpf_printk("found map %d!!!!!!!!", id);
	}

	if (header.udp != NULL && header.udp->dest == bpf_htons(redirect_port)) {
		is_udp_head = true;
		struct ip_flags flags = extract_flags(header.ip->frag_off);
		if (flags.mf == 1) {
			int ret = bpf_map_update_elem(&dest_map, &id, &id, BPF_ANY);
			bpf_printk("update map  %d %d %d", id, ret, bpf_ntohs(header.udp->len));
		}
	}

	if (!is_udp_following && !is_udp_head) {
		return TC_ACT_OK;
	}



	int ret;
	for (int i=0;i<SERVER_COUNT;i++){
		if (is_udp_head) {
			uint16_t new_port = bpf_htons(server_ports[i]);
			ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, dest), &new_port,
				sizeof(new_port), 0);
			bpf_printk("replace port %d", ret);
			u16 zero16 = 0;
			int ret = bpf_skb_store_bytes(
				ctx, ETH_SIZE + IP_SIZE + offsetof(struct udphdr, check), &zero16,
				sizeof(16), 0);
		}

		uint32_t new_daddr = bpf_htonl(server_ips[i]);
		ret	= bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, daddr), &new_daddr,
				sizeof(u32), 0);
		bpf_printk("replace ip %d", ret);

		Elf32_Half check = 0;
		bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
			sizeof(u16), 0);
		header = try_parse_udp((void*) ctx->data ,(void*) ctx->data_end);
		if (header.udp != NULL)
			check = compute_ip_checksum(header.ip, (void*) ctx->data_end);
		bpf_skb_store_bytes(ctx, ETH_SIZE + offsetof(struct iphdr, check), &check,
			sizeof(u16), 0);

		ret = bpf_skb_store_bytes(ctx, 0, server_macs[i], 6, 0);
		bpf_printk("replace mac %d", ret);

		ret = bpf_clone_redirect(ctx, ctx->ifindex, 0);
		bpf_printk("clone redirect %d", ret);
	}

	return TC_ACT_SHOT;
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
	if(ip->protocol != IP_P_UDP){
		return (struct hdr) {NULL,NULL, NULL};
	}
	
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