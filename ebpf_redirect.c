#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "lib_net_def.h"
#include "bpf_compiler.h"

#define MAX_MAP_ENTRIES 0x8000

struct mac_key {
    u8 h_dest[6];
};

struct bpf_map_def mac_map SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct mac_key),
    .value_size = sizeof(u16),
    .map_flags = BPF_F_NO_PREALLOC,
    .max_entries = MAX_MAP_ENTRIES,
};

SEC("redirect")
int redirect_base_dst_mac(struct __sk_buff *skb) {
	void *data_end = (void *)(u64)skb->data_end;
	void *data     = (void *)(u64)skb->data;

	// Only IPv4 supported for this example
	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
		return TC_ACT_SHOT;
	}

    u16 *ifindex = bpf_map_lookup_elem(&mac_map, ether->h_dest);
    if (ifindex) {
        return TC_ACT_OK;
    }

    // 21: trunk ifindex
    // 22: tap ifindex
    // 185: eth ifindex
    // return bpf_clone_redirect(skb, 22, BPF_F_INGRESS);
    if (ether->h_dest[0] == 238 || ether->h_dest[0] == 255) { // ee: or ff:
        return bpf_redirect(185, 0);
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
