#ifndef _MCE_FDIR_FLOW_H_
#define _MCE_FDIR_FLOW_H_

#include "mce_flow.h"

#define MCE_NODE_MAX_ENTRY	 (4)
#define MCE_SIGN_NODE_MAX_ENTRY	 (4)
#define MCE_EXACT_NODE_MAX_ENTRY (2)

struct mce_fdir_rule {
	enum mce_rule_engine_module e_module;
	void *engine_rule;
	uint16_t tun_type;
	uint16_t profile_id;
};

#pragma pack(push)
#pragma pack(1)
struct mce_inset_key {
	uint64_t inset_key0;
	uint64_t inset_key1;
};

struct mce_inset_key_extend {
	uint32_t dword_key[6];
};

struct mce_hw_inset_key {
	struct mce_inset_key inset;
	struct mce_inset_key_extend inset_ex;
	uint32_t dscp_vtag;
	uint16_t tun_type;
};

union mce_hash_data {
	struct {
		uint32_t hash_inset[10];
		uint16_t rev;
	};
	uint16_t word_stream[21];
};

union mce_ext_seg {
	struct {
		uint16_t first_seg : 15;
		uint16_t pad : 1;

		uint16_t data_1[21];
		uint16_t end_seg;
		/* 366 bit */
	};
	uint16_t word_stream[23];
};

struct mce_hash_key {
	uint32_t key[11];
};

/* Flow Director ATR input struct. */
union mce_exact_atr_input {
	struct {
		uint16_t next_fd_ptr : 13;
		uint16_t end : 1;
		uint16_t resv1 : 2;
		/* 16 bit */
		union {
			struct {
				uint32_t action;
				uint16_t priority : 3;
				uint16_t resv2 : 1;
				uint16_t e_vld : 1;
				uint16_t profile_id : 6;
				uint16_t resv3 : 5;
				uint8_t port : 7;
				uint8_t resv4 : 1;
				/* 56 bit */
				struct mce_inset_key inset;
				/* 184 bit */
			};
		} entry[MCE_EXACT_NODE_MAX_ENTRY];
		/* 384 bit */
	} v4;
	struct {
		uint64_t next_fd_ptr : 13;
		uint64_t end : 1;
		uint64_t action : 32;
		uint64_t priority : 3;
		uint64_t resv1 : 1;
		uint64_t e_vld : 1;
		uint64_t profile_id : 6;
		uint64_t port : 7;
		/* 64 bit */
		struct mce_inset_key inset;
		/* 192 bit */
		struct mce_inset_key_extend inset_ex;
		/* 384 bit */
	} v6;
	uint32_t dword_stream[12];
};

union mce_sign_atr_input {
	struct {
		uint16_t next_fd_ptr : 13;
		uint16_t end : 1;
		uint16_t resv1 : 2;
		/* 16 bit */
		struct {
			uint32_t actions;
			/* 32 bit */
			uint32_t priority : 3;
			uint32_t resv2 : 1;
			uint32_t resv3 : 4;
			uint32_t e_vld : 1;
			uint32_t profile_id : 6;
			uint32_t port : 7;
			uint32_t resv4 : 2;
			uint32_t sign_p1 : 8;
			/* 64 bit */
			uint8_t sign[3];
			/* 88 bit */
		} entry[MCE_SIGN_NODE_MAX_ENTRY];
		/* 192 bit */
	};
	uint32_t dword_stream[12];
};

#pragma pack(pop)

enum mce_fdir_hash_mode {
	MCE_MODE_HASH_INSET,
	MCE_MODE_HASH_EX_PORT,
};

struct mce_node_key {
	union {
		/* exact_key */
		struct mce_hw_inset_key hw_inset;
		/* sign_key */
		uint32_t sign_hash;
	};
	bool used;
};

struct mce_node_info {
	struct mce_node_key key[MCE_NODE_MAX_ENTRY];

	uint8_t bit_used;
};

enum mce_fdir_mode_type {
	MCE_FDIR_EXACT_M_MODE,
	MCE_FDIR_SIGN_M_MODE,
	MCE_FDIR_MACVLAN_MODE,
};

struct mce_fdir_node {
	TAILQ_ENTRY(mce_fdir_node) entry;
	enum mce_fdir_mode_type type;

	union mce_exact_atr_input exact_meta;
	union mce_sign_atr_input sign_meta;
	struct mce_node_info node_info;

	bool is_ipv6;
	uint16_t loc;
};

/* Flow Director ATR input struct. */
union mce_fdir_pattern {
	struct {
		union {
			struct {
				uint8_t src_mac[RTE_ETHER_ADDR_LEN];
				uint8_t dst_mac[RTE_ETHER_ADDR_LEN];
				uint16_t vlan_id;
			};
			struct {
				uint16_t ether_type;
				uint32_t dst_addr[4];
				uint32_t src_addr[4];
				uint8_t ip_tos;
				uint8_t protocol;
				uint16_t l4_sport;
				uint16_t l4_dport;
				union {
					uint32_t vni;
					uint32_t key;
					uint32_t esp_spi;
					uint32_t teid;
					uint32_t vtag; /* sctp vtag */
				};
				uint16_t tun_type;
			};
		};
	} formatted;
};

struct mce_hw_rule_inset {
	struct mce_hw_inset_key keys;

	uint32_t action;
	uint8_t profile_id;
	uint8_t port;
	uint8_t priority;
};

struct mce_rule_date {
	uint32_t dword_stream[12];
};

struct mce_fdir_filter {
	struct mce_rule_date data;
	struct mce_hw_rule_inset hw_inset;
	union mce_fdir_pattern lkup_pattern;
	bool is_ipv6;

	struct mce_flow_action actions;
	uint32_t fdirhash; /* hash value for fdir */
	uint32_t signhash;
	bool hash_child;
	bool clear_node;
	uint16_t profile_id;
	struct mce_lkup_meta *meta;
	struct mce_field_bitmask_info *mask_info;
	uint64_t options;
	uint16_t meta_num;
	uint16_t loc;
	int rule_engine;
};

TAILQ_HEAD(mce_fdir_node_entry, mce_fdir_node);

struct mce_fdir_hash_entry {
	TAILQ_ENTRY(mce_fdir_hash_entry) entry;
	uint32_t fdir_hash;
	uint16_t nb_child;
	bool is_ipv6;

	struct mce_fdir_node_entry node_entrys;
};

struct mce_fdir_field_mask {
	uint16_t key_off;
	uint16_t mask;
	uint16_t loc;

	bool used;
	uint64_t ref_count;
};

/* list of fdir filters */
TAILQ_HEAD(mce_fdir_node_list, mce_fdir_hash_entry);

struct mce_fdir_handle {
	enum mce_fdir_mode_type mode;
	enum mce_fdir_hash_mode hash_mode;
	struct mce_fdir_node_list hash_entry0_list; /* sync to hw list */
	struct mce_fdir_node_list hash_entry1_list; /* sync to hw list */
	struct mce_fdir_filter **hash_map;
	struct mce_fdir_filter **ex_hash_map;
	struct rte_hash *hash_handle; /* cuckoo hash handler */
	struct rte_hash *ex_hash_handle;
	struct mce_fdir_hash_entry **fdir_entry_map;
	struct mce_tx_queue *txq;

	struct mce_fdir_field_mask field_mask[32];
	struct mce_lkup_meta meta_db[2][MCE_META_TYPE_MAX];
	struct mce_hw_profile *profiles[64];
	uint16_t ipv6_max_hash_entry;
	uint16_t ipv4_max_hash_entry;
	uint16_t ipv4_hash_entry_num;
	uint16_t ipv6_hash_entry_num;
	uint32_t entry_bitmap[128];
	bool fdir_flush_en;
};
#endif
