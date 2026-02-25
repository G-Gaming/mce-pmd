#include "mce_vp_reg.h"
#include "mce_hw.h"
#include "../mce.h"

struct mce_reg_offset {
	uint16_t loc;
	uint32_t sriov_base;
	uint32_t vport_base;
	uint32_t vport_with;
};
static const struct mce_reg_offset mce_common_reg[] = {
	{ MCE_VP_ATTR, 0x20000, 0xa0000, BIT_TO_BYTES(32) },
	{ MCE_VP_ETQF, 0x21000, 0xb0000, BIT_TO_BYTES(512) },
	{ MCE_VP_ETQS, 0x22000, 0xb2000, BIT_TO_BYTES(512) },
	{ MCE_VP_MULTICAST_HI_F, 0x23000, 0xb4000, BIT_TO_BYTES(512) },
	{ MCE_VP_MULTICAST_LO_F, 0x24000, 0xb6000, BIT_TO_BYTES(512) },
	{ MCE_VP_VLAN_F, 0x25000, 0xb8000, BIT_TO_BYTES(256) },
	{ MCE_VP_SYNQF_PRI, 0x26000, 0xc0000, BIT_TO_BYTES(32) },
	{ MCE_VP_SYNQF_F, 0x27000, 0xc0200, BIT_TO_BYTES(32) },
	{ MCE_VP_TUPLE_ACL_F, 0, 0, 0 },
	{ MCE_VP_RSS, 0x29000, 0xe0000, BIT_TO_BYTES(512) },\
	{ MCE_VP_RSS_RETA, 0x2a000, 0xe6000, 0 },
	{ MCE_VP_RSS_ACT, 0x2b000, 0xe4000, 0 },
};

void mce_vport_reg_setup(struct mce_vport *vport)
{
	uint16_t vport_id = vport->attr.vport_id;
	const struct mce_reg_offset *ptr;
	struct mce_hw *hw = vport->hw;
	bool is_vf = vport->is_vf;
	bool is_isolat = 0;
	uint32_t base = 0;
	int i = 0;

	if (hw->vf_bar_isolate_on)
		is_isolat = is_vf | (!is_vf && hw->max_vfs);
	for (i = 0; i < MCE_VP_REG_MAX; i++) {
		ptr = &mce_common_reg[i];
		if (is_vf && is_isolat)
			base = ptr->sriov_base;
		else if ((hw->max_vfs || is_vf) && !is_isolat)
			base = ptr->vport_base + ptr->vport_with * vport_id;
		else if (!hw->max_vfs && !is_vf)
			base = ptr->vport_base;
		else if (hw->max_vfs && !is_vf)
			base = ptr->vport_base + ptr->vport_with * vport_id;
		else
			printf("this is a bug\n");
		hw->vp_reg_base[i] = base;
	}
}
