#ifndef _MCE_VP_REG_H_
#define _MCE_VP_REG_H_
enum mce_vp_cmd {
	MCE_VP_ATTR,
	MCE_VP_ETQF,
	MCE_VP_ETQS,
	MCE_VP_MULTICAST_LO_F,
	MCE_VP_MULTICAST_HI_F,
	MCE_VP_VLAN_F,
	MCE_VP_SYNQF_F,
	MCE_VP_SYNQF_PRI,
	MCE_VP_TUPLE_ACL_F,
	MCE_VP_RSS,
	MCE_VP_RSS_RETA,
	MCE_VP_RSS_ACT,
	MCE_VP_REG_MAX,
};
struct mce_vport;
void mce_vport_reg_setup(struct mce_vport *vport);
#endif /* _MCE_VP_REG_H_ */
