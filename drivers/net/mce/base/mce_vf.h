#ifndef _MCE_VF_H_
#define _MCE_VF_H_

#include "mce_hw.h"
#include "mce_mbx.h"

s32 mce_init_ops_vf(struct mce_hw *hw);

void mcevf_mbx_pf2vf_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req);

void mcevf_mbx_pf2vf_event_req_isr(struct mce_mbx_info *mbx, int event_id);
struct mce_vf_ntuple_rule;
int mce_request_set_vf_ntuple(struct mce_vport *vport, struct mce_vf_ntuple_rule *rule);

#endif /* _MCE_VF_H_ */
