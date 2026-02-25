/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020-2024 Mucse Corporation
 */
#ifndef _MCE_MBX_H_
#define _MCE_MBX_H_

#include "mce_osdep.h"
#include "../mce.h"

/**
 * @brief PF<->VF mailbox field indices
 *
 * Identifiers for fields carried in mailbox reset/data responses between PF
 * and VF.
 */
/* PF<->VF mailbox  fields */
enum F_VF_RESET_DATA_RESP {
	F_VF_MAC_ADDR = 0,
	F_VF_RESET_RING_MAX_CNT = 2,
	F_VF_RESET_FW_VERSION,
	F_VF_RESET_VLAN,
	F_VF_RESET_LINK_ST,
	F_VF_RESET_AXI_MHZ,
	F_VF_NR_PF,
	F_VF_RXFCS_STATE,
	F_VF_SPOOF_STATE,
	F_VF_TRUST_STATE,
	F_VF_ISOLATE_ADDR,
	F_VF_RESET_RESP_CNT
};
#define MCE_PF_LINK_UP BIT(31)

/**
 * @brief VF -> PF mailbox request command opcodes
 */
enum VF2PF_MBX_REQ_CMD {
	MCE_VF_RESET = 1,
	MCE_VF_REMOVED,
	MCE_VF_SET_VLAN,
	MCE_VF_SET_VLAN_STRIP,
	MCE_VF_SET_MAC_ADDR,
	MCE_VF_SET_PROMISC_MODE,
	MCE_VF_SET_MACVLAN_ADDR,
	MCE_VF_DEL_MACVLAN_ADDR,
	MCE_VF_NOTIFY_RING_CNT,
	MCE_VF_SET_NTUPLE,
};

/**
 * @brief PF -> VF mailbox request opcodes
 */
enum PF2VF_MBX_REQ {
	MCE_PF2VF_SET_VLAN = 1,
};

/**
 * @brief Encoded mailbox request/response command header
 *
 * Low-level bit-field representation used in mailbox request/response
 * structures. Fields describe opcode, error code and flags.
 */
union req_cmd {
	unsigned int v;
	struct {
		unsigned short opcode;

		unsigned char err_code : 6;
		/* Error code */
		/* Return immediately without waiting for command completion */
		unsigned char flag_no_wait : 1;
		/* Do not expect a response for this request */
		unsigned char flag_no_resp : 1;
		/* Number of arguments in request or values in response */
		unsigned char arg_cnts : 4;
		/* Flags indicating request direction/peer encoding */
		unsigned char flag_pf2peer_req : 1; /* PF -> CM3/VF request */
		unsigned char flag_peer2pf_req : 1; /* VF/CM3 -> PF request */
		unsigned char flag_vf2cm3_req : 1;  /* VF -> CM3 request */
		unsigned char flag_cm32vf_req : 1;  /* CM3 -> VF request */
	};
} __attribute__((aligned(4), packed));

/**
 * @brief Mailbox request message container
 *
 * Fixed-size (64 byte) mailbox request sent from one endpoint to another.
 */
struct mbx_req {
	union req_cmd cmd;
	unsigned int data[(64 - sizeof(union req_cmd)) / 4];
} __attribute__((aligned(4), packed));

/**
 * @brief Mailbox response message container
 *
 * Fixed-size (64 byte) mailbox response returned by recipients.
 */
struct mbx_resp {
	union req_cmd cmd;
	unsigned int data[(64 - sizeof(union req_cmd)) / 4];
} __attribute__((aligned(4), packed));

/**
 * @brief Mailbox error codes
 */
enum MBX_ERR_CODE {
	MBX_EOK = 0, /* There is no error */
	MBX_EPERM = 1, /* Operation not permitted */
	MBX_ENOENT = 2, /* No entry */
	MBX_EFULL = 3, /* The resource is full */
	MBX_EEMPTY = 4, /* The resource is empty */
	MBX_EIO = 5, /* IO error */
	MBX_ENOMEM = 12, /* No memory */
	MBX_EFAULT = 14, /* Bad address */
	MBX_EBUSY = 16, /* Busy */
	MBX_EINVAL = 22, /* Invalid argument */
	MBX_ENOSPC = 28, /* No space left */
	MBX_ERROR = 40, /* A generic/unknown error happens */
	MBX_ENOSUPPORTED = 41, /* not implemented */
	MBX_ENOSYS = 42, /* Function not implemented */
	MBX_ETIMEOUT = 43, /* Timed out */
	MBX_EINTERNAL = 44, /* internal erro */
	MBX_ENOBUFS = 45, /* No buffer space is available */
	MBX_EVERIFY = 46, /* verify faild */
	MBX_ERANGE = 47, /* range invalid */
	MBX_ENODEV = 48 /* invalid arg, not find device */
};

/**
 * @brief Mailbox endpoint identifiers
 */
enum MBX_ID {
	MBX_VF0 = 0,
	MBX_VF1,
	MBX_VF2,
	MBX_VF3,
	MBX_VF4,
	/* vf5 ... vf126*/
	MBX_VF127 = 126,
	MAX_VF_CNT = MBX_VF127,
	MBX_FW,
	MBX_CNT
};

/**
 * @brief Mailbox request status values
 */
enum MBX_REQ_STAT {
	HAS_ERR = 0,
	REQ_WITH_DATA = 1,
	EVENT_REQ = 2,
	RESP_OR_ACK = 3,
};

/**
 * @brief PF-to-VF event identifiers
 */
enum PF2VF_EVENT_ID {
	EVT_PF_LINK_CHANGED = 1,
	EVT_PF_RESET_VF = 2,
	EVT_PF_DRV_REMOVE = 3,
	EVT_PF_FORCE_VF_LINK_UP = 4,
	EVT_PF_FORCE_VF_LINK_DOWN = 5,
	EVT_PF_FORECE_VF_OPEN = 6,
	EVT_PF_FORECE_VF_CLOESE = 7,
	EVT_PF_FORECE_FCS_ON = 8,
	EVT_PF_FORECE_FCS_OFF = 9,
	EVT_PF_FORECE_SPOOF_ON = 10,
	EVT_PF_FORECE_SPOOF_OFF = 11,
	EVT_PF_TRUST_ON = 12,
	EVT_PF_TRUST_OFF = 13,
};

/**
 * @brief VF-to-PF event identifiers
 */
enum VF2PF_EVENT_ID {
	EVT_VF_MBX_INIT_DONE = 1,
	VF_DRV_REMOVR = 2,
};

/**
 * @brief Firmware-to-PF event identifiers
 */
enum FW2PF_EVENT_ID {
	EVT_PORT_LINK_UP = 1,
	EVT_SFP_PLUGIN_IN = 2,
	EVT_PTP = 3,
	EVT_PORT_LINK_DOWN = 4,
	EVT_SFP_PLUGIN_OUT = 5,
	EVT_SFP_SPEED_CHANGED = 6,
};

/**
 * @brief PF-to-Firmware event identifiers
 */
enum PF2FW_EVENT_ID {
	EVT_NIC_RESET = 1,
	EVT_DRV_REMOVE = 4,
	EVT_REG_OP = 5,
};

/**
 * @brief Firmware mailbox status selectors
 */
enum MBX_FW_STAT {
	FW_LINK_STAT,
	FW_NIC_RESET_DONE_STAT,
	FW_NR_PF,
};

/**
 * @brief VF mailbox status selectors
 */
enum MBX_VF_STAT {
	VF_RESET_DONE,
	VF_MBX_IRQ_INIT_DONE,
};

/**
 * @brief PF mailbox status selectors
 */
enum MBX_PF_STAT {
	PF_NR_PF,
	PF_SPEED,
	PF_LINKUP,
};

/* init */
/**
 * @brief Reset mailbox internal state for a hardware instance
 * @param hw Pointer to device hardware context
 */
void mce_mbx_reset(struct mce_hw *hw);

/**
 * @brief Initialize mailbox info structure configuration
 * @param mbx Pointer to mailbox info to initialize
 * @return 0 on success, negative on error
 */
int mce_mbx_init_configure(struct mce_mbx_info *mbx);

/**
 * @brief Clear peer request IRQ for a mailbox and set status
 * @param mbx Pointer to mailbox info
 * @param stat Request status to clear
 */
void mce_mbx_clear_peer_req_irq_with_stat(struct mce_mbx_info *mbx,
					  enum MBX_REQ_STAT stat);

/**
 * @brief Setup mailbox info for PF-to-FW communication
 * @param hw Hardware context
 * @param mbx Mailbox info to populate
 * @return 0 on success, negative on error
 */
int mce_setup_pf2fw_mbx_info(struct mce_hw *hw, struct mce_mbx_info *mbx);

/**
 * @brief Setup mailbox info for PF internal use
 * @param hw Hardware context
 * @param mbx Mailbox info to populate
 * @return 0 on success, negative on error
 */
int mce_setup_pf_mbx_info(struct mce_hw *hw, struct mce_mbx_info *mbx);

/**
 * @brief Setup PF-to-VF mailbox information
 * @param hw Hardware context
 * @param nr_vf Number of VFs
 * @param mbx Mailbox info to populate
 * @return 0 on success, negative on error
 */
int mce_setup_pf2vf_mbx_info(struct mce_hw *hw, int nr_vf,
				 struct mce_mbx_info *mbx);

/**
 * @brief Setup VF-to-PF mailbox information
 * @param hw Hardware context
 * @param mbx Mailbox info to populate
 * @return 0 on success, negative on error
 */
int mce_setup_vf2pf_mbx_info(struct mce_hw *hw, struct mce_mbx_info *mbx);

/**
 * @brief Enable or disable mailbox vectors
 * @param mbx Mailbox info
 * @param nr_vector Number of vectors
 * @param enable true to enable, false to disable
 * @return 0 on success
 */
int mce_mbx_vector_set(struct mce_mbx_info *mbx, int nr_vector, bool enable);

/**
 * @brief Set mailbox vector state for all VF->PF mailboxes
 * @param hw Hardware context
 * @param nr_vector Number of vectors
 * @param enable true to enable, false to disable
 * @return 0 on success
 */
int mce_pf_set_all_vf2pf_mbx_vector(struct mce_hw *hw, int nr_vector,
					bool enable);

/* irq */
/**
 * @brief Mailbox event callback invoked for event-only requests.
 *
 * @param mbx Pointer to mailbox info for the endpoint
 * @param event_id Event identifier (one of PF2VF_EVENT_ID, etc.)
 */
typedef void(mbx_event_req_cb)(struct mce_mbx_info *mbx, int event_id);

/**
 * @brief Mailbox request callback invoked for requests carrying data.
 *
 * @param mbx Pointer to mailbox info for the endpoint
 * @param req Pointer to the received mailbox request structure
 */
typedef void(mbx_req_with_data_cb)(struct mce_mbx_info *mbx,
				   struct mbx_req *req);
/**
 * @brief Clean and process all pending incoming mailbox requests.
 *
 * Walks pending mailbox requests and dispatches them via the provided
 * callbacks.
 *
 * @param hw Pointer to device hardware context
 * @param event_cb Callback for event-only requests
 * @param req_cb Callback for requests with data
 * @return 0 on success, negative on error
 */
int mce_mbx_clean_all_incomming_req(struct mce_hw *hw,
					mbx_event_req_cb *event_cb,
					mbx_req_with_data_cb *req_cb);

/* req */
/**
 * @brief Send a mailbox request and optionally wait for a response.
 *
 * @param mbx Mailbox endpoint info to use for sending
 * @param opcode Request opcode
 * @param data Pointer to request payload (word array), or NULL
 * @param data_bytes Size in bytes of the payload
 * @param resp Pointer to response buffer to fill, or NULL if none
 * @param timeout_us Timeout in microseconds to wait for response
 * @return 0 on success, negative errno on failure or timeout
 */
int mce_mbx_send_req(struct mce_mbx_info *mbx, int opcode, unsigned int *data,
			 int data_bytes, struct mbx_resp *resp, int timeout_us);

/**
 * @brief Send a mailbox response from ISR context.
 *
 * Used to reply to a request from an interrupt handler.
 *
 * @param mbx Mailbox info for the endpoint
 * @param resp Pointer to response to send
 * @return 0 on success, negative errno on failure
 */
int mce_mbx_send_resp_isr(struct mce_mbx_info *mbx, struct mbx_resp *resp);

/**
 * @brief Send an event notification via mailbox.
 *
 * @param mbx Mailbox info for the endpoint
 * @param event_id Event identifier to send
 * @param timeout_us Timeout in microseconds to wait for ack (if any)
 * @return 0 on success, negative errno on failure
 */
int mce_mbx_send_event(struct mce_mbx_info *mbx, int event_id, int timeout_us);

/* status */
/**
 * @brief Update PF status registers from mailbox state.
 *
 * @param hw Pointer to device hardware context
 * @return 0 on success, negative errno on failure
 */
int mce_mbx_set_pf_stat_reg(struct mce_hw *hw);

/**
 * @brief Update VF->PF status mapping (internal helper).
 *
 * @param hw Pointer to device hardware context
 */
void mcevf_mbx_set_vf2pf_stat(struct mce_hw *hw);

/**
 * @brief Poll and update firmware mailbox status into hw state.
 *
 * @param hw Pointer to device hardware context
 */
void mce_update_fw_stat(struct mce_hw *hw);

/**
 * @brief Retrieve a PF mailbox status value.
 *
 * @param pf_mbx Pointer to PF mailbox info
 * @param stat Selector for PF status
 * @return Status value or negative error
 */
int mcevf_mbx_get_pf_stat(struct mce_mbx_info *pf_mbx, enum MBX_PF_STAT stat);

/**
 * @brief Set VF status bits in the PF mailbox structure.
 *
 * @param vf2pf_mbx Pointer to VF->PF mailbox info
 */
void mcevf_mbx_set_vf_stat(struct mce_mbx_info *vf2pf_mbx);

/**
 * @brief Report link state change to relevant subsystems.
 *
 * @param hw Pointer to device hardware context
 */
void mce_report_link(struct mce_hw *hw);

/**
 * @brief Clear VF reset-done status in PF->VF mailbox.
 *
 * @param pf2vf_mbx Pointer to PF->VF mailbox info
 */
void mce_mbx_clear_vf_reset_done_stat(struct mce_mbx_info *pf2vf_mbx);

/**
 * @brief Clear reset-done flag used by VF in hardware state.
 *
 * @param hw Pointer to device hardware context
 */
void mcevf_mbx_clear_reset_done_flag(struct mce_hw *hw);

/**
 * @brief Clear firmware NIC reset-done flag in PF->FW mailbox.
 *
 * @param pf2fw_mbx Pointer to PF->FW mailbox info
 */
void mce_mbx_clear_fw_nic_reset_done_flag(struct mce_mbx_info *pf2fw_mbx);

/**
 * @brief Query firmware mailbox for a FW status selector.
 *
 * @param pf2fw_mbx Pointer to PF->FW mailbox info
 * @param stat Selector for firmware status
 * @return Status value or negative error
 */
int mce_pf_mbx_get_fw_stat(struct mce_mbx_info *pf2fw_mbx,
			   enum MBX_FW_STAT stat);

/**
 * @brief Query VF-related status from PF->VF mailbox.
 *
 * @param pf2vf_mbx Pointer to PF->VF mailbox info
 * @param stat Selector for VF status
 * @return Status value or negative error
 */
int mce_mbx_get_vf_stat(struct mce_mbx_info *pf2vf_mbx, enum MBX_VF_STAT stat);

/**
 * @brief Update PF statistics derived from mailbox values.
 *
 * @param hw Pointer to device hardware context
 * @return 0 on success, negative errno on failure
 */
int mcevf_update_pf_stat(struct mce_hw *hw);

/**
 * @brief Notify firmware that driver is uninstalling.
 *
 * @param hw Pointer to device hardware context
 */
void mce_mbx_drv_send_uninstall_notify_fw(struct mce_hw *hw);

/**
 * @brief Enable or disable SFP plug/unplug notifications to firmware.
 *
 * @param hw Pointer to device hardware context
 * @param enable Non-zero to enable, zero to disable
 */
void mce_mbx_sfp_plug_notify_en(struct mce_hw *hw, int enable);

/**
 * @brief Enable or disable link state change notifications to firmware.
 *
 * @param hw Pointer to device hardware context
 * @param enable Non-zero to enable, zero to disable
 */
void mce_mbx_link_state_change_notify_en(struct mce_hw *hw, int enable);

/**
 * @brief Mark VF mailbox initialization complete or clear it.
 *
 * @param hw Pointer to device hardware context
 * @param en True to set init-done, false to clear
 * @return 0 on success, negative errno on failure
 */
int mcevf_set_mbx_init_done(struct mce_hw *hw, bool en);
#endif /*_MCE_MBX_H_*/
