/*
 * Copyright (C) 2018-2019, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _NVME_PT_IOCTL_H
#define _NVME_PT_IOCTL_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/types.h>
#include <linux/nvme_ioctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libsed.h>

#include "sed_util.h"

#define GENERIC_HOST_SESSION_NUM 0x41

/*
 * TSM SHALL NOT assign any TSN in the range 0 to 4095 to a regular session.
 * These TSNs are reserved by TCG for special sessions
 */
#define RSVD_TPER_SESSION_NUM    (4096)

#define OPAL_SUCCESS (0)

#define MAX_FEATURES 64

#define DTAERROR_NO_METHOD_STATUS 0x89

#define TPER_SYNC_SUPPORTED 0x01
#define MBR_ENABLED_MASK 0x10

/* Derived from TCG Core spec 2.01 Section:
 * 3.2.2.1
 * Data Type
 */
#define TINY_ATOM_BYTE   0x7F
#define SHORT_ATOM_BYTE  0xBF
#define MEDIUM_ATOM_BYTE 0xDF
#define LONG_ATOM_BYTE   0xE3

/*
 * User IDs used in the TCG storage SSCs
 * Derived from: TCG_Storage_Architecture_Core_Spec_v2.01_r1.00
 * Section: 6.3 Assigned UIDs
 */
#define OPAL_UID_LENGTH 8
#define OPAL_METHOD_LENGTH 8
#define OPAL_MSID_KEYLEN 15
#define OPAL_UID_LENGTH_HALF 4

#define OPAL_INVALID_PARAM 12

#define OPAL_ISSUED                       0x00
#define OPAL_ISSUED_DISABLED              0x01
#define OPAL_ISSUED_FROZEN                0x02
#define OPAL_ISSUED_DISABLED_FROZEN       0x03
#define OPAL_ISSUED_FAILED                0x04
#define OPAL_RESERVED_05                  0x05
#define OPAL_RESERVED_06                  0x06
#define OPAL_RESERVED_07                  0x07
#define OPAL_MANUFACTURED_INACTIVE        0x08
#define OPAL_MANUFACTURED                 0x09
#define OPAL_MANUFACTURED_DISABLED        0x0A
#define OPAL_MANUFACTURED_FROZEN          0x0B
#define OPAL_MANUFACTURED_DISABLED_FROZEN 0x0C
#define OPAL_MANUFACTURED_FAILED          0x0D
#define OPAL_RESERVED_0E                  0x0E
#define OPAL_RESERVED_0F                  0x0F

#define LOCKING_RANGE_NON_GLOBAL 0x03

#define FC_TPER       0x0001
#define FC_LOCKING    0x0002
#define FC_GEOMETRY   0x0003
#define FC_ENTERPRISE 0x0100
#define FC_DATASTORE  0x0202
#define FC_SINGLEUSER 0x0201
#define FC_OPALV100   0x0200
#define FC_OPALV200   0x0203

#define KEEP_GLOBAL_RANGE_KEY (0x060000)

enum {
    TCG_SECP_00 = 0,
    TCG_SECP_01,
    TCG_SECP_02,
};

enum opaluid {
    /* users uid */
    OPAL_SM_UID,
    OPAL_THIS_SP_UID,
    OPAL_ADMIN_SP_UID,
    OPAL_LOCKING_SP_UID,
    OPAL_ENTERPRISE_LOCKING_SP_UID,

    /* authority */
    OPAL_ANYBODY_UID,
    OPAL_ADMINS_UID,
    OPAL_MAKERS_UID,
    OPAL_MAKERSYMK_UID,
    OPAL_MAKERPUK_UID,
    OPAL_SID_UID,
    OPAL_PSID_UID,
    OPAL_TPERSIGN_UID,
    OPAL_TPEREXCH_UID,
    OPAL_ADMINEXCH_UID,
    OPAL_ISSUERS_UID,
    OPAL_ADMIN1_ADMIN_SP_UID = OPAL_ISSUERS_UID,
    OPAL_EDITORS_UID,
    OPAL_DELETERS_UID,
    OPAL_SERVERS_UID,
    OPAL_RESERVE0_UID,
    OPAL_RESERVE1_UID,
    OPAL_RESERVE2_UID,
    OPAL_RESERVE3_UID,
    OPAL_ADMIN_UID,
    OPAL_ADMIN1_UID,
    OPAL_ADMIN2_UID,
    OPAL_ADMIN3_UID,
    OPAL_ADMIN4_UID,
    OPAL_USERS_UID,
    OPAL_USER_UID,
    OPAL_USER1_UID,
    OPAL_USER2_UID,
    OPAL_USER3_UID,
    OPAL_USER4_UID,
    OPAL_USER5_UID,
    OPAL_USER6_UID,
    OPAL_USER7_UID,
    OPAL_USER8_UID,
    OPAL_USER9_UID,
    OPAL_ENTERPRISE_BANDMASTER0_UID,
    OPAL_ENTERPRISE_ERASEMASTER_UID,

    /* tables uid */
    OPAL_TABLE_TABLE_UID,
    OPAL_LOCKING_TABLE_UID,
    OPAL_LOCKINGRANGE_GLOBAL_UID,
    OPAL_LOCKINGRANGE_ACE_RDLOCKED_UID,
    OPAL_LOCKINGRANGE_ACE_WRLOCKED_UID,
    OPAL_MBRCONTROL_UID,
    OPAL_MBR_UID,
    OPAL_AUTHORITY_TABLE_UID,
    OPAL_C_PIN_TABLE_UID,
    OPAL_LOCKING_INFO_TABLE_UID,
    OPAL_ENTERPRISE_LOCKING_INFO_TABLE_UID,
    OPAL_DATASTORE_UID,
    OPAL_ACCESS_CONTROL_UID,

    /* c_pin_table objects UID's */
    OPAL_C_PIN_MSID_UID,
    OPAL_C_PIN_SID_UID,
    OPAL_C_PIN_ADMIN_SP_ADMIN1_UID,
    OPAL_C_PIN_LOCKING_SP_ADMIN1_UID,
    OPAL_C_PIN_USER1_UID,

    /* half UID's (only the first four bytes used) */
    OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID,
    OPAL_HALF_UID_BOOLEAN_ACE_UID,

    /* ACE DS UIDs */
    OPAL_ACE_DS_GET_ALL_UID,
    OPAL_ACE_DS_SET_ALL_UID,

    /* optional parameter UID */
    OPAL_UID_HEXFF_UID,
};

enum opalmethod {
    OPAL_PROPERTIES_METHOD_UID,
    OPAL_STARTSESSION_METHOD_UID,
    OPAL_REVERT_METHOD_UID,
    OPAL_ACTIVATE_METHOD_UID,
    OPAL_EGET_METHOD_UID,
    OPAL_ESET_METHOD_UID,
    OPAL_NEXT_METHOD_UID,
    OPAL_EAUTHENTICATE_METHOD_UID,
    OPAL_GETACL_METHOD_UID,
    OPAL_GENKEY_METHOD_UID,
    OPAL_REVERTSP_METHOD_UID,
    OPAL_GET_METHOD_UID,
    OPAL_SET_METHOD_UID,
    OPAL_AUTHENTICATE_METHOD_UID,
    OPAL_RANDOM_METHOD_UID,
    OPAL_ERASE_METHOD_UID,
    OPAL_REACTIVATE_METHOD_UID,
    OPAL_ASSIGN_METHOD_UID,
    OPAL_DEASSIGN_METHOD_UID,
};

enum opaltoken {
    /* Boolean */
    OPAL_TRUE = 0x01,
    OPAL_FALSE = 0x00,
    OPAL_BOOLEAN_EXPR = 0x03,
    /* cellblocks */
    OPAL_TABLE = 0x00,
    OPAL_STARTROW = 0x01,
    OPAL_ENDROW = 0x02,
    OPAL_STARTCOLUMN = 0x03,
    OPAL_ENDCOLUMN = 0x04,
    OPAL_VALUES = 0x01,
    /* opal tables */
    OPAL_TABLE_ROW = 0x07,
    /* authority table */
    OPAL_PIN = 0x03,
    /* locking tokens */
    OPAL_RANGESTART = 0x03,
    OPAL_RANGELENGTH = 0x04,
    OPAL_READLOCKENABLED = 0x05,
    OPAL_WRITELOCKENABLED = 0x06,
    OPAL_READLOCKED = 0x07,
    OPAL_WRITELOCKED = 0x08,
    OPAL_ACTIVEKEY = 0x0A,
    /* lockingsp table */
    OPAL_LIFECYCLE = 0x06,
    /* locking info table */
    OPAL_MAXRANGES = 0x04,
    /* mbr control */
    OPAL_MBRENABLE = 0x01,
    OPAL_MBRDONE = 0x02,
    /* properties */
    OPAL_HOSTPROPERTIES = 0x00,
    /* atoms */
    OPAL_STARTLIST = 0xf0,
    OPAL_ENDLIST = 0xf1,
    OPAL_STARTNAME = 0xf2,
    OPAL_ENDNAME = 0xf3,
    OPAL_CALL = 0xf8,
    OPAL_ENDOFDATA = 0xf9,
    OPAL_ENDOFSESSION = 0xfa,
    OPAL_STARTTRANSACTON = 0xfb,
    OPAL_ENDTRANSACTON = 0xfc,
    OPAL_EMPTYATOM = 0xff,
    OPAL_WHERE = 0x00,
    /* CNL NS col */
    OPAL_NS_ID = 0x14,
    OPAL_NS_GLOBAL_RANGE = 0x15,
};

struct tper_feat {
    uint8_t sync_supp : 1;
    uint8_t async_supp : 1;
    uint8_t ack_nak_supp : 1;
    uint8_t buff_mgmt_supp : 1;
    uint8_t stream_supp : 1;
    uint8_t reserved1 : 1;
    uint8_t comid_mgmt_supp : 1;
    uint8_t reserved2 : 1;
} __attribute__((__packed__));

struct locking_feat {
    uint8_t locking_supp : 1;
    uint8_t locking_en : 1;
    uint8_t locked : 1;
    uint8_t media_enc : 1;
    uint8_t mbr_en : 1;
    uint8_t mbr_done : 1;
    uint8_t reserved : 2;
} __attribute__((__packed__));

struct geometry_feat {
    struct {
        uint8_t align : 1;
        uint8_t rsvd1 : 7;
    } __attribute__((__packed__)) rsvd_align;
    uint8_t rsvd2[7];
    uint32_t logical_blk_sz;
    uint64_t alignment_granularity;
    uint64_t lowest_aligned_lba;
} __attribute__((__packed__));

struct datastore_feat {
    uint16_t max_num_datastores;
    uint32_t max_total_size_datastore_tbls;
    uint32_t datastore_size_align;
} __attribute__((__packed__));

struct block_sid_feat {
    uint8_t sid_valuestate : 1;
    uint8_t sid_blockedstate : 1;
    uint8_t reserved : 6;
    uint8_t hardware_reset :  1;
    uint8_t reserved1 : 7;
    uint8_t reserved2[10];
} __attribute__((__packed__));

struct opalv100_feat {
    uint16_t v1_base_comid;
    uint16_t v1_comid_num;
} __attribute__((__packed__));

struct opalv200_feat {
    uint16_t base_comid;
    uint16_t comid_num;
    struct {
        uint8_t range_crossing : 1;
        uint8_t rsvd1 : 7;
    } __attribute__((__packed__)) rangecross_rsvd;
    uint16_t admin_lp_auth_num;
    uint16_t user_lp_auth_num;
    uint8_t init_pin;
    uint8_t revert_pin;
    uint8_t reserved2[5];
} __attribute__((__packed__));

struct pyrite_feat {
    uint16_t base_comid;
    uint16_t comid_num;
    uint8_t reserved[5];
    uint8_t init_pin;
    uint8_t revert_pin;
    uint8_t reserved2[5];
} __attribute__((__packed__));

struct data_rm_feat {
    uint8_t data[36];
} __attribute__((__packed__));

struct siis_feat {
    uint8_t data[16];
} __attribute__((__packed__));

struct sum_feat {
    uint32_t number_of_locking_objects_supported;
    uint8_t any : 1;
    uint8_t all : 1;
    uint8_t policy : 1;
    uint8_t reserved : 5;
} __attribute__((__packed__));

struct cnl_feat {
    struct {
        uint8_t rsvd1 : 6;
        uint8_t range_p : 1;
        uint8_t range_c : 1;
    } __attribute__((__packed__)) ranges_rsvd;
    uint8_t rsvd2[3];
    uint32_t max_key_count;
    uint32_t unused_key_count;
    uint32_t max_ranges_per_ns;
} __attribute__((__packed__));

struct opal_l0_feat {
    int type;
    union {
        struct {
            struct tper_feat flags;
        } __attribute__((__packed__))tper;
        struct{
            struct locking_feat flags;
        } __attribute__((__packed__)) locking;
        struct opalv100_feat opalv100;
        struct opalv200_feat opalv200;
        struct opalv200_feat ruby;
        struct pyrite_feat pyritev100;
        struct pyrite_feat pyritev200;
    } __attribute__((__packed__)) feat;
} __attribute__((__packed__));

struct opal_l0_disc {
    uint32_t rev;
    uint16_t comid;
    struct opal_l0_feat feats[MAX_FEATURES];
} __attribute__((__packed__));

struct opal_level0_header {
    uint32_t len;
    uint32_t rev;
    uint64_t reserved;
    uint8_t vendor_specific[32];
} __attribute__((__packed__)) ;

struct opal_level0_feat_desc {
    uint16_t code;
    uint8_t reserved : 4;
    uint8_t rev : 4;
    uint8_t len;
    union {
        struct {
            struct tper_feat flags;
            uint8_t reserved[11];
        } __attribute__((__packed__)) tper;
        struct {
            struct locking_feat flags;
            uint8_t reserved[11];
        } __attribute__((__packed__)) locking;
        struct {
            uint8_t reserved[2];
            struct datastore_feat datastore;
        } datastore;
        struct geometry_feat geometry;
        struct opalv100_feat opalv100;
        struct opalv200_feat opalv200;
        struct opalv200_feat ruby;
        struct pyrite_feat pyritev100;
        struct pyrite_feat pyritev200;
        struct data_rm_feat data_rm;
        struct block_sid_feat block_sid;
        struct cnl_feat cnl;
        struct siis_feat siis;
        struct sum_feat sum;
    } feat;
} __attribute__((__packed__)) ;

struct opal_compacket {
    uint32_t reserved;
    uint8_t ext_comid[4];
    uint32_t outstanding_data;
    uint32_t min_transfer;
    uint32_t length;
} __attribute__((__packed__));

struct opal_packet {
    struct {
        uint32_t tsn;
        uint32_t hsn;
    } __attribute__((__packed__)) session;
    uint32_t seq_num;
    uint16_t reserved;
    uint16_t ack_type;
    uint32_t ack;
    uint32_t length;
} __attribute__((__packed__));

struct opal_subpacket {
    uint8_t reserved[6];
    uint16_t kind;
    uint32_t length;
} __attribute__((__packed__));

struct opal_header {
    struct opal_compacket compacket;
    struct opal_packet packet;
    struct opal_subpacket subpacket;
    uint8_t payload[];
} __attribute__((__packed__));

struct opal_level0_discovery {
    struct tper_feat tper;
    struct locking_feat locking;
    struct geometry_feat geometry;
    struct datastore_feat datastore;
    struct opalv100_feat opalv100;
    struct opalv200_feat opalv200;
};

int opal_init_pt(struct sed_device *dev, const char *device_path, bool try);

int opal_host_prop_pt(struct sed_device *dev, const char *props, uint32_t *vals);

int opal_dev_discovery_pt(struct sed_device *dev, struct sed_opal_device_discovery *discovery);

int opal_parse_tper_state_pt(struct sed_device *dev, struct sed_tper_state *tper_state);

int opal_start_session_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid, struct sed_session *session);

int opal_end_session_pt(struct sed_device *dev, struct sed_session *session);

int opal_start_end_transactions_pt(struct sed_device *dev, bool start, uint8_t status);

int opal_take_ownership_pt(struct sed_device *dev, const struct sed_key *key);

int opal_get_msid_pin_pt(struct sed_device *dev, struct sed_key *msid_pin);

int opal_revert_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *target_sp_uid);

int opal_revert_lsp_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *auth_uid, bool keep_global_range_key);

int opal_activate_sp_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *target_sp_uid, char *lr_str, uint8_t range_start_length_policy, char *dsts_str);

int opal_add_user_to_lr_pt(struct sed_device *dev, const struct sed_key *key, const char *user,
    enum SED_ACCESS_TYPE access_type, uint8_t lr);

int opal_enable_user_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *user_uid);

int opal_setup_global_range_pt(struct sed_device *dev, const struct sed_key *key, enum SED_FLAG_TYPE rle,
    enum SED_FLAG_TYPE wle);

int opal_setup_lr_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *lr_uid,
    uint64_t range_start, uint64_t range_length, enum SED_FLAG_TYPE rle, enum SED_FLAG_TYPE wle);

int opal_lock_unlock_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *auth_uid, uint8_t lr, bool sum,
    enum SED_ACCESS_TYPE access_type);

int opal_set_password_pt(struct sed_device *dev, uint8_t *sp_uid, uint8_t *auth_uid, const struct sed_key *auth_key,
    uint8_t *user_uid, const struct sed_key *new_user_key);

int opal_mbr_done_pt(struct sed_device *dev, const struct sed_key *key, bool mbr_done);

int opal_shadow_mbr_pt(struct sed_device *dev, const struct sed_key *key, bool mbr);

int opal_read_shadow_mbr_pt(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key, uint8_t *to,
    uint32_t size, uint32_t offset);

int opal_write_shadow_mbr_pt(struct sed_device *dev, const struct sed_key *key, const uint8_t *from, uint32_t size,
    uint32_t offset);

int opal_erase_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *uid);

int opal_genkey_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint32_t public_exponent, uint32_t pin_length);

int opal_ds_read_pt(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, uint8_t *to, uint32_t size,
    uint32_t offset);

int opal_ds_write_pt(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, const uint8_t *from,
    uint32_t size, uint32_t offset);

int opal_ds_add_anybody_get_pt(struct sed_device *dev, const struct sed_key *key);

int opal_list_lr_pt(struct sed_device *dev, const struct sed_key *key, struct sed_opal_locking_ranges *lrs);

int opal_block_sid_pt(struct sed_device *dev, bool hw_reset);

int opal_stack_reset_pt(struct sed_device *device, int32_t com_id, uint64_t extended_com_id, uint8_t *response);

int opal_set_with_buf_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, struct opal_req_item *cmd, size_t cmd_len);

int opal_get_set_col_val_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint64_t col, bool get, struct sed_opal_col_info *col_info);

int opal_get_set_byte_table_pt(struct sed_device *dev, const struct sed_key *key, const enum SED_SP_TYPE sp,
    const char *user, uint8_t *uid, uint64_t start, uint64_t end, uint8_t *buffer, bool is_set);

int opal_tper_reset_pt(struct sed_device *dev);

int opal_reactivate_sp_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *target_sp_uid, char *lr_str, uint8_t range_start_length_policy, const struct sed_key *admin1_pwd,
    char *dsts_str);

int opal_assign_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint32_t nsid, uint8_t range_start, uint8_t range_len, struct sed_locking_object *info);

int opal_deassign_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    const uint8_t *uid, bool keep_ns_global_range_key);

int opal_table_next_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint8_t *where, uint16_t count, struct sed_next_uids *next_uids);

int opal_authenticate_pt(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key);

int opal_get_acl_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    const uint8_t *invoking_uid, const uint8_t *method_uid, struct sed_next_uids *next_uids);

void opal_deinit_pt(struct sed_device *dev);

#endif /* _NVME_PT_IOCTL_H */
