/*
 * Copyright (C) 2018-2019, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _LIBSED_H_
#define _LIBSED_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define OPAL_UID_LENGTH 8

#define SED_MAX_KEY_LEN 255

#define SED_OPAL_MAX_LRS 9
#define OPAL_MAX_DSTS 256

#define MAX_PROP_NAME_LEN 32
#define NUM_TPER_PROPS    23
#define NUM_HOST_PROPS    10

#define SED_OPAL_MANUFACTURED_INACTIVE 0x08

enum SED_CLI_TYPE {
    SED_CLI_STANDARD,
    SED_CLI_KMIP
} sed_cli;

enum SED_ACCESS_TYPE {
    SED_ACCESS_RO = 1 << 0, // read only
    SED_ACCESS_WO = 1 << 1, // write only
    SED_ACCESS_RW = 1 << 2, // read write
    SED_ACCESS_LK = 1 << 3, // locked (read and write not allowed)
};

enum SED_AUTHORITY {
    SED_ANYBODY,
    SED_ADMINS,
    SED_MAKERS,
    SED_MAKERSYMK,
    SED_MAKERPUK,
    SED_SID,
    SED_PSID,
    SED_TPERSIGN,
    SED_TPEREXCH,
    SED_ADMINEXCH,
    SED_ISSUERS,
    SED_EDITORS,
    SED_DELETERS,
    SED_SERVERS,
    SED_RESERVE0,
    SED_RESERVE1,
    SED_RESERVE2,
    SED_RESERVE3,
    SED_ADMIN,
    SED_ADMIN1,
    SED_ADMIN2,
    SED_ADMIN3,
    SED_ADMIN4,
    SED_USERS,
    SED_USER,
    SED_USER1,
    SED_USER2,
    SED_USER3,
    SED_USER4,
    SED_USER5,
    SED_USER6,
    SED_USER7,
    SED_USER8,
    SED_USER9,
    SED_BAND_MASTER_0,
    SED_ERASE_MASTER
};

struct sed_device;

struct sed_tper_feat {
    uint8_t sync_supp : 1;
    uint8_t async_supp : 1;
    uint8_t ack_nak_supp : 1;
    uint8_t buff_mgmt_supp : 1;
    uint8_t stream_supp : 1;
    uint8_t reserved1 : 1;
    uint8_t comid_mgmt_supp : 1;
    uint8_t reserved2 : 1;
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_locking_feat {
    uint8_t locking_supp : 1;
    uint8_t locking_en : 1;
    uint8_t locked : 1;
    uint8_t media_enc : 1;
    uint8_t mbr_en : 1;
    uint8_t mbr_done : 1;
    uint8_t mbr_shadowing_not_supported : 1;
    uint8_t mbr_hw_reset_for_lor_dor_supported : 1;
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_geometry_feat {
    struct {
        uint8_t align : 1;
        uint8_t rsvd1 : 7 ;
    } __attribute__((__packed__)) rsvd_align;
    uint8_t rsvd2[7];
    uint32_t logical_blk_sz;
    uint64_t alignmnt_granlrty;
    uint64_t lowest_aligned_lba;
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_datastore_feat {
    uint16_t max_num_datastores;
    uint32_t max_total_size_datstr_tbls;
    uint32_t datastore_size_align;
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_opalv100_feat {
    uint16_t v1_base_comid;
    uint16_t v1_comid_num;
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_opalv200_feat {
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
    uint16_t code;
    union {
        struct {
            uint8_t feature_descriptor_version : 4;
            uint8_t ssc_minor_version : 4;
        } __attribute__((__packed__)) ver;
        uint8_t rev;
    } rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_pyrite_feat {
    uint16_t base_comid;
    uint16_t comid_num;
    uint8_t reserved[5];
    uint8_t init_pin;
    uint8_t revert_pin;
    uint8_t reserved2[5];
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_data_rm_feat {
    uint8_t reserved;
    struct {
        uint8_t rm_op_processing:1;
        uint8_t rsvd1:7;
    } __attribute__((__packed__)) rmopprocessing_rsvd;
    uint8_t supp_data_rm;
    struct {
        uint8_t data_rm_time_fmt : 6;
        uint8_t rsvd2:2;
    } __attribute__((__packed__)) datarmtimefmtbits_rsvd;
    uint16_t data_rm_time[6];
    uint8_t reserved2[16];
} __attribute__((__packed__));

struct sed_tper_properties {
    struct {
        char key_name[MAX_PROP_NAME_LEN];
        uint64_t value;
    } property[NUM_TPER_PROPS];
} __attribute__((__packed__));

struct sed_block_sid_feat {
    uint8_t sid_valuestate : 1;
    uint8_t sid_blockstate : 1;
    uint8_t lsp_freeze_lock_support : 1 ;
    uint8_t lsp_freeze_lock_state : 1;
    uint8_t reserved1 : 4;
    uint8_t hardware_reset : 1;
    uint8_t reserved2 : 7;
    uint8_t reserved3[10];
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_sum_feat {
    uint32_t number_of_locking_objects_supported;
    uint8_t any : 1;
    uint8_t all : 1;
    uint8_t policy : 1;
    uint8_t reserved : 5;
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_cnl_feat {
    struct {
        uint8_t rsvd1 : 5;
        uint8_t sum_c : 1;
        uint8_t range_p : 1;
        uint8_t range_c : 1;
    } __attribute__((__packed__)) ranges_rsvd;
    uint8_t rsvd2[3];
    uint32_t max_key_count;
    uint32_t unused_key_count;
    uint32_t max_ranges_per_ns;
    uint16_t code;
    uint8_t rev;
    uint8_t len;
} __attribute__((__packed__));

struct sed_opal_level0_discovery_header {
    uint32_t len;
    uint32_t rev;
    uint64_t reserved;
    uint8_t vendor_specific[32];
} __attribute__((__packed__));

struct sed_opal_level0_discovery {
    struct {
        uint64_t feat_tper:1;
        uint64_t feat_locking:1;
        uint64_t feat_geometry:1;
        uint64_t feat_datastore:1;
        uint64_t feat_opalv100:1;
        uint64_t feat_opalv200:1;
        uint64_t feat_ruby:1;
        uint64_t feat_pyritev100:1;
        uint64_t feat_pyritev200:1;
        uint64_t feat_data_rm:1;
        uint64_t feat_block_sid:1;
        uint64_t feat_sum:1;
        uint64_t feat_cnl:1;
        uint64_t reserved:51;
    } __attribute__((__packed__)) feat_avail_flag;

    struct sed_tper_feat sed_tper;
    struct sed_locking_feat sed_locking;
    struct sed_geometry_feat sed_geometry;
    struct sed_datastore_feat sed_datastore;
    struct sed_opalv100_feat sed_opalv100;
    struct sed_opalv200_feat sed_opalv200;
    struct sed_opalv200_feat sed_ruby;
    struct sed_pyrite_feat sed_pyritev100;
    struct sed_pyrite_feat sed_pyritev200;
    struct sed_data_rm_feat sed_data_rm;
    struct sed_block_sid_feat sed_block_sid;
    struct sed_sum_feat sed_sum;
    struct sed_cnl_feat sed_cnl;
};

struct sed_opal_device_discovery {
    struct sed_opal_level0_discovery_header sed_lvl0_discv_header;
    struct sed_opal_level0_discovery sed_lvl0_discv;
    struct sed_tper_properties sed_tper_props;
    struct sed_tper_properties sed_host_props;
};

struct sed_tper_state {
    uint8_t session_open;
    uint8_t blk_sid_val_state;
    uint8_t locking_en;
    uint8_t admisp_lc;
    uint8_t lsp_lc;
};

struct sed_key {
    char key[SED_MAX_KEY_LEN];
    uint8_t len;
};

struct sed_opal_lockingrange {
    size_t start;
    size_t length;
    uint8_t lr_id:4;
    uint8_t read_locked:1;
    uint8_t write_locked:1;
    uint8_t rle:1;
    uint8_t wle:1;
};

struct sed_opal_locking_ranges {
    struct sed_opal_lockingrange lrs[SED_OPAL_MAX_LRS];
    uint8_t lr_num;
};

enum SED_TOKEN_TYPE {
    SED_DATA_BYTESTRING = 0xE0,
    SED_DATA_SINT = 0xE1,
    SED_DATA_UINT = 0xE2,
    SED_DATA_TOKEN = 0xE3,
    SED_DATA_TOKEN_INVALID = 0x0,
};

enum SED_SP_TYPE {
    SED_ADMIN_SP,
    SED_LOCKING_SP,
    SED_THIS_SP,
    SED_UID_SP,
};

enum SED_FLAG_TYPE {
    SED_FLAG_UNDEFINED,
    SED_FLAG_ENABLED,
    SED_FLAG_DISABLED
};

struct opal_req_item {
    uint8_t type;
    int len;
    union {
        uint8_t byte;
        uint64_t uint;
        const uint8_t *bytes;
    } val;
};

struct sed_opal_col_info {
    void *data;
    uint32_t len;
    enum SED_TOKEN_TYPE type;
    uint8_t opal_type;
    struct sed_opal_col_info *next_col;
};

struct sed_locking_object {
    uint32_t nsid; /* NS id assigned */
    uint8_t uid[OPAL_UID_LENGTH]; /* Locking Object UID */
    uint8_t nsgid; /* True or False */
};

struct sed_next_uids {
    uint8_t **uids;
    uint32_t size;
};

struct sed_session {
    uint32_t hsn;
    uint32_t tsn;
};

enum sed_status {
    SED_SUCCESS,
    SED_NOT_AUTHORIZED,
    SED_UNKNOWN_ERROR, // not in spec
    SED_SP_BUSY,
    SED_SP_FAILED,
    SED_SP_DISABLED,
    SED_SP_FROZEN,
    SED_NO_SESSIONS_AVAILABLE,
    SED_UNIQUENESS_CONFLICT,
    SED_INSUFFICIENT_SPACE,
    SED_INSUFFICIENT_ROWS,
    SED_INVALID_FUNCTION, // not in spec
    SED_INVALID_PARAMETER,
    SED_INVALID_REFERENCE, // not in spec
    SED_UNKNOWN_ERROR_1, // not in spec
    SED_TPER_MALFUNCTION,
    SED_TRANSACTION_FAILURE,
    SED_RESPONSE_OVERFLOW,
    SED_AUTHORITY_LOCKED_OUT,
    SED_FAIL = 0x3F, /* Fail status code as defined by Opal is higher value */
};

/**
 * This function initializes libsed for usage. It opens device node file and
 * stores relevant information in data structure representing libsed context.
 * Libsed context must be passed to other libsed functions for its proper
 * operation.
 */
int sed_init(struct sed_device **dev, const char *dev_path, bool try);

int sed_host_prop(struct sed_device *dev, const char *prop, uint32_t *val);

int sed_dev_discovery(struct sed_device *dev,
    struct sed_opal_device_discovery *discv);

int sed_parse_tper_state(struct sed_device *dev,
    struct sed_tper_state *tper_state);

void sed_deinit(struct sed_device *dev);

int sed_key_init(struct sed_key *disk_key, char *key, const uint8_t key_len);

int sed_get_msid_pin(struct sed_device *dev, struct sed_key *msid_pin);

int sed_take_ownership(struct sed_device *dev, const struct sed_key *key);

int sed_activate_sp(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *target_sp_uid, char *lr_str,
    uint8_t range_start_length_policy, char *dsts_str);

int sed_setup_global_range(struct sed_device *dev, const struct sed_key *key,
    enum SED_FLAG_TYPE rle, enum SED_FLAG_TYPE wle);

int sed_lock_unlock(struct sed_device *dev, const struct sed_key *key,
    uint8_t *auth_uid, uint8_t lr, bool sum, enum SED_ACCESS_TYPE access_type);

int sed_revert(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *target_sp_uid);

int sed_revert_lsp(struct sed_device *dev, const struct sed_key *key,
    uint8_t *auth_uid, bool keep_global_range_key);

int sed_set_password(struct sed_device *dev, uint8_t *sp_uid, uint8_t *auth_uid,
    const struct sed_key *auth_key, uint8_t *user_uid,
    const struct sed_key *new_user_key);

int sed_list_lr(struct sed_device *dev, const struct sed_key *key,
    struct sed_opal_locking_ranges *lrs);

int sed_ds_add_anybody_get(struct sed_device *dev, const struct sed_key *key);

int sed_ds_read(struct sed_device *dev, enum SED_AUTHORITY auth,
    const struct sed_key *key, uint8_t *to, uint32_t size,
    uint32_t offset);

int sed_ds_write(struct sed_device *dev, enum SED_AUTHORITY auth,
    const struct sed_key *key, const void *from, uint32_t size,
    uint32_t offset);

int sed_shadow_mbr(struct sed_device *dev, const struct sed_key *key, bool mbr);

int sed_mbr_done(struct sed_device *dev, const struct sed_key *key, bool mbr);

int sed_read_shadow_mbr(struct sed_device *dev, enum SED_AUTHORITY auth,
    const struct sed_key *key,uint8_t *to, uint32_t size,
    uint32_t offset);

int sed_write_shadow_mbr(struct sed_device *dev, const struct sed_key *key,
    const uint8_t *from, uint32_t size, uint32_t offset);

int sed_issue_block_sid_cmd(struct sed_device *dev, bool hw_reset);

int sed_add_user_to_lr(struct sed_device *dev, const struct sed_key *key,
    const char *user, enum SED_ACCESS_TYPE access_type, uint8_t lr);

int sed_setup_lr(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *lr_uid, uint64_t range_start,
    uint64_t range_length, enum SED_FLAG_TYPE rle, enum SED_FLAG_TYPE wle);

int sed_enable_user(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *user_uid);

int sed_erase(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *uid);

int sed_genkey(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *uid,
    uint32_t public_exponent, uint32_t pin_length);

int sed_start_session(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, struct sed_session *session);

int sed_end_session(struct sed_device *dev, struct sed_session *session);

int sed_start_end_transactions(struct sed_device *dev, bool start,
    uint8_t status);

int sed_set_with_buf(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *uid, struct opal_req_item *cmd,
    size_t cmd_len);

int sed_get_set_col_val(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *uid, uint64_t col,
    bool get, struct sed_opal_col_info *col_info);

int sed_get_set_byte_table(struct sed_device *dev, const struct sed_key *key,
    const enum SED_SP_TYPE sp, const char *user, uint8_t *uid, uint64_t start,
    uint64_t end, uint8_t *buffer, bool is_set);

int sed_stack_reset(struct sed_device *dev, int32_t com_id, uint64_t extended_com_id, uint8_t *response);

int sed_tper_reset(struct sed_device *dev);

int sed_reactivate_sp(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *target_sp_uid, char *lr_str,
    uint8_t range_start_length_policy, const struct sed_key *admin1_pwd,
    char *dsts_str);

int sed_assign(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint32_t nsid,
    uint8_t range_start, uint8_t range_length, struct sed_locking_object *info);

int sed_deassign(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, const uint8_t *uid,
    bool keep_ns_global_range_key);

int sed_table_next(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *uid,
    uint8_t *where, uint16_t count, struct sed_next_uids *next_uids);

int sed_authenticate(struct sed_device *dev, enum SED_AUTHORITY auth,
    const struct sed_key *key);

int sed_get_acl(struct sed_device *dev, const struct sed_key *key,
    uint8_t *sp_uid, uint8_t *auth_uid, const uint8_t *invoking_uid,
    const uint8_t *method_uid, struct sed_next_uids *next_uids);

#endif /* _LIBSED_H_ */
