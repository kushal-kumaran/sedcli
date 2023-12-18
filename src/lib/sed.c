/*
 * Copyright (C) 2018-2019, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <libsed.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <linux/version.h>

#include "nvme_pt_ioctl.h"
#include "sed_util.h"
#include "sedcli_log.h"

#define ARRAY_SIZE(x) ((size_t)(sizeof(x) / sizeof(x[0])))
#define NVME_DEV_PREFIX "nvme"
#define PATH_MAX 4096

typedef int (*init)(struct sed_device *, const char *, bool);
typedef int (*host_prop)(struct sed_device *, const char *, uint32_t *);
typedef int (*dev_discovery)(struct sed_device *, struct sed_opal_device_discovery *);
typedef int (*parse_tper_state)(struct sed_device *, struct sed_tper_state *);
typedef int (*take_ownership)(struct sed_device *, const struct sed_key *);
typedef int (*get_msid_pin)(struct sed_device *, struct sed_key *);
typedef int (*revert)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *);
typedef int (*revert_lsp)(struct sed_device *, const struct sed_key *, uint8_t *, bool);
 typedef int (*activate_sp)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *, char *,
    uint8_t, char *);
typedef int (*setup_global_range)(struct sed_device *, const struct sed_key *, enum SED_FLAG_TYPE, enum SED_FLAG_TYPE);
typedef int (*add_user_to_lr)(struct sed_device *, const struct sed_key *, const char *, enum SED_ACCESS_TYPE, uint8_t);
typedef int (*enable_user)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *);
typedef int (*setup_lr)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *, uint64_t, uint64_t,
    enum SED_FLAG_TYPE, enum SED_FLAG_TYPE);
typedef int (*lock_unlock)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t, bool, enum SED_ACCESS_TYPE);
typedef int (*set_password)(struct sed_device *, uint8_t *, uint8_t *, const struct sed_key *, uint8_t *,
    const struct sed_key *);
typedef int (*shadow_mbr)(struct sed_device *, const struct sed_key *, bool);
typedef int (*mbr_done) (struct sed_device *, const struct sed_key *, bool);
typedef int (*read_shadow_mbr) (struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, uint8_t *, uint32_t,
    uint32_t);
typedef int (*write_shadow_mbr)(struct sed_device *, const struct sed_key *, const uint8_t *, uint32_t, uint32_t);
typedef int (*erase)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *);
typedef int (*genkey) (struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *,
    uint32_t, uint32_t);
typedef int (*ds_add_anybody_get)(struct sed_device *, const struct sed_key *);
typedef int (*ds_read)(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, uint8_t *, uint32_t, uint32_t);
typedef int (*ds_write)(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *, const uint8_t *, uint32_t,
    uint32_t);
typedef int (*list_lr)(struct sed_device *, const struct sed_key *, struct sed_opal_locking_ranges *);
typedef int (*block_sid)(struct sed_device *, bool);
typedef int (*stack_reset)(struct sed_device *, int32_t com_id, uint64_t extended_com_id, uint8_t *response);
typedef int (*start_session)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, struct sed_session *);
typedef int (*end_session)(struct sed_device *, struct sed_session *);
typedef int (*start_end_transactions)(struct sed_device *, bool, uint8_t);
typedef int (*set_with_buf)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *,
    struct opal_req_item *, size_t);
typedef int (*get_set_col_val)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *,
    uint64_t, bool, struct sed_opal_col_info *);
typedef int (*tper_reset)(struct sed_device *);
typedef int (*get_set_byte_table)(struct sed_device *, const struct sed_key *, const enum SED_SP_TYPE,
    const char *, uint8_t *, uint64_t, uint64_t, uint8_t *, bool is_set);
typedef int (*reactivate_sp)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *, char *, uint8_t,
    const struct sed_key *, char *);
typedef int (*assign)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint32_t,
    uint8_t, uint8_t, struct sed_locking_object *);
typedef int (*deassign)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *,
    const uint8_t *, bool);
typedef int (*table_next)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, uint8_t *, uint8_t *,
    uint16_t, struct sed_next_uids *);
typedef int (*authenticate)(struct sed_device *, enum SED_AUTHORITY, const struct sed_key *);
typedef int (*get_acl)(struct sed_device *, const struct sed_key *, uint8_t *, uint8_t *, const uint8_t *,
    const uint8_t *, struct sed_next_uids *);
typedef void (*deinit)(struct sed_device *);

#define OPAL_INTERFACE(FN) FN FN ##_fn

struct opal_interface {
    OPAL_INTERFACE(init);
    OPAL_INTERFACE(host_prop);
    OPAL_INTERFACE(dev_discovery);
    OPAL_INTERFACE(parse_tper_state);
    OPAL_INTERFACE(take_ownership);
    OPAL_INTERFACE(get_msid_pin);
    OPAL_INTERFACE(revert);
    OPAL_INTERFACE(revert_lsp);
    OPAL_INTERFACE(activate_sp);
    OPAL_INTERFACE(setup_global_range);
    OPAL_INTERFACE(add_user_to_lr);
    OPAL_INTERFACE(enable_user);
    OPAL_INTERFACE(setup_lr);
    OPAL_INTERFACE(lock_unlock);
    OPAL_INTERFACE(set_password);
    OPAL_INTERFACE(shadow_mbr);
    OPAL_INTERFACE(read_shadow_mbr);
    OPAL_INTERFACE(write_shadow_mbr);
    OPAL_INTERFACE(mbr_done);
    OPAL_INTERFACE(erase);
    OPAL_INTERFACE(genkey);
    OPAL_INTERFACE(ds_add_anybody_get);
    OPAL_INTERFACE(ds_read);
    OPAL_INTERFACE(ds_write);
    OPAL_INTERFACE(list_lr);
    OPAL_INTERFACE(block_sid);
    OPAL_INTERFACE(stack_reset);
    OPAL_INTERFACE(start_session);
    OPAL_INTERFACE(end_session);
    OPAL_INTERFACE(start_end_transactions);
    OPAL_INTERFACE(set_with_buf);
    OPAL_INTERFACE(get_set_col_val);
    OPAL_INTERFACE(tper_reset);
    OPAL_INTERFACE(reactivate_sp);
    OPAL_INTERFACE(assign);
    OPAL_INTERFACE(deassign);
    OPAL_INTERFACE(table_next);
    OPAL_INTERFACE(authenticate);
    OPAL_INTERFACE(get_acl);
    OPAL_INTERFACE(deinit);
    OPAL_INTERFACE(get_set_byte_table);
};

#define OPAL_INTERFACE_DEF(FN) .FN ## _fn = opal_ ## FN ## _pt

static struct opal_interface nvmept_if = {
    OPAL_INTERFACE_DEF(init),
    OPAL_INTERFACE_DEF(host_prop),
    OPAL_INTERFACE_DEF(dev_discovery),
    OPAL_INTERFACE_DEF(parse_tper_state),
    OPAL_INTERFACE_DEF(take_ownership),
    OPAL_INTERFACE_DEF(get_msid_pin),
    OPAL_INTERFACE_DEF(revert),
    OPAL_INTERFACE_DEF(revert_lsp),
    OPAL_INTERFACE_DEF(activate_sp),
    OPAL_INTERFACE_DEF(setup_global_range),
    OPAL_INTERFACE_DEF(add_user_to_lr),
    OPAL_INTERFACE_DEF(enable_user),
    OPAL_INTERFACE_DEF(setup_lr),
    OPAL_INTERFACE_DEF(lock_unlock),
    OPAL_INTERFACE_DEF(set_password),
    OPAL_INTERFACE_DEF(shadow_mbr),
    OPAL_INTERFACE_DEF(read_shadow_mbr),
    OPAL_INTERFACE_DEF(write_shadow_mbr),
    OPAL_INTERFACE_DEF(mbr_done),
    OPAL_INTERFACE_DEF(erase),
    OPAL_INTERFACE_DEF(genkey),
    OPAL_INTERFACE_DEF(ds_add_anybody_get),
    OPAL_INTERFACE_DEF(ds_read),
    OPAL_INTERFACE_DEF(ds_write),
    OPAL_INTERFACE_DEF(list_lr),
    OPAL_INTERFACE_DEF(block_sid),
    OPAL_INTERFACE_DEF(stack_reset),
    OPAL_INTERFACE_DEF(start_session),
    OPAL_INTERFACE_DEF(end_session),
    OPAL_INTERFACE_DEF(start_end_transactions),
    OPAL_INTERFACE_DEF(set_with_buf),
    OPAL_INTERFACE_DEF(get_set_col_val),
    OPAL_INTERFACE_DEF(tper_reset),
    OPAL_INTERFACE_DEF(reactivate_sp),
    OPAL_INTERFACE_DEF(assign),
    OPAL_INTERFACE_DEF(deassign),
    OPAL_INTERFACE_DEF(table_next),
    OPAL_INTERFACE_DEF(authenticate),
    OPAL_INTERFACE_DEF(get_acl),
    OPAL_INTERFACE_DEF(deinit),
    OPAL_INTERFACE_DEF(get_set_byte_table),
};

static struct opal_interface *curr_if = &nvmept_if;

uint32_t nvme_error = 0;
int sed_init(struct sed_device **dev, const char *dev_path, bool try)
{
    struct sed_device *ret = malloc(sizeof(*ret));
    if (ret == NULL)
        return -ENOMEM;

    memset(ret, 0, sizeof(*ret));

    char *base = basename(dev_path);
    if (strncmp(base, NVME_DEV_PREFIX, strnlen(NVME_DEV_PREFIX, PATH_MAX))) {
        sed_deinit(ret);
        SEDCLI_DEBUG_PARAM("%s is not an NVMe device and opal-driver not built-in!\n", dev_path);
        return -EINVAL;
    }

    int status = curr_if->init_fn(ret, dev_path, try);
    if (status != 0) {
        sed_deinit(ret);
        SEDCLI_DEBUG_PARAM("Error initializing the device: %s\nStatus: %d\n", dev_path, status);
        nvme_error = status;
        return status;
    }

    *dev = ret;

    return status;
}

int sed_host_prop(struct sed_device *dev, const char *props, uint32_t *vals)
{
    if (curr_if->host_prop_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->host_prop_fn(dev, props, vals);
}

int sed_dev_discovery(struct sed_device *dev, struct sed_opal_device_discovery *discv)
{
    if (curr_if->dev_discovery_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->dev_discovery_fn(dev, discv);
}

int sed_parse_tper_state(struct sed_device *dev, struct sed_tper_state *tper_state)
{
    if (curr_if->parse_tper_state_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->parse_tper_state_fn(dev, tper_state);
}

void sed_deinit(struct sed_device *dev)
{
    if (dev != NULL) {
        curr_if->deinit_fn(dev);
        memset(dev, 0, sizeof(*dev));
        free(dev);
    }
}

int sed_key_init(struct sed_key *auth_key, char *key, const uint8_t key_len)
{
    if (key_len == 0)
        return -EINVAL;

    memcpy(auth_key->key, key, key_len);
    auth_key->len = key_len;

    return 0;
}

int sed_take_ownership(struct sed_device *dev, const struct sed_key *key)
{
    if (curr_if->take_ownership_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->take_ownership_fn(dev, key);
}

int sed_get_msid_pin(struct sed_device *dev, struct sed_key *msid_pin)
{
    if (curr_if->get_msid_pin_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->get_msid_pin_fn(dev, msid_pin);
}

int sed_setup_global_range(struct sed_device *dev, const struct sed_key *key, enum SED_FLAG_TYPE rle,
    enum SED_FLAG_TYPE wle)
{
    if (curr_if->setup_global_range_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->setup_global_range_fn(dev, key, rle, wle);
}

int sed_revert(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid, uint8_t *target_sp_uid)
{
    if (curr_if->revert_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->revert_fn(dev, key, sp_uid, auth_uid, target_sp_uid);
}

 int sed_revert_lsp(struct sed_device *dev, const struct sed_key *key, uint8_t *auth_uid, bool keep_global_range_key)
{
    if (curr_if->revert_lsp_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->revert_lsp_fn(dev, key, auth_uid, keep_global_range_key);
}

int sed_activate_sp(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *target_sp_uid, char *lr_str, uint8_t range_start_length_policy, char *dsts_str)
{
    if (curr_if->activate_sp_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->activate_sp_fn(dev, key, sp_uid, auth_uid, target_sp_uid, lr_str, range_start_length_policy, dsts_str);
}

int sed_lock_unlock(struct sed_device *dev, const struct sed_key *key, uint8_t *auth_uid, uint8_t lr, bool sum,
    enum SED_ACCESS_TYPE access_type)
{
    if (curr_if->lock_unlock_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->lock_unlock_fn(dev, key, auth_uid, lr, sum, access_type);
}

int sed_add_user_to_lr(struct sed_device *dev, const struct sed_key *key, const char *user,
    enum SED_ACCESS_TYPE access_type, uint8_t lr)
{
    if (curr_if->add_user_to_lr_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->add_user_to_lr_fn(dev, key, user, access_type, lr);
}

int sed_enable_user(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *user_uid)
{
    if (curr_if->enable_user_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->enable_user_fn(dev, key, sp_uid, auth_uid, user_uid);
}

int sed_setup_lr(struct sed_device *dev, const struct sed_key *key,  uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *lr_uid, uint64_t range_start, uint64_t range_length, enum SED_FLAG_TYPE rle, enum SED_FLAG_TYPE wle)
{
    return curr_if->setup_lr_fn(dev, key, sp_uid, auth_uid, lr_uid, range_start, range_length, rle, wle);
}

int sed_set_password(struct sed_device *dev, uint8_t *sp_uid, uint8_t *auth_uid, const struct sed_key *auth_key,
    uint8_t *user_uid, const struct sed_key *new_user_key)
{
    return curr_if->set_password_fn(dev, sp_uid, auth_uid, auth_key, user_uid, new_user_key);
}

int sed_shadow_mbr(struct sed_device *dev, const struct sed_key *key, bool mbr)
{
    return curr_if->shadow_mbr_fn(dev, key, mbr);
}

int sed_read_shadow_mbr(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key,uint8_t *to,
    uint32_t size, uint32_t offset)
{
    if (curr_if->read_shadow_mbr_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->read_shadow_mbr_fn(dev, auth, key, to, size, offset);
}

int sed_write_shadow_mbr(struct sed_device *dev, const struct sed_key *key, const uint8_t *from, uint32_t size,
    uint32_t offset)
{
    if (curr_if->write_shadow_mbr_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->write_shadow_mbr_fn(dev, key, from, size, offset);
}

int sed_mbr_done(struct sed_device *dev, const struct sed_key *key, bool mbr)
{
    if (curr_if->mbr_done_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->mbr_done_fn(dev, key, mbr);
}

int sed_erase(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid)
{
    if (curr_if->erase_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->erase_fn(dev, key, sp_uid, auth_uid, uid);
}

int sed_genkey(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint32_t public_exponent, uint32_t pin_length)
{
    if (curr_if->genkey_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->genkey_fn(dev, key, sp_uid, auth_uid, uid, public_exponent, pin_length);
}

int sed_ds_read(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key, uint8_t *to, uint32_t size,
    uint32_t offset)
{
    if (curr_if->ds_read_fn == NULL)
        return -EOPNOTSUPP;

    if (auth != SED_ANYBODY && key == NULL) {
        SEDCLI_DEBUG_MSG("Key can't be null\n");
        return -EINVAL;
    }

    return curr_if->ds_read_fn(dev, auth, key, to, size, offset);
}

int sed_ds_write(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key, const void *from,
    uint32_t size, uint32_t offset)
{
    if (curr_if->ds_write_fn == NULL)
        return -EOPNOTSUPP;

    if (auth != SED_ANYBODY && key == NULL) {
        SEDCLI_DEBUG_MSG("Key can't be null\n");
        return -EINVAL;
    }

    return curr_if->ds_write_fn(dev, auth, key, from, size, offset);
}

int sed_ds_add_anybody_get(struct sed_device *dev, const struct sed_key *key)
{
    if (curr_if->ds_add_anybody_get_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->ds_add_anybody_get_fn(dev, key);
}

int sed_list_lr(struct sed_device *dev, const struct sed_key *key, struct sed_opal_locking_ranges *lrs)
{
    if (curr_if->list_lr_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->list_lr_fn(dev, key, lrs);
}

int sed_issue_block_sid_cmd(struct sed_device *dev, bool hw_reset)
{
    if (curr_if->block_sid_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->block_sid_fn(dev, hw_reset);
}

int sed_stack_reset(struct sed_device *dev, int32_t com_id, uint64_t extended_com_id, uint8_t *response)
{
    if (curr_if->stack_reset_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->stack_reset_fn(dev, com_id, extended_com_id, response);
}

int sed_start_session(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    struct sed_session *session)
{
    if (curr_if->start_session_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->start_session_fn(dev, key, sp_uid, auth_uid, session);
}

int sed_end_session(struct sed_device *dev, struct sed_session *session)
{
    if (curr_if->end_session_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->end_session_fn(dev, session);
}

int sed_start_end_transactions(struct sed_device *dev, bool start, uint8_t status)
{
    if (curr_if->start_end_transactions_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->start_end_transactions_fn(dev, start, status);
}

int sed_set_with_buf(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, struct opal_req_item *cmd, size_t cmd_len)
{
    if (curr_if->set_with_buf_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->set_with_buf_fn(dev, key, sp_uid, auth_uid, uid, cmd, cmd_len);
}

int sed_get_set_col_val(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint64_t col, bool get, struct sed_opal_col_info *col_info)
{
    if (curr_if->get_set_col_val_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->get_set_col_val_fn(dev, key, sp_uid, auth_uid, uid, col, get, col_info);
}

int sed_get_set_byte_table(struct sed_device *dev, const struct sed_key *key, const enum SED_SP_TYPE sp,
    const char *user, uint8_t *uid, uint64_t start, uint64_t end, uint8_t *buffer, bool is_set)
{
    if (curr_if->get_set_byte_table_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->get_set_byte_table_fn(dev, key, sp, user, uid, start, end, buffer, is_set);
}

int sed_tper_reset(struct sed_device *dev)
{
    if (curr_if->tper_reset_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->tper_reset_fn(dev);
}

int sed_reactivate_sp(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *target_sp_uid, char *lr_str, uint8_t range_start_length_policy, const struct sed_key *admin1_pwd, char *dsts_str)
{
    if (curr_if->reactivate_sp_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->reactivate_sp_fn(dev, key, sp_uid, auth_uid, target_sp_uid, lr_str, range_start_length_policy, admin1_pwd, dsts_str);
}

int sed_assign(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint32_t nsid, uint8_t range_start, uint8_t range_len, struct sed_locking_object *info)
{
    if (curr_if->assign_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->assign_fn(dev, key, sp_uid, auth_uid, nsid, range_start, range_len, info);
}

int sed_deassign(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    const uint8_t *uid, bool keep_ns_global_range_key)
{
    if (curr_if->deassign_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->deassign_fn(dev, key, sp_uid, auth_uid, uid, keep_ns_global_range_key);
}

int sed_table_next(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint8_t *where, uint16_t count, struct sed_next_uids *next_uids)
{
    if (curr_if->table_next_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->table_next_fn(dev, key, sp_uid, auth_uid, uid, where, count, next_uids);
}

int sed_authenticate(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key)
{
    if (curr_if->authenticate_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->authenticate_fn(dev, auth, key);
}

int sed_get_acl(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    const uint8_t *invoking_uid, const uint8_t *method_uid, struct sed_next_uids *next_uids)
{
    if (curr_if->get_acl_fn == NULL)
        return -EOPNOTSUPP;

    return curr_if->get_acl_fn(dev, key, sp_uid, auth_uid, invoking_uid, method_uid, next_uids);
}
