/*
 * Copyright (C) 2018-2019, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _SED_UTIL_H_
#define _SED_UTIL_H_

#include <stdint.h>
#include "libsed.h"

struct sed_device {
    int fd;
    struct sed_opal_device_discovery discovery;
    void *priv;
};

int open_dev(const char *dev, bool try);

bool parse_uid(char **arg, uint8_t *uid);
int sed_get_user_admin(const char *user, uint32_t *who, bool *admin);

int sed_get_authority_uid(const char *user, uint8_t *user_uid);
int get_opal_auth_id(enum SED_AUTHORITY auth, uint8_t *auth_uid);

int get_opal_user_auth_uid(char *user_auth, bool user_auth_is_uid, uint8_t *user_auth_uid);
int get_opal_sp_uid(enum SED_SP_TYPE sp, uint8_t *sp_uid);

bool compare_uid(uint8_t *uid1, uint8_t *uid2);
bool compare_uid_range(uint8_t *uid1, uint8_t *uid2, uint8_t start, uint8_t end);

#endif /* _SED_UTIL_H_ */
