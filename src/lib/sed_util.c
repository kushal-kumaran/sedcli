/*
 * Copyright (C) 2018-2019, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <sys/stat.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>

#include "../argp.h"

#include "nvme_pt_ioctl.h"
#include "sed_util.h"
#include "sedcli_log.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

extern uint8_t opal_uid[][OPAL_UID_LENGTH];

extern sedcli_printf_t sedcli_printf;

int open_dev(const char *dev, bool try)
{
    int err, fd;
    struct stat _stat;

    err = open(dev, O_RDONLY);
    if (err < 0)
        goto perror;
    fd = err;

    err = fstat(fd, &_stat);
    if (err < 0) {
        close(fd);
        goto perror;
    }

    if (!S_ISBLK(_stat.st_mode)) {
        SEDCLI_DEBUG_PARAM("%s is not a block device!\n", dev);
        close(fd);
        return -ENODEV;
    }

    return fd;

perror:
    if (try == false)
        perror(dev);
    return err;
}

int sed2opal_map[] = {
    [SED_ANYBODY] = OPAL_ANYBODY_UID,
    [SED_ADMINS] = OPAL_ADMINS_UID,
    [SED_MAKERS] = OPAL_MAKERS_UID,
    [SED_MAKERSYMK] = OPAL_MAKERSYMK_UID,
    [SED_MAKERPUK] = OPAL_MAKERPUK_UID,
    [SED_SID] = OPAL_SID_UID,
    [SED_PSID] = OPAL_PSID_UID,
    [SED_TPERSIGN] = OPAL_TPERSIGN_UID,
    [SED_TPEREXCH] = OPAL_TPEREXCH_UID,
    [SED_ADMINEXCH] = OPAL_ADMINEXCH_UID,
    [SED_ISSUERS] = OPAL_ISSUERS_UID,
    [SED_EDITORS] = OPAL_EDITORS_UID,
    [SED_DELETERS] = OPAL_DELETERS_UID,
    [SED_SERVERS] = OPAL_SERVERS_UID,
    [SED_RESERVE0] = OPAL_RESERVE0_UID,
    [SED_RESERVE1] = OPAL_RESERVE1_UID,
    [SED_RESERVE2] = OPAL_RESERVE2_UID,
    [SED_RESERVE3] = OPAL_RESERVE3_UID,
    [SED_ADMIN] = OPAL_ADMIN_UID,
    [SED_ADMIN1] = OPAL_ADMIN1_UID,
    [SED_ADMIN2] = OPAL_ADMIN2_UID,
    [SED_ADMIN3] = OPAL_ADMIN3_UID,
    [SED_ADMIN4] = OPAL_ADMIN4_UID,
    [SED_USERS] = OPAL_USERS_UID,
    [SED_USER] = OPAL_USER_UID,
    [SED_USER1] = OPAL_USER1_UID,
    [SED_USER2] = OPAL_USER2_UID,
    [SED_USER3] = OPAL_USER3_UID,
    [SED_USER4] = OPAL_USER4_UID,
    [SED_USER5] = OPAL_USER5_UID,
    [SED_USER6] = OPAL_USER6_UID,
    [SED_USER7] = OPAL_USER7_UID,
    [SED_USER8] = OPAL_USER8_UID,
    [SED_USER9] = OPAL_USER9_UID,
    [SED_BAND_MASTER_0] = OPAL_ENTERPRISE_BANDMASTER0_UID,
    [SED_ERASE_MASTER] = OPAL_ENTERPRISE_ERASEMASTER_UID
};

bool parse_uid(char **arg, uint8_t *uid)
{
    // uid in hex as 8 bytes table format 00-01-02-03-04-05-06-07
    uint8_t id = 0;
    char *p = arg[0];

    // parse all nums from table
    char *str;
    while (id < 8) {
        if (isxdigit(p[0]) == false || isxdigit(p[1]) == false)
            return false;

        // parse two-chars num as hex
        char byte[3];
        memcpy(byte, p, sizeof(char) * 2);
        byte[2] = 0;
        uid[id++] = (int)strtoul(byte, &str, 16);
        if (str == byte)
            return false;

        // skip 2 bytes for already parsed num
        p += 2;

        // skip 1 byte for dash
        if (id < 7 && *p != '-')
            return false;
        p += 1;
    }

    return true;
}

int get_opal_user_auth_uid(char *user_auth, bool user_auth_is_uid, uint8_t *user_auth_uid)
{
    if (user_auth_is_uid == false) {
        uint8_t user_auth_id;

        bool alias =  false;
        FILE *tfp = fopen("aliases", "r");
        if (tfp) {
            char line[256] = { 0 } ;
            char auth_tmp[256] = { 0 };
            memcpy(auth_tmp, user_auth, strlen(user_auth));
            auth_tmp[strlen(user_auth)] = 0;
            memcpy(auth_tmp + strlen(auth_tmp), "\n", 1);
            while (fgets(line, sizeof(line), tfp)) {
                if (strncmp(line, auth_tmp, 255) == 0)
                    if (fgets(line, sizeof(line), tfp)) {
                        char *p = line;
                        if (parse_uid(&p, user_auth_uid)) {
                            alias = true;
                            if (sed_cli == SED_CLI_STANDARD) {
                                sedcli_printf(LOG_INFO, "Found alias for %s: ", user_auth);
                                for (uint8_t i = 0; i < OPAL_UID_LENGTH; i++) {
                                    sedcli_printf(LOG_INFO, "%02x", user_auth_uid[i]);
                                    if (i < OPAL_UID_LENGTH - 1)
                                        sedcli_printf(LOG_INFO, "-");
                                    else
                                        sedcli_printf(LOG_INFO, "\n");
                                }
                            }
                            break;
                        }
                    }
                memset(line, 0, sizeof(line));
            }

            fclose(tfp);
        }

        if (alias)
            return SED_SUCCESS;

        if (sed_get_authority_uid(user_auth, &user_auth_id) != SED_SUCCESS)
            return -EINVAL;

        memcpy(user_auth_uid, opal_uid[user_auth_id], sizeof(uint8_t) * OPAL_UID_LENGTH);
    }

    return SED_SUCCESS;
}

int get_opal_auth_id(enum SED_AUTHORITY auth, uint8_t *auth_id)
{
    if (auth > ARRAY_SIZE(sed2opal_map)) {
        return -EINVAL;
    }

    *auth_id = sed2opal_map[auth];

    return SED_SUCCESS;
}

int sp2uid_map[] = {
    [SED_ADMIN_SP] = OPAL_ADMIN_SP_UID,
    [SED_LOCKING_SP] = OPAL_LOCKING_SP_UID,
    [SED_THIS_SP] = OPAL_THIS_SP_UID,
};

int get_opal_sp_uid(enum SED_SP_TYPE sp, uint8_t *sp_uid)
{
    if (sp == SED_UID_SP)
        return SED_SUCCESS;

    if (sp > ARRAY_SIZE(sp2uid_map)) {
        SEDCLI_DEBUG_MSG("error: get_opal_sp_uid\n");
        return -EINVAL;
    }

    memcpy(sp_uid, opal_uid[sp2uid_map[sp]], sizeof(uint8_t) * OPAL_UID_LENGTH);

    return SED_SUCCESS;
}

int sed_get_authority_uid(const char *authority, uint8_t *authority_uid)
{
    if (!strncmp(authority, "sid", MAX_INPUT)) *authority_uid = OPAL_SID_UID;
    else if (!strncmp(authority, "anybody", MAX_INPUT)) *authority_uid = OPAL_ANYBODY_UID;
    else if (!strncmp(authority, "admin1", MAX_INPUT)) *authority_uid = OPAL_ADMIN1_UID;
    else if (!strncmp(authority, "user1", MAX_INPUT)) *authority_uid = OPAL_USER1_UID;
    else {
        *authority_uid = -1;
        return -EINVAL;
    }

    return SED_SUCCESS;
}

int sed_get_user_admin(const char *user, uint32_t *who, bool *admin)
{
    unsigned int unum = 0;
    char *error;

    if (strlen(user) < 5) {
        SEDCLI_DEBUG_MSG("Incorrect User, please provide userN/Admin1\n");
        return -EINVAL;
    }

    if (!strncasecmp(user, "admin", 5)) {
        SEDCLI_DEBUG_MSG("Making the user an admin\n");
        unum = strtol(&user[5], &error, 10);
        *admin = true;
    } else if (!strncasecmp(user, "user", 4)) {
        unum = strtol(&user[4], &error, 10);
        *admin = false;
    } else {
        SEDCLI_DEBUG_MSG("Incorrect User provide. Provide adminN/userN\n");
        return -EINVAL;
    }

    if (error == &user[4]) {
        SEDCLI_DEBUG_MSG("Failed to parse user # from string\n");
        return -EINVAL;
    }

    *who = unum;

    return 0;
}

bool compare_uid(uint8_t *uid1, uint8_t *uid2)
{
    if (memcmp(uid1, uid2, sizeof(uint8_t) * OPAL_UID_LENGTH) == 0)
        return true;

    return false;
}

bool compare_uid_range(uint8_t *uid1, uint8_t *uid2, uint8_t start, uint8_t end)
{
    uint8_t uid_temp[OPAL_UID_LENGTH];
    memcpy(uid_temp, uid1, sizeof(uint8_t) * OPAL_UID_LENGTH);
    for (uint8_t i = start; i < end; i++) {
        uid_temp[OPAL_UID_LENGTH - 1] = i;
        if (memcmp(uid_temp, uid2, sizeof(uint8_t) * OPAL_UID_LENGTH) == 0)
            return true;
    }

    return false;
}
