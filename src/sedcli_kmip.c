/*
 * Copyright (C) 2020, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h" // include first

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <sys/syslog.h>
#include <sys/mman.h>

#include <libsed.h>

#include "argp.h"
#include "kmip_lib.h"
#include "crypto_lib.h"
#include "config_file.h"
#include "metadata_serializer.h"
#include "sedcli_util.h"

#include "lib/nvme_pt_ioctl.h"

#include "lib/opal_parser.h"

#define MAX_SCAN_DEVS 64

#define ENC_KEY_LEN (SED_KMIP_KEY_LEN / 8)

extern sedcli_printf_t sedcli_printf;

extern uint8_t opal_uid[][OPAL_UID_LENGTH];

static int handle_connection_test_opts(char *opt, char **arg);
static int handle_provision_opts(char *opt, char **arg);
static int handle_lock_unlock_opts(char *opt, char **arg);
static int handle_get_lock_info_opts(char *opt, char **arg);
static int handle_revert_tper_opts(char *opt, char **arg);

static int handle_version(void);
static int handle_scan(void);
static int handle_connection_test(void);
static int handle_provision(void);
static int handle_lock_unlock(void);
static int handle_get_lock_info(void);
static int handle_revert_tper(void);

static int read_key_from_datastore(struct sed_device *sed_dev, struct sed_key *dek_key);

static int programmatic_reset_enable(struct sed_device *sed_dev, const struct sed_key *key);

static struct sedcli_stat_conf _conf_stat_file;
static struct sedcli_stat_conf *conf_stat_file = &_conf_stat_file;

static struct sedcli_dyn_conf _conf_dyn_file;
static struct sedcli_dyn_conf *conf_dyn_file = &_conf_dyn_file;

static cli_option connection_opts[] = {
    {0}
};

static cli_option provision_opts[] = {
    {'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
    {0}
};

static cli_option lock_unlock_opts[] = {
    {'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
    {'t', "access-type", "String specifying access type to the data on drive. Allowed values: RO/WO/RW/LK", 1, "FMT", CLI_OPTION_REQUIRED},
    {0}
};

static cli_option revert_tper_opts[] = {
    {'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
    {0}
};

static cli_option get_lock_info_opts[] = {
    {'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED},
    {0}
};

static cli_command sedcli_commands[] = {
    {
        .name = "provision",
        .desc = "Provision disk for security.",
        .long_desc = NULL,
        .options = provision_opts,
        .options_parse = handle_provision_opts,
        .handle = handle_provision,
        .flags = 0,
        .help = NULL
    },
    {
        .name = "lock-unlock",
        .desc = "Lock or unlock global locking range.",
        .long_desc = "Lock or unlock global locking range in Locking SP using key retrieved from KMS.",
        .options = lock_unlock_opts,
        .options_parse = handle_lock_unlock_opts,
        .handle = handle_lock_unlock,
        .flags = 0,
        .help = NULL
    },
    {
        .name = "revert-tper",
        .desc = "Revert TPer.",
        .long_desc = "Revert TPer.",
        .options = revert_tper_opts,
        .options_parse = handle_revert_tper_opts,
        .handle = handle_revert_tper,
        .flags = 0,
        .help = NULL
    },
    {
        .name = "get-lock-info",
        .desc = "Get Lock info.",
        .long_desc = "Get Lock info.",
        .options = get_lock_info_opts,
        .options_parse = handle_get_lock_info_opts,
        .handle = handle_get_lock_info,
        .flags = 0,
        .help = NULL
    },
    {
        .name = "connection-test",
        .desc = "Connection test.",
        .long_desc = "Connection test.",
        .options = connection_opts,
        .options_parse = handle_connection_test_opts,
        .handle = handle_connection_test,
        .flags = 0,
        .help = NULL
    },
    {
        .name = "scan",
        .desc = "Scans available drives.",
        .long_desc = "Scans available drives.",
        .options = NULL,
        .options_parse = NULL,
        .handle = handle_scan,
        .flags = 0,
        .help = NULL
    },
    {
        .name = "version",
        .desc = "Print sedcli-kmip version.",
        .long_desc = "Print sedcli-kmip version.",
        .options = NULL,
        .options_parse = NULL,
        .handle = handle_version,
        .flags = 0,
        .help = NULL
    },
    {0},
};

static char *dev_path;

struct sedcli_options {
    uint8_t pwd_len;
    uint8_t repeated_pwd_len;
    enum SED_ACCESS_TYPE access_type;
};

static struct sedcli_options *opts;

#define DEV_INFO_LEN 256
typedef struct dev_info {
    char serial[DEV_INFO_LEN];
    char model[DEV_INFO_LEN];
} dev_info;
struct dev_info devs[MAX_SCAN_DEVS];

#define READ_BUF_SIZE 4096
#define COMMAND_BUF_SIZE 1024
#define MAX_DEV_LEN 10

int execl_param(int dev, char *param, char *output)
{
    char read_buf[READ_BUF_SIZE + 1] = {0};

    int link[2];
    if (pipe(link) == -1)
        return FAILURE;

    pid_t pid;
    if ((pid = fork()) == -1)
        return FAILURE;

    if (pid == 0) {
        dup2(link[1], STDOUT_FILENO);
        close(link[0]);
        close(link[1]);

        char *prefix = "//sys//block//nvme";
        int prefix_len = strlen(prefix);
        char prefix_with_dev[DEV_INFO_LEN] = {0};
        memcpy(prefix_with_dev, prefix, sizeof(char) * prefix_len);
        char dev_str[MAX_DEV_LEN];
        snprintf(dev_str, sizeof(dev_str), "%d", dev);
        memcpy(prefix_with_dev + prefix_len, dev_str, sizeof(char) * strlen(dev_str));

        char *postfix = "n1//device//";
        int postfix_len = strlen(postfix);
        char postfix_with_param[DEV_INFO_LEN] = {0};
        memcpy(postfix_with_param, postfix, sizeof(char) * postfix_len);
        memcpy(postfix_with_param + postfix_len, param, sizeof(char) * strlen(param));

        char cmd[COMMAND_BUF_SIZE] = {0};
        memcpy(cmd, prefix_with_dev, sizeof(char) * strlen(prefix_with_dev));
        memcpy(cmd + strlen(prefix_with_dev), postfix_with_param, sizeof(char) * strlen(postfix_with_param));

        char *cmds[3] = {"cat", NULL, NULL};
        cmds[1] = cmd;
        execve("//bin//cat", cmds, NULL);
    } else {
        close(link[1]);
        int nbytes = 0;
        while(0 != (nbytes = read(link[0], read_buf, sizeof(read_buf)))) {
            read_buf[READ_BUF_SIZE] = '\0';
            memcpy(output, read_buf, sizeof(char) * strlen(read_buf));
            memset(read_buf, 0, sizeof(read_buf));
        }
        wait(NULL);
    }

    return SUCCESS;
}

static int handle_scan(void)
{
    int fd = 0;
    if ((fd = open("//dev//null", O_RDWR)) == -1) {
        perror("open");
        return FAILURE;
    }

    dup2(fd, STDERR_FILENO);
    close(fd);

    for (uint8_t i = 0; i < MAX_SCAN_DEVS; i++)
    {
        char dev_name[DEV_INFO_LEN] = {0};
        snprintf(dev_name, sizeof(dev_name), "//dev//nvme%dn1", i);

        struct sed_device *dev = NULL;
        int ret = sed_init(&dev, dev_name, true);
        if (ret)
            continue;

        execl_param(i, "serial", devs[i].serial);
        execl_param(i, "model", devs[i].model);

        sedcli_printf(LOG_INFO, "nvme%dn1:\nserial: %smodel: %s", i, devs[i].serial, devs[i].model);
        if (dev->discovery.sed_lvl0_discovery.feat_avail_flag.feat_opalv100)
            sedcli_printf(LOG_INFO, "opal1 supported\n");
        if (dev->discovery.sed_lvl0_discovery.feat_avail_flag.feat_opalv200)
            sedcli_printf(LOG_INFO, "opal2 supported\n");
        sedcli_printf(LOG_INFO, "\n");

        sed_deinit(dev);
    }

    return SUCCESS;
}

static int handle_version(void)
{
    sedcli_printf(LOG_INFO, "sedcli-kmip %s\n", SEDCLI_KMIP_VERSION);

    return SUCCESS;
}

static int handle_connection_test_opts(char *opt, char **arg)
{
    if (opt || arg[0])
        sedcli_printf(LOG_INFO, "not supported\n");

    return SUCCESS;
}

static int handle_provision_opts(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT))
        dev_path = (char *)arg[0];

    return SUCCESS;
}

static int handle_lock_unlock_opts(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        dev_path = (char *) arg[0];
    } else if (!strncmp(opt, "access-type", MAX_INPUT)) {
        int err = get_access_type(arg[0], &opts->access_type);
        if (err == -EINVAL) {
            sedcli_printf(LOG_ERR, "Incorrect lock type\n");
            return -EINVAL;
        }
    }

    return SUCCESS;
}

static int handle_revert_tper_opts(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT))
        dev_path = (char *) arg[0];

    return SUCCESS;
}

static int handle_get_lock_info_opts(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT))
        dev_path = (char *) arg[0];

    return SUCCESS;
}

bool free_col_info(struct sed_opal_col_info *col_info)
{
    if (col_info == NULL)
        return false;

    if (col_info->next_col) {
        free_col_info(col_info->next_col);
        col_info->next_col = NULL;
    }

    free(col_info->data);
    col_info->data = NULL;

    free(col_info);

    return true;
}

static int handle_connection_test(void)
{
    memset(conf_stat_file, 0, sizeof(*conf_stat_file));
    memset(conf_dyn_file, 0, sizeof(*conf_dyn_file));

    int status = read_stat_config(conf_stat_file);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while reading sedcli config file.\n");
        return KMIP_FAILURE;
    }

    status = read_dyn_config(conf_dyn_file);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while reading sedcli dynamic config file.\n");
        return KMIP_FAILURE;
    }

    struct sed_kmip_ctx ctx = { 0 };
    status = sed_kmip_init(&ctx, conf_stat_file->kmip_ip,
        conf_stat_file->kmip_port,
        conf_stat_file->client_cert_path,
        conf_stat_file->client_key_path,
        conf_stat_file->ca_cert_path);

    if (status == -1) {
        sedcli_printf(LOG_ERR, "Can't initialize KMIP connection.\n");
        status = KMIP_FAILURE;
        goto deinit;
    }

    status = sed_kmip_connect(&ctx);
    if (status) {
        sedcli_printf(LOG_ERR, "Can't connect to KMIP.\n");
        status = KMIP_FAILURE;
        goto deinit;
    } else
        status = KMIP_SUCCESS_CONNECTED;

deinit:
    sed_kmip_deinit(&ctx);

    return status;
}

static int handle_revert_tper(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, dev_path, false);
    if (ret)
        return ret;

    struct sed_key *key = NULL; /* [0] - DEK, [1] - existing key*/
    key = alloc_locked_buffer(2 * sizeof(*key));
    if (!key) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        ret = -ENOMEM;
        goto deinit;
    }

    int status = read_key_from_datastore(dev, &key[0]);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while accessing datastore.\n");
        ret = status;
        goto deinit;
    }

    ret = sed_revert(dev, &key[0], opal_uid[OPAL_ADMIN_SP_UID], opal_uid[OPAL_SID_UID], opal_uid[OPAL_ADMIN_SP_UID]);

deinit:
    sed_deinit(dev);

    if (key)
        free_locked_buffer(key, 2 * sizeof(*key));

    return ret;
}

static int handle_provision(void)
{
    struct sed_device *sed_dev = NULL;
    struct sed_key *key = NULL; /* [0] - DEK, [1] - existing key*/
    struct sedcli_metadata *meta = NULL;
    int pek_id_size = 0, pek_size = 0, auth_len;
    uint8_t *iv = NULL, *pek = NULL, *enc_dek = NULL, *pek_id = NULL, *tag = NULL;

    memset(conf_stat_file, 0, sizeof(*conf_stat_file));
    memset(conf_dyn_file, 0, sizeof(*conf_dyn_file));

    int status = read_stat_config(conf_stat_file);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while reading sedcli config file!\n");
        return -1;
    }

    int dynamic_config_read_status = read_dyn_config(conf_dyn_file);
    if (dynamic_config_read_status)
        sedcli_printf(LOG_INFO, "Error while reading sedcli kmip dynamic config file! Will create new one.\n");

    key = alloc_locked_buffer(2 * sizeof(*key));
    if (!key) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        return -ENOMEM;
    }

    struct sed_kmip_ctx *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        status = -ENOMEM;
        goto deinit;
    }
    memset(ctx, 0, sizeof(struct sed_kmip_ctx));

    status = sed_kmip_init(ctx, conf_stat_file->kmip_ip,
        conf_stat_file->kmip_port,
        conf_stat_file->client_cert_path,
        conf_stat_file->client_key_path,
        conf_stat_file->ca_cert_path);

    if (status == -1) {
        sedcli_printf(LOG_ERR, "Can't initialize KMIP connection.\n");
        goto deinit;
    }

    status = sed_kmip_connect(ctx);
    if (status) {
        sedcli_printf(LOG_ERR, "Can't connect to KMIP.\n");
        goto deinit;
    }

    if (conf_dyn_file->pek_id_size == 0) {
        status = sed_kmip_gen_platform_key(ctx, (char **)&pek_id, &pek_id_size);
        if (!status) {
            memcpy(conf_dyn_file->pek_id, pek_id, pek_id_size);
            conf_dyn_file->pek_id_size = pek_id_size;

            status = write_dyn_conf(conf_dyn_file->pek_id, pek_id_size);
            if (status) {
                sedcli_printf(LOG_ERR, "Error while updating sedcli dynamic config file.\n");
                goto deinit;
            }
        } else {
            sedcli_printf(LOG_ERR, "Can't create PEK from KMIP.\n");
            goto deinit;
        }
    }

    status = sed_kmip_get_platform_key(ctx, conf_dyn_file->pek_id, conf_dyn_file->pek_id_size, (char **)&pek,
        &pek_size);
    if (status) {
        sedcli_printf(LOG_ERR, "Can't get PEK from KMIP.\n");
        goto deinit;
    }

    sed_kmip_deinit(ctx);

    meta = sedcli_metadata_alloc_buffer();
    if (!meta) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        status = -ENOMEM;
        goto deinit;
    }

    sedcli_metadata_init(meta, conf_dyn_file->pek_id_size, IV_SIZE, SED_KMIP_KEY_LEN, TAG_SIZE);

    pek_id = sedcli_meta_get_pek_id_addr(meta);
    iv = sedcli_meta_get_iv_addr(meta);
    enc_dek = sedcli_meta_get_enc_dek_addr(meta);
    tag = sedcli_meta_get_tag_addr(meta);

    auth_len = (enc_dek - (uint8_t *)meta);

    memcpy(pek_id, conf_dyn_file->pek_id, conf_dyn_file->pek_id_size);

    status = get_random_bytes(iv, IV_SIZE);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while generating IV.\n");
        goto deinit;
    }

    status = get_random_bytes((uint8_t *)key[0].key, SED_KMIP_KEY_LEN);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while generating DEK.\n");
        goto deinit;
    }
    key[0].len = SED_KMIP_KEY_LEN;

    status = encrypt_dek((uint8_t *)key[0].key, key[0].len, (uint8_t *)meta, auth_len, enc_dek, SED_KMIP_KEY_LEN, pek,
        pek_size, iv, IV_SIZE, tag, TAG_SIZE);
    if (status < 0) {
        sedcli_printf(LOG_ERR, "Error while encrypting DEK.\n");
        goto deinit;
    }

    status = sed_init(&sed_dev, dev_path, false);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while initializing SED library.\n");
        goto deinit;
    }
    sedcli_printf(LOG_INFO, "SED library initialized.\n");

    status = sed_get_msid_pin(sed_dev, &key[1]);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while reading MSID PIN.\n");
        goto deinit;
    }

    status = sed_activate_sp(sed_dev, &key[1], opal_uid[OPAL_ADMIN_SP_UID], opal_uid[OPAL_SID_UID], opal_uid[OPAL_LOCKING_SP_UID], NULL, (uint8_t)-1, NULL);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while activating Locking SP.\n");
        goto deinit;
    }
    sedcli_printf(LOG_INFO, "Locking SP activated.\n");

    status = sed_ds_add_anybody_get(sed_dev, &key[1]);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while updating permissions for anybody authority.\n");
        goto deinit;
    }
    sedcli_printf(LOG_INFO, "Datastore permission updated.\n");

    status = sed_ds_write(sed_dev, SED_ADMIN1, &key[1], (uint8_t *)meta, SEDCLI_METADATA_SIZE, 0);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while storing sedcli metadata in datastore.\n");
        goto deinit;
    }
    sedcli_printf(LOG_INFO, "Metadata stored in datastore.\n");

    status = sed_set_password(sed_dev, opal_uid[OPAL_ADMIN_SP_UID], opal_uid[OPAL_SID_UID], &key[1], opal_uid[OPAL_SID_UID], &key[0]);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while updating pin for SID authority.\n");
        goto deinit;
    }
    sedcli_printf(LOG_INFO, "Updated pin for SID authority.\n");

    status = sed_set_password(sed_dev, opal_uid[OPAL_LOCKING_SP_UID], opal_uid[OPAL_ADMIN1_UID], &key[1], opal_uid[OPAL_ADMIN1_UID], &key[0]);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while updating pin for Admin1 authority\n");
        goto deinit;
    }
    sedcli_printf(LOG_INFO, "Updated pin for Admin1 authority.\n");

    status = sed_setup_global_range(sed_dev, &key[0], 1, 1);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while setting up global locking range\n");
        goto deinit;
    }
    sedcli_printf(LOG_INFO, "Global Locking Range setup completed.\n");

    status = programmatic_reset_enable(sed_dev, &key[0]);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while enabling programmatic reset\n");
        goto deinit;
    }
    sedcli_printf(LOG_INFO, "Programmatic reset enabled.\n");

deinit:
    sed_kmip_deinit(ctx);

    sed_deinit(sed_dev);

    sedcli_metadata_free_buffer(meta);

    if (pek)
        free(pek);

    if (ctx)
        free(ctx);

    if (key)
        free_locked_buffer(key, 2 * sizeof(*key));

    return status;
}

static int read_key_from_datastore(struct sed_device *sed_dev, struct sed_key *dek_key)
{
    int status = read_stat_config(conf_stat_file);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while reading sedcli config file.\n");
        return -1;
    }

    int ret = 0;

    uint8_t *pek = NULL;
    struct sedcli_metadata *meta = NULL;

    struct sed_kmip_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        ret = -ENOMEM;
        goto deinit;
    }
    memset(ctx, 0, sizeof(struct sed_kmip_ctx));

    meta = sedcli_metadata_alloc_buffer();
    if (!meta) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        ret = -ENOMEM;
        goto deinit;
    }

    status = sed_ds_read(sed_dev, SED_ANYBODY, NULL, (uint8_t *)meta, SEDCLI_METADATA_SIZE, 0);
    if (status) {
        sedcli_printf(LOG_ERR, "Can't read sedcli metadata from datastore.\n");
        ret = status;
        goto deinit;
    }

    status = sed_kmip_init(ctx, conf_stat_file->kmip_ip,
                   conf_stat_file->kmip_port,
                   conf_stat_file->client_cert_path,
                   conf_stat_file->client_key_path,
                   conf_stat_file->ca_cert_path);

    if (status == -1) {
        sedcli_printf(LOG_ERR, "Can't initialize KMIP connection.\n");
        ret = KMIP_FAILURE;
        goto deinit;
    }

    status = sed_kmip_connect(ctx);
    if (status) {
        sedcli_printf(LOG_ERR, "Can't connect to KMIP.\n");
        ret = KMIP_FAILURE;
        goto deinit;
    }

    int pek_size = 0;
    uint8_t *pek_id = sedcli_meta_get_pek_id_addr(meta);
    uint32_t pek_id_size = sedcli_meta_get_pek_id_size(meta);
    status = sed_kmip_get_platform_key(ctx, (char *)pek_id, pek_id_size, (char **)&pek, &pek_size);
    if (status) {
        sedcli_printf(LOG_ERR, "Can't get PEK from KMIP.\n");
        ret = KMIP_FAILURE;
        goto deinit;
    }

    uint8_t *iv = sedcli_meta_get_iv_addr(meta);
    uint32_t iv_size = sedcli_meta_get_iv_size(meta);
    uint8_t *enc_dek = sedcli_meta_get_enc_dek_addr(meta);
    uint32_t enc_dek_size = sedcli_meta_get_enc_dek_size(meta);
    uint8_t *tag = sedcli_meta_get_tag_addr(meta);
    uint32_t tag_size = sedcli_meta_get_tag_size(meta);
    int auth_len = (enc_dek - (uint8_t *)meta);
    status = decrypt_dek(enc_dek, enc_dek_size, (uint8_t *)meta, auth_len, (uint8_t *)(dek_key->key), SED_KMIP_KEY_LEN,
        pek, pek_size, iv, iv_size, tag, tag_size);
    if (status != SED_KMIP_KEY_LEN) {
        sedcli_printf(LOG_ERR, "Error while decrypting DEK key.\n");
        ret = KMIP_FAILURE;
        goto deinit;
    }

    dek_key->len = status;

deinit:
    sed_kmip_deinit(ctx);

    if (meta)
        sedcli_metadata_free_buffer(meta);

    if (pek)
        free(pek);

    if (ctx)
        free(ctx);

    return ret;
}

int get_buf_val(char* ptr, uint64_t *val)
{
    char *error;

    if (ptr[0] == '0' && ptr[1] == 'x')
        *val = strtoul(ptr, &error, 16);
    else
        *val = strtoul(ptr, &error, 10);

    if (error == &ptr[0])
        return -EINVAL;

    return SED_SUCCESS;
}

#define MAX_SET_BYTES     1024
#define SET_CMD_START_LEN 5
#define SET_CMD_END_LEN   3

static int programmatic_reset_enable(struct sed_device *sed_dev, const struct sed_key *key)
{
    // set true in ProgrammaticResetEnable column
    struct sed_opal_col_info col_info;
    col_info.type = SED_DATA_SINT;
    col_info.len = 1;
    col_info.data = (int64_t*)malloc(sizeof(int64_t));
    if (col_info.data == NULL) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        return -ENOMEM;
    }

    memset(col_info.data, 0, sizeof(int64_t));
    int64_t val = strtol("1", NULL, 10);
    memcpy(col_info.data, &val, sizeof(int64_t));

    uint8_t pre_uid[OPAL_UID_LENGTH] = {0, 0, 2, 1, 0, 3, 0, 1};

    int ret = sed_get_set_col_val(sed_dev, key, opal_uid[OPAL_ADMIN_SP_UID], opal_uid[OPAL_SID_UID], pre_uid, 8, false, &col_info);
    if (ret) {
        free(col_info.data);
        return ret;
    }

    free(col_info.data);

    // update lock on ResetWithPowerCycle 0 and Programmatic 3
    struct opal_req_item cmd_start[] = {
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
        { .type = OPAL_U64, .len = 1, .val = { .uint = 9 } },
    };

    struct opal_req_item cmd_end[] = {
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    };

    struct opal_req_item cmd[MAX_SET_BYTES + SET_CMD_START_LEN + SET_CMD_END_LEN] = { 0 };
    memcpy(cmd, cmd_start, sizeof(struct opal_req_item) * SET_CMD_START_LEN);

    struct opal_req_item cmd_buff[MAX_SET_BYTES] = { 0 };

    uint16_t item = 0;
    char temp[MAX_SET_BYTES] = {'0', 'x', 'f', '0', ' ',
                                '0', 'x', '0', '0', ' ',
                                '0', 'x', '0', '3', ' ',
                                '0', 'x', 'f', '1'};

    // parse all tokens from scanned line, separated by a ' ' space char
    char *ptr = temp;
    while (ptr != NULL) {
        uint64_t token;
        if (get_buf_val(ptr, &token))
            return -EINVAL;

        cmd_buff[item].type = OPAL_U8;
        cmd_buff[item].len = 1;
        cmd_buff[item].val.byte = token;

        if (item++ == MAX_SET_BYTES - 1)
            return -EINVAL;

        ptr = strchr(ptr, ' ');
        if (ptr != NULL)
            ptr++;
    }

    memcpy(cmd + SET_CMD_START_LEN, cmd_buff, sizeof(struct opal_req_item) * item);
    memcpy(cmd + SET_CMD_START_LEN + item, cmd_end, sizeof(struct opal_req_item) * SET_CMD_END_LEN);
    size_t cmd_len = SET_CMD_START_LEN + SET_CMD_END_LEN + item;

    uint8_t uid[OPAL_UID_LENGTH] = {0, 0, 8, 2, 0, 0, 0, 1};

    return sed_set_with_buf(sed_dev, &key[0], opal_uid[OPAL_LOCKING_SP_UID], opal_uid[OPAL_ADMIN1_UID], uid, cmd, cmd_len);
}

static int handle_get_lock_info(void)
{
    int ret = 0, status;
    struct sed_key *key = NULL; /* [0] - DEK key, [1] - key derived from password */
    struct sed_device *sed_dev = NULL;

    status = sed_init(&sed_dev, dev_path, false);
    if (status) {
        ret = KMIP_FAILURE;
        goto deinit;
    }

    key = alloc_locked_buffer(2 * sizeof(*key));
    if (!key) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        ret = -ENOMEM;
        goto deinit;
    }

    status = read_key_from_datastore(sed_dev, &key[0]);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while accessing datastore.\n");
        ret = status;
        goto deinit;
    }

    // create cols table
    struct sed_opal_col_info **cols;
    uint8_t start = 5;
    uint8_t end = 9;
    uint8_t last_col = 0;
    cols = malloc(sizeof(struct sed_opal_col_info *) * (end - start + 1));
    if (cols == NULL) {
        ret = -ENOMEM;
        goto deinit;
    }

    // get cols
    for (uint64_t i = start; i <= end && ret == SED_SUCCESS; i++) {
        struct sed_opal_col_info *col_info = malloc(sizeof(struct sed_opal_col_info));
        if (col_info == NULL) {
            ret = -ENOMEM;
            goto cleanup;
        }

        cols[last_col++] = col_info;
        memset(col_info, 0, sizeof(struct sed_opal_col_info));

        uint8_t uid[OPAL_UID_LENGTH] = {0, 0, 8, 2, 0, 0, 0, 1};

        ret = sed_get_set_col_val(sed_dev, &key[0], opal_uid[OPAL_LOCKING_SP_UID], opal_uid[OPAL_ADMIN1_UID], uid, i, true /* get */, col_info);
    }

    if (ret == SED_SUCCESS)
    {
        sedcli_printf(LOG_INFO, "Read Lock Enabled: ");
        *(uint8_t *)(cols[0]->data) == 1 ? sedcli_printf(LOG_INFO, "true\n") : sedcli_printf(LOG_INFO, "false\n");
        sedcli_printf(LOG_INFO, "Write Lock Enabled: ");
        *(uint8_t *)(cols[1]->data) == 1 ? sedcli_printf(LOG_INFO, "true\n") : sedcli_printf(LOG_INFO, "false\n");
        sedcli_printf(LOG_INFO, "Read Lock: ");
        *(uint8_t *)(cols[2]->data) == 1 ? sedcli_printf(LOG_INFO, "true\n") : sedcli_printf(LOG_INFO, "false\n");
        sedcli_printf(LOG_INFO, "Write Lock: ");
        *(uint8_t *)(cols[3]->data) == 1 ? sedcli_printf(LOG_INFO, "true\n") : sedcli_printf(LOG_INFO, "false\n");
    }

cleanup:
    if (cols) {
        for (uint8_t i = 0; i < last_col; i++)
            free_col_info(cols[i]);

        free(cols);
    }

deinit:
    sed_deinit(sed_dev);

    free(key);

    return ret;
}

static int handle_lock_unlock(void)
{
    struct sed_key *dek = alloc_locked_buffer(sizeof(*dek));
    if (!dek) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        return -ENOMEM;
    }

    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, dev_path, false);
    if (ret) {
        sedcli_printf(LOG_ERR, "Error in initializing the dev: %s\n", dev_path);
        goto deinit;
    }

    int status = read_key_from_datastore(dev, dek);
    if (status) {
        sedcli_printf(LOG_ERR, "Error while decrypting DEK key.\n");
        ret = KMIP_FAILURE;
        goto deinit;
    }

    ret = sed_lock_unlock(dev, dek, opal_uid[OPAL_ADMIN1_UID], 0, false, opts->access_type);
    if (ret)
        sedcli_printf(LOG_ERR, "Error while unlocking drive.\n");

deinit:
    if (dek)
        free_locked_buffer(dek, sizeof(*dek));

    sed_deinit(dev);

    return ret;
}

int main(int argc, char *argv[])
{
    // Set CLI to KMIP, this will cause in different status handling.
    sed_cli = SED_CLI_KMIP;

    int blocked = 0, status;
    app app_values;

    app_values.name = argv[0];
    app_values.info = "<command> [option...]";
    app_values.title = "sedcli-kmip";
    app_values.doc = "";
    app_values.man = "sedcli-kmip";
    app_values.block = blocked;

    opts = alloc_locked_buffer(sizeof(*opts));
    if (!opts) {
        sedcli_printf(LOG_ERR, "Failed to allocate memory.\n");
        return -ENOMEM;
    }

    status = args_parse(&app_values, sedcli_commands, argc, argv);

    free_locked_buffer(opts, sizeof(*opts));

    return status;
}
