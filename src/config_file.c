/*
 * Copyright (C) 2020, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config_file.h"
#include "lib/sedcli_log.h"

#define SEDCLI_CONF_DELIM "="

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

enum {
    KMIP_IP = 0,
    KMIP_PORT,
    CLIENT_CERT,
    CLIENT_KEY,
    CA_CERT,
    UNDEFINED
};

enum {
    PEK_ID = 0
};

static char *line_prefix[] = {
    [KMIP_IP] = "kmip_ip",
    [KMIP_PORT] = "kmip_port",
    [CLIENT_CERT] = "client_cert",
    [CLIENT_KEY] = "client_key",
    [CA_CERT] = "ca_cert",
};

static char *line_dynamic_prefix[] = {
    [PEK_ID] = "pek_id"
};

static int get_line_type(char *line, int char_no)
{
    int i, size;

    size = ARRAY_SIZE(line_prefix);

    for (i = 0; i < size; i++)
        if (strncmp(line_prefix[i], line, char_no) == 0)
            return i;

    return UNDEFINED;
}

static int get_line_dynamic_type(char *line, int char_no)
{
    int i, size;

    size = ARRAY_SIZE(line_dynamic_prefix);

    for (i = 0; i < size; i++)
        if (strncmp(line_dynamic_prefix[i], line, char_no) == 0)
            return i;

    return UNDEFINED;
}

static int process_line_stat(struct sedcli_stat_conf *conf, char *line, int len)
{
    int offset, type, bytes_no, status = 0;
    char *found;

    found = strstr(line, SEDCLI_CONF_DELIM);
    if (found == NULL)
        return -1;

    /* Calculate len and move pointer after delimiter */
    offset = found - line;
    found++;

    /* Calculate len of configuration option value */
    bytes_no = len - offset - 1;

    /* Eliminate newline character if present */
    if (line[len - 1] == '\n')
        bytes_no--;

    type = get_line_type(line, offset);
    switch (type) {
    case KMIP_IP:
        if (bytes_no <= MAX_IP_LEN)
            memcpy(conf->kmip_ip, found, bytes_no);
        else
            status = -EINVAL;
        break;
    case KMIP_PORT:
        if (bytes_no <= MAX_PORT_LEN)
            memcpy(conf->kmip_port, found, bytes_no);
        else
            status = -EINVAL;
        break;
    case CLIENT_CERT:
        if (bytes_no <= MAX_PATH_LEN)
            memcpy(conf->client_cert_path, found, bytes_no);
        else
            status = -EINVAL;
        break;
    case CLIENT_KEY:
        if (bytes_no <= MAX_PATH_LEN)
            memcpy(conf->client_key_path, found, bytes_no);
        else
            status = -EINVAL;
        break;
    case CA_CERT:
        if (bytes_no <= MAX_PATH_LEN)
            memcpy(conf->ca_cert_path, found, bytes_no);
        else
            status = -EINVAL;
        break;
    default:
        return -1;
    }

    return status;
}

static int process_line_dyn(struct sedcli_dyn_conf *conf, char *line, int len)
{
    char *found = strstr(line, SEDCLI_CONF_DELIM);
    if (found == NULL)
        return -1;

    /* Calculate len and move pointer after delimiter */
    int offset = found - line;
    found++;

    /* Calculate len of configuration option value */
    int bytes_no = len - offset - 1;

    /* Eliminate newline character if present */
    if (line[len - 1] == '\n')
        bytes_no--;

    int type = get_line_dynamic_type(line, offset);
    switch (type) {
    case PEK_ID:
        if (bytes_no <= MAX_PEK_ID_LEN) {
            memcpy(conf->pek_id, found, bytes_no);
            SEDCLI_DEBUG_PARAM("pek_id: %s", found);
            if (bytes_no < MAX_PEK_ID_LEN)
                conf->pek_id[bytes_no] = 0;
            conf->pek_id[MAX_PEK_ID_LEN - 1] = '\0';
            conf->pek_id_size = strlen(conf->pek_id);
        } else {
            conf->pek_id_size = 0;
            return -EINVAL;
        }
        break;

    default:
        return 0;
    }

    return 0;
}

int read_stat_config(struct sedcli_stat_conf *conf)
{
    char *conf_file = SEDCLI_DEF_STAT_CONFIG_FILE;
    FILE *file = fopen(conf_file, "r");
    if (file == NULL) {
        conf_file = SEDCLI_BKP_STAT_CONFIG_FILE;
        file = fopen(conf_file, "r");
        if (file == NULL)
            return -ENOENT;
    }

    int status = 0;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        /* Ignore comment lines */
        if (line[0] != '#' && line[0] != '\n') {
            status = process_line_stat(conf, line, read);
            if (status != 0) {
                SEDCLI_DEBUG_PARAM("error %d while processing line %s\n", status, line);
                status = -EINVAL;
                break;
            }
        }
    }

    free(line);

    fclose(file);

    return status;
}

int read_dyn_config(struct sedcli_dyn_conf *conf)
{
    char *conf_file = SEDCLI_DEF_DYN_CONFIG_FILE;
    SEDCLI_DEBUG_PARAM("Opening config file: %s\n", conf_file);
    FILE *file = fopen(conf_file, "r");
    if (file == NULL) {
        conf_file = SEDCLI_BKP_DYN_CONFIG_FILE;
        file = fopen(conf_file, "r");
        if (file == NULL)
            return -ENOENT;
    }

    int status = 0;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        /* Ignore comment lines */
        if (line[0] != '#' && line[0] != '\n') {
            size_t line_len = strlen(line);
            if (line_len == 0 || line_len > 256) {
                SEDCLI_DEBUG_PARAM("error %d while processing line %s - length.\n", status, line);
                status = -EINVAL;
                break;
            } else {
                SEDCLI_DEBUG_PARAM("Processing line: %s", line);
                status = process_line_dyn(conf, line, read);
                if (status != 0) {
                    SEDCLI_DEBUG_PARAM("error %d while processing line %s.\n", status, line);
                    status = -EINVAL;
                    break;
                }
            }
        }
    }

    free(line);

    fclose(file);

    return status;
}

int write_dyn_conf(const char *data, int data_size)
{
    FILE *file;
    char *conf_file = SEDCLI_DEF_DYN_CONFIG_FILE;
    int bytes_written;

    file = fopen(conf_file, "w+");
    if (file == NULL) {
        conf_file = SEDCLI_BKP_DYN_CONFIG_FILE;

        file = fopen(conf_file, "w+");

        if (file == NULL)
            return -ENOENT;
    }

    fwrite("pek_id=", 7, 1, file);
    bytes_written = fwrite(data, 1, data_size, file);
    fwrite("\n", 1, 1, file);

    fclose(file);

    if (bytes_written != data_size)
        return -ENOSPC;

    return 0;
}
