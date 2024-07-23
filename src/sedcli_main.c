/*
 * Copyright (C) 2018-2019, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h" // include first

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>

#include <sys/syslog.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "libsed.h"
#include "lib/nvme_pt_ioctl.h"

#include "argp.h"
#include "sedcli_util.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define SEDCLI_TITLE "Self-Encrypting Drive command line interface (sedcli)"
#define PYRITE_V100 "v1.00"
#define PYRITE_V200 "v2.00"

extern sedcli_printf_t sedcli_printf;

extern uint8_t opal_uid[][OPAL_UID_LENGTH];

static int host_prop_opts_parse(char *opt, char **arg);
static int discovery_opts_parse(char *opt, char **arg);
static int parse_tper_state_opts_parse(char *opt, char **arg);
static int ownership_opts_parse(char *opt, char **arg);
static int activate_sp_opts_parse(char*opt, char **arg);
static int revert_opts_parse(char *opt, char **arg);
static int revert_lsp_opts_parse(char *opt, char **arg);
static int lock_unlock_opts_parse(char *opt, char **arg);
static int setup_global_range_opts_parse(char *opt, char **arg);
static int set_password_opts_parse(char *opt, char **arg);
static int mbr_control_opts_parse(char *opt, char **arg);
static int write_mbr_opts_parse(char *opt, char **arg);
static int block_sid_opts_parse(char *opt, char **arg);
static int add_user_lr_opts_parse(char *opt, char **arg);
static int setup_lr_opts_parse(char *opt, char **arg);
static int enable_user_opts_parse(char *opt, char **arg);
static int genkey_opts_parse(char *opt, char **arg);
static int erase_opts_parse(char *opt, char **arg);
static int assign_opts_parse(char *opt, char **arg);
static int deassign_opts_parse(char *opt, char **arg);
static int table_next_opts_parse(char *opt, char **arg);
static int get_object_opts_parse(char *opt, char **arg);
static int set_object_opts_parse(char *opt, char **arg);
static int stack_reset_opts_parse(char *opt, char **arg);
static int reactivate_sp_opts_parse(char *opt, char **arg);
static int tper_reset_opts_parse(char *opt, char **arg);
static int get_byte_table_opts_parse(char *opt, char **arg);
static int set_byte_table_opts_parse(char *opt, char **arg);
static int get_acl_opts_parse(char *opt, char **arg);
static int start_session_opts_parse(char *opt, char **arg);
static int end_session_opts_parse(char *opt, char **arg);

static int host_prop_handle(void);
static int discovery_handle(void);
static int parse_tper_state_handle(void);
static int ownership_handle(void);
static int version_handle(void);
static int help_handle(void);
static int activate_sp_handle(void);
static int revert_handle(void);
static int revert_lsp_handle(void);
static int lock_unlock_handle(void);
static int setup_global_range_handle(void);
static int set_password_handle(void);
static int mbr_control_handle(void);
static int write_mbr_handle(void);
static int block_sid_handle(void);
static int add_user_lr_handle(void);
static int setup_lr_handle(void);
static int enable_user_handle(void);
static int genkey_handle(void);
static int erase_handle(void);
static int assign_handle(void);
static int deassign_handle(void);
static int table_next_handle(void);
static int stack_reset_handle(void);
static int get_object_handle(void);
static int set_object_handle(void);
static int reactivate_sp_handle(void);
static int tper_reset_handle(void);
static int get_byte_table_handle(void);
static int set_byte_table_handle(void);
static int get_acl_handle(void);
static int start_session_handle(void);
static int end_session_handle(void);

static int read_password(struct sed_key *, bool);

#define D_DEVICE_PARAM_REQUIRED \
    {'d', "device", "Device node e.g. /dev/nvme0n1", 1, "DEVICE", CLI_OPTION_REQUIRED}
#define F_FORMAT_PARAM_OPTIONAL \
    {'f', "format", "Output format: normal/udev", 1, "FMT", CLI_OPTION_OPTIONAL}
#define A_AUTHORITY_PARAM_REQUIRED \
    {'a', "authority", "String specifying the authority, can be in UID format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_REQUIRED}
#define A_AUTHORITY_PARAM_OPTIONAL \
    {'a', "authority", "String specifying the authority, can be in UID format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_OPTIONAL}
#define U_USER_PARAM_REQUIRED \
    {'u', "user", "String specifying the user, can be in UID format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_REQUIRED}
#define N_KEEP_GLOBAL_RANGE_KEY_PARAM_OPTIONAL \
    {'n', "keep-global-range-key", "Perform non-destructive revert on TPer (i.e. keep the user data intact even after revert)", 0, "FLAG", CLI_OPTION_OPTIONAL}
#define L_LOCKING_RANGE_PARAM_OPTIONAL \
    {'l', "locking-range", "Locking Range: 1..9", 1, "NUM", CLI_OPTION_OPTIONAL}
#define L_LOCKING_RANGE_UID_PARAM_REQUIRED \
    {'l', "locking-range", "Locking Range in UID format: 00-01-02-03-04-05-06-07", 1, "NUM", CLI_OPTION_REQUIRED}
#define S_SUM_PARAM_OPTIONAL \
    {'s', "sum", "Single User Mode", 0, "FLAG", CLI_OPTION_OPTIONAL}
#define T_ACCESS_TYPE_PARAM_REQUIRED \
    {'t', "access-type", "String specifying access type to the data on drive. Allowed values: RO/WO/RW/LK", 1, "FMT", CLI_OPTION_REQUIRED}
#define R_RLE_PARAM_OPTIONAL \
    {'r', "rle", "Enable/Disable Read Lock Enable(RLE) bit. Allowed values: enabled/disabled.", 1, "FMT", CLI_OPTION_OPTIONAL}
#define W_WLE_PARAM_OPTIONAL \
    {'w', "wle", "Enable/Disable Write Lock Enable(WLE) bit. Allowed values: enabled/disabled.", 1, "FMT", CLI_OPTION_OPTIONAL}
#define E_MBR_ENABLE_PARAM_OPTIONAL \
    {'e', "enable", "Set/Unset MBR Enable column. Allowed values: TRUE/FALSE", 1, "FMT", CLI_OPTION_OPTIONAL}
#define M_MBR_DONE_PARAM_OPTIONAL \
    {'m', "done", "Set/Unset MBR Done column. Allowed values: TRUE/FALSE", 1, "FMT", CLI_OPTION_OPTIONAL}
#define F_FILE_PARAM_REQUIRED \
    {'f', "file", "File path to load data from", 1, "FMT", CLI_OPTION_REQUIRED}
#define O_OFFSET_PARAM_OPTIONAL \
    {'o', "offset", "Enter the offset (by default 0)", 1, "NUM", CLI_OPTION_OPTIONAL}
#define R_HWRESET_PARAM_REQUIRED \
    {'r', "hwreset", "Clear events by setting Hardware Reset flag. Allowed values: 1/0", 1, "FMT", CLI_OPTION_REQUIRED}
#define N_NAMESPACE_PARAM_REQUIRED \
    {'n', "namespace", "Number specifying Namespace ID", 1, "NUM", CLI_OPTION_REQUIRED}
#define K_KEEP_NS_GLOBAL_RANGE_KEY_PARAM_OPTIONAL \
    {'k', "keep-ns-global-range-key", "Specifies whether the media encryption key is eradicated when a locking object is deassigned", 0, "FLAG", CLI_OPTION_OPTIONAL}
#define P_SP_PARAM_REQUIRED \
    {'p', "sp", "Security provider for session to be opened: admin_sp/locking_sp, can be in UID format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_REQUIRED}
#define P_SP_PARAM_OPTIONAL \
    {'p', "sp", "Security provider for session to be opened: admin_sp/locking_sp, can be in UID format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_OPTIONAL}
#define T_TARGET_SP_PARAM_OPTIONAL \
    {'g', "target-sp", "Target security provider: admin_sp/locking_sp, can be in UID format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_OPTIONAL}
#define I_UID_PARAM_REQUIRED \
    {'i', "uid", "String specyfying UID in format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_REQUIRED}
#define I_INVOKING_UID_PARAM_REQUIRED \
    {'i', "invoking-uid", "String specyfying UID in format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_REQUIRED}
#define M_METHOD_UID_PARAM_REQUIRED \
    {'m', "method-uid", "String specyfying UID in format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_REQUIRED}
#define W_WHERE_PARAM_OPTIONAL \
    {'w', "where", "Row to begin in UID format: 00-01-02-03-04-05-06-07", 1, "FMT", CLI_OPTION_OPTIONAL}
#define C_COUNT_PARAM_OPTIONAL \
    {'c', "count", "Number of rows to iterate through.", 1, "NUM", CLI_OPTION_OPTIONAL}
#define S_START_PARAM_REQUIRED \
    {'s', "start", "Number of row/column to start with", 1, "NUM", CLI_OPTION_REQUIRED}
#define E_END_PARAM_REQUIRED \
    {'e', "end", "Number of row/column to end with", 1, "NUM", CLI_OPTION_REQUIRED}
#define R_ROW_PARAM_REQUIRED \
    {'r', "row", "Number of row to set", 1, "NUM", CLI_OPTION_REQUIRED}
#define T_TYPE_PARAM_OPTIONAL \
    {'t', "type", "Type of the data", 1, "FMT", CLI_OPTION_OPTIONAL}
#define V_VALUE_PARAM_OPTIONAL \
    {'v', "value", "Value to be set", 1, "NUM", CLI_OPTION_OPTIONAL}
#define V_VALUE_PARAM_REQUIRED \
    {'v', "value", "Value to be set", NUM_HOST_PROPS, "NUM", CLI_OPTION_REQUIRED}
#define B_BUFF_PARAM_OPTIONAL \
    {'b', "buffer", "Buffer to be set is going to be provided", 0, "FLAG", CLI_OPTION_OPTIONAL}
#define B_RANGE_START_PARAM_REQUIRED \
    {'b', "range-start", "Range Start", 1, "NUM", CLI_OPTION_REQUIRED}
#define Z_RANGE_LENGTH_PARAM_REQUIRED \
    {'z', "range-length", "Range Length", 1, "NUM", CLI_OPTION_REQUIRED}
#define B_RANGE_START_PARAM_OPTIONAL \
    {'b', "range-start", "Range Start", 1, "NUM", CLI_OPTION_OPTIONAL}
#define Z_RANGE_LENGTH_PARAM_OPTIONAL \
    {'z', "range-length", "Range Length", 1, "NUM", CLI_OPTION_OPTIONAL}
#define L_LOCKING_RANGE_UIDS_PARAM_OPTIONAL \
    {'l', "locking-ranges", "Locking Range in UID format: 00-01-02-03-04-05-06-07, separated by a comma, can be set to 'none'", 1, "NUM", CLI_OPTION_OPTIONAL}
#define R_RANGE_START_LENGTH_POLICY_OPTIONAL \
    {'r', "range-start-length-policy", "Range Start Length policy", 1, "NUM", CLI_OPTION_OPTIONAL}
#define I_ADMIN1_PIN_OPTIONAL \
    {'i', "admin1-pin", "Password to set Admin1 PIN to, can be set to 'none'", 1, "FMT", CLI_OPTION_OPTIONAL}
#define T_DATASTORE_TABLE_SIZES_OPTIONAL \
    {'t', "datastore-table-sizes", "DataStore Table sizes separated by a comma", 1, "FMT", CLI_OPTION_OPTIONAL}
#define A_PROP_PARAM_REQUIRED \
    {'p', "property", "String specifying the property to be set", NUM_HOST_PROPS, "FMT", CLI_OPTION_REQUIRED}
#define E_PUBLIC_EXPONENT_PARAM_OPTIONAL \
    {'e', "public-exponent", "Public exponent to be used when the method is invoked on a C_RSA object", 1, "NUM", CLI_OPTION_OPTIONAL}
#define L_PIN_LENGTH_PARAM_OPTIONAL \
    {'l', "pin-length", "For method invoked on a C_PIN object, a new value with PinLength characters is stored in Password column", 1, "NUM", CLI_OPTION_OPTIONAL}
#define C_COM_ID_PARAM_OPTIONAL \
    {'c', "com-id", "ComID on which Stack Reset request will be send", 1, "NUM", CLI_OPTION_OPTIONAL}
#define E_EXTENDED_COM_ID_PARAM_OPTIONAL \
    {'e', "extended-com-id", "Value for Extended ComID filed in Stack Reset request", 1, "NUM", CLI_OPTION_OPTIONAL}
#define H_HSN_PARAM_PARAM_REQUIRED \
    {'h', "hsn", "HSN parameter for end-session command.", 1, "NUM", CLI_OPTION_REQUIRED}
#define T_TSN_PARAM_PARAM_REQUIRED \
    {'t', "tsn", "TSN parameter for end-session command.", 1, "NUM", CLI_OPTION_REQUIRED}
#define X_PWD_IS_HEXENCODED_OPTIONAL \
    {'x', "hex", "Treat read passwords as hex-encoded strings.", 0, "FLAG", CLI_OPTION_OPTIONAL}

static cli_option host_prop_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    A_PROP_PARAM_REQUIRED,
    V_VALUE_PARAM_REQUIRED,
    {0}
};

static cli_option discovery_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    F_FORMAT_PARAM_OPTIONAL,
    {0}
};

static cli_option parse_tper_state_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    {0}
};

static cli_option ownership_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option activate_sp_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    T_TARGET_SP_PARAM_OPTIONAL,
    L_LOCKING_RANGE_UIDS_PARAM_OPTIONAL,
    R_RANGE_START_LENGTH_POLICY_OPTIONAL,
    T_DATASTORE_TABLE_SIZES_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option revert_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_OPTIONAL,
    A_AUTHORITY_PARAM_REQUIRED,
    T_TARGET_SP_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option revert_lsp_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    N_KEEP_GLOBAL_RANGE_KEY_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option lock_unlock_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    L_LOCKING_RANGE_PARAM_OPTIONAL,
    S_SUM_PARAM_OPTIONAL,
    T_ACCESS_TYPE_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option setup_global_range_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    R_RLE_PARAM_OPTIONAL,
    W_WLE_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option set_password_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    U_USER_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option mbr_control_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    E_MBR_ENABLE_PARAM_OPTIONAL,
    M_MBR_DONE_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option write_mbr_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    F_FILE_PARAM_REQUIRED,
    O_OFFSET_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option block_sid_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    R_HWRESET_PARAM_REQUIRED,
    {0}
};

static cli_option add_user_lr_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    T_ACCESS_TYPE_PARAM_REQUIRED,
    L_LOCKING_RANGE_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option setup_lr_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    L_LOCKING_RANGE_UID_PARAM_REQUIRED,
    R_RLE_PARAM_OPTIONAL,
    W_WLE_PARAM_OPTIONAL,
    B_RANGE_START_PARAM_REQUIRED,
    Z_RANGE_LENGTH_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option genkey_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    I_UID_PARAM_REQUIRED,
    E_PUBLIC_EXPONENT_PARAM_OPTIONAL,
    L_PIN_LENGTH_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option erase_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    L_LOCKING_RANGE_UID_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option enable_user_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    U_USER_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option assign_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    N_NAMESPACE_PARAM_REQUIRED,
    B_RANGE_START_PARAM_OPTIONAL,
    Z_RANGE_LENGTH_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option deassign_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    I_UID_PARAM_REQUIRED,
    K_KEEP_NS_GLOBAL_RANGE_KEY_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option table_next_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    I_UID_PARAM_REQUIRED,
    W_WHERE_PARAM_OPTIONAL,
    C_COUNT_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option get_acl_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    I_INVOKING_UID_PARAM_REQUIRED,
    M_METHOD_UID_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option reactivate_sp_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    T_TARGET_SP_PARAM_OPTIONAL,
    L_LOCKING_RANGE_UIDS_PARAM_OPTIONAL,
    R_RANGE_START_LENGTH_POLICY_OPTIONAL,
    T_DATASTORE_TABLE_SIZES_OPTIONAL,
    I_ADMIN1_PIN_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option get_object_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    I_UID_PARAM_REQUIRED,
    S_START_PARAM_REQUIRED,
    E_END_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option set_object_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    I_UID_PARAM_REQUIRED,
    R_ROW_PARAM_REQUIRED,
    T_TYPE_PARAM_OPTIONAL,
    V_VALUE_PARAM_OPTIONAL,
    B_BUFF_PARAM_OPTIONAL,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option stack_reset_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    C_COM_ID_PARAM_OPTIONAL,
    E_EXTENDED_COM_ID_PARAM_OPTIONAL,
    {0}
};

static cli_option tper_reset_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    {0}
};

static cli_option get_byte_table_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    I_UID_PARAM_REQUIRED,
    S_START_PARAM_REQUIRED,
    E_END_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option set_byte_table_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    I_UID_PARAM_REQUIRED,
    S_START_PARAM_REQUIRED,
    E_END_PARAM_REQUIRED,
    F_FILE_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option start_session_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    P_SP_PARAM_REQUIRED,
    A_AUTHORITY_PARAM_REQUIRED,
    X_PWD_IS_HEXENCODED_OPTIONAL,
    {0}
};

static cli_option end_session_opts[] = {
    D_DEVICE_PARAM_REQUIRED,
    H_HSN_PARAM_PARAM_REQUIRED,
    T_TSN_PARAM_PARAM_REQUIRED,
    {0}
};

#define CMD_OPTS(function) function ## _opts
#define CMD_OPTS_PARSE(function) function ## _opts_parse
#define CMD_HANDLE(function) function ## _handle
#define CMD_FN_PTRS(function) \
    .options = CMD_OPTS(function), \
    .options_parse = CMD_OPTS_PARSE(function), \
    .handle = CMD_HANDLE(function), \
    .flags = 0, \
    .help = NULL

static cli_command sedcli_commands[] = {
    {
        .name = "discovery",
        .desc = "Performs SED Opal Device discovery.",
        .long_desc = "Performs SED Opal Device discovery. Provides Level 0 and Level 1 Discovery info of the device.",
        CMD_FN_PTRS(discovery)
    },
    {
        .name = "host-prop",
        .desc = "Sets a host property.",
        .long_desc = "Sets a host property with specified pair name-value. More than one pair can be provided.",
        CMD_FN_PTRS(host_prop)
    },
    {
        .name = "start-session",
        .desc = "Starts a session.",
        .long_desc = "Starts a session.",
        CMD_FN_PTRS(start_session)
    },
    {
        .name = "end-session",
        .desc = "Ends a session with HSN and TSN parameters from start-session command.",
        .long_desc = "Ends a session.",
        CMD_FN_PTRS(end_session)
    },
    {
        .name = "parse-tper-state",
        .desc = "Parse TPer state for the Opal Device.",
        .long_desc = "Parse TPer state for the Opal Device discovery.",
        CMD_FN_PTRS(parse_tper_state)
    },
    {
        .name = "ownership",
        .desc = "Bring the Trusted Peripheral (TPer) out of a factory setting.",
        .long_desc = "Take ownership operation updates password for SID authority in Admin SP.",
        CMD_FN_PTRS(ownership)
    },
    {
        .name = "activate-sp",
        .desc = "Activate SP.",
        .long_desc = "Activate SP if in Manufactured-Inactive state.",
        CMD_FN_PTRS(activate_sp)
    },
    {
        .name = "revert",
        .desc = "Revert Trusted Peripheral (TPer) to factory State. *THIS WILL ERASE ALL YOUR DATA*.",
        .long_desc = "TPer is reverted back to manufactured-inactive state.",
        CMD_FN_PTRS(revert)
    },
    {
        .name = "revert-lsp",
        .desc = "Issues the Revert with Locking SP and given authority.",
        .long_desc = "Issues the Revert with Locking SP and given authority with optional parameter keep-global-range-key\n"
                     "   to keep user's data.",
        CMD_FN_PTRS(revert_lsp)
    },
    {
        .name = "setup-global-range",
        .desc = "Setup global locking range.",
        .long_desc = "Setup global locking range with Read Lock Enabled (RLE) and Write Lock Enabled (WLE) options set.",
        CMD_FN_PTRS(setup_global_range)
    },
    {
        .name = "lock-unlock",
        .desc = "Lock or unlock locking range.",
        .long_desc = "Lock or unlock locking range in Locking SP.",
        CMD_FN_PTRS(lock_unlock)
    },
    {
        .name = "set-password",
        .desc = "Change password for Admin1 authority in Locking SP.",
        .long_desc = "Update password for Admin1 authority in Locking SP.",
        CMD_FN_PTRS(set_password)
    },
    {
        .name = "mbr-control",
        .desc = "Enable/Disable MBR Shadow and Set/Unset MBR Done.",
        .long_desc = "Enable/Disable MBR Shadow and Set/Unset MBR Done.",
        CMD_FN_PTRS(mbr_control)
    },
    {
        .name = "write-mbr",
        .desc = "Write data into shadow MBR region.",
        .long_desc = "Write data into shadow MBR region.",
        CMD_FN_PTRS(write_mbr)
    },
    {
        .name = "block-sid",
        .desc = "Issue Block SID authentication command.",
        .long_desc = "Issue Block SID authentication command.",
        CMD_FN_PTRS(block_sid)
    },
    {
        .name = "add-user-to-lr",
        .desc = "Add users to the Locking Ranges.",
        .long_desc = "Add users to the Locking Ranges.",
        CMD_FN_PTRS(add_user_lr)
    },
    {
        .name = "setup-lr",
        .desc = "Setup Locking Ranges.",
        .long_desc = "Setup Locking Ranges.",
        CMD_FN_PTRS(setup_lr)
    },
    {
        .name = "genkey",
        .desc = "Replace an existing key-like object using GenKey method.",
        .long_desc = "Replace an existing key-like object using GenKey method. Invoked on a locking range will result in securely data erase.",
        CMD_FN_PTRS(genkey)
    },
    {
        .name = "erase",
        .desc = "Erase Global Range or given Locking Ranges.",
        .long_desc = "Erase Global Range or given Locking Ranges.",
        CMD_FN_PTRS(erase)
    },
    {
        .name = "enable-user",
        .desc = "Enable users for Locking Ranges.",
        .long_desc = "Enable users for Locking Ranges.",
        CMD_FN_PTRS(enable_user)
    },
    {
        .name = "assign",
        .desc = "Assign a namespace.",
        .long_desc = "Assign a namespace.",
        CMD_FN_PTRS(assign)
    },
    {
        .name = "deassign",
        .desc = "Deassign a namespace.",
        .long_desc = "Deassign a namespace.",
        CMD_FN_PTRS(deassign)
    },
    {
        .name = "table-next",
        .desc = "Iterate through an object table.",
        .long_desc = "Iterate through an object table.",
        CMD_FN_PTRS(table_next)
    },
    {
        .name = "get-acl",
        .desc = "Retrieve the contest of an access control association's ACL.",
        .long_desc = "Retrieve the contest of an access control association's ACL, which are stored in the AccessControlTable.",
        CMD_FN_PTRS(get_acl)
    },
    {
        .name = "reactivate-sp",
        .desc = "Reactivate SP.",
        .long_desc = "Reactivate SP.",
        CMD_FN_PTRS(reactivate_sp)
    },
    {
        .name = "get-object",
        .desc = "Get Object.",
        .long_desc = "Get Object.",
        CMD_FN_PTRS(get_object)
    },
    {
        .name = "set-object",
        .desc = "Set Object.",
        .long_desc = "Set Object.",
        CMD_FN_PTRS(set_object)
    },
    {
        .name = "stack-reset",
        .desc = "Stack Reset.",
        .long_desc = "Stack Reset.",
        CMD_FN_PTRS(stack_reset)
    },
    {
        .name = "tper-reset",
        .desc = "TPer Reset.",
        .long_desc = "TPer Reset.",
        CMD_FN_PTRS(tper_reset)
    },
    {
        .name = "get-byte-table",
        .desc = "Get Byte Table.",
        .long_desc = "Get Byte Table.",
        CMD_FN_PTRS(get_byte_table)
    },
    {
        .name = "set-byte-table",
        .desc = "Set Byte Table.",
        .long_desc = "Set Byte Table.",
        CMD_FN_PTRS(set_byte_table)
    },
    {
        .name = "version",
        .desc = "Print sedcli version.",
        .long_desc = "Print sedcli version.",
        .options = NULL,
        .options_parse = NULL,
        .handle = version_handle,
        .flags = 0,
        .help = NULL
    },
    {
        .name = "help",
        .desc = "Print help.",
        .long_desc = "Print help.",
        .options = NULL,
        .options_parse = NULL,
        .handle = help_handle,
        .flags = 0,
        .help = NULL
    },
    {0},
};

#define MAX_STRING 256

struct sedcli_options {
    char dev_path[PATH_MAX];
    char file_path[PATH_MAX];
    bool pwd_is_hexencoded;
    struct sed_key pwd;
    struct sed_key repeated_pwd;
    enum SED_ACCESS_TYPE access_type;
    int print_fmt;
    int enable;
    int done;
    int offset;
    bool hardware_reset;
    bool keep_global_range_key;
    bool sum;
    enum SED_FLAG_TYPE rle;
    enum SED_FLAG_TYPE wle;
    uint8_t lr;
    char lr_str[1024];

    char auth[MAX_STRING]; /* User{1..9} or Admin1 */
    uint8_t auth_uid[OPAL_UID_LENGTH];
    bool auth_is_uid;

    char user[MAX_STRING]; /* User{1..9} or Admin1 */
    uint8_t user_uid[OPAL_UID_LENGTH];
    bool user_is_uid;

    enum SED_SP_TYPE sp;
    uint8_t sp_uid[OPAL_UID_LENGTH];
    enum SED_SP_TYPE target_sp;
    uint8_t target_sp_uid[OPAL_UID_LENGTH];

    char props[NUM_HOST_PROPS][MAX_PROP_NAME_LEN];
    uint32_t values[NUM_HOST_PROPS];
    uint64_t range_length;
    uint64_t range_start;
    uint32_t nsid;
    uint8_t uid[OPAL_UID_LENGTH];
    uint8_t method[OPAL_UID_LENGTH];
    uint8_t where[OPAL_UID_LENGTH];
    uint16_t count;
    uint64_t start;
    uint64_t end;
    uint8_t type;
    union {
        uint64_t uvalue;
        int64_t svalue;
    };
    uint16_t row;
    bool buff;
    uint8_t range_start_length_policy;
    struct sed_key admin1_pwd;
    char dsts_str[1024];
    uint32_t public_exponent;
    uint32_t pin_length;
    bool keep_ns_global_range_key;
    int32_t com_id;
    uint64_t extended_com_id;
    struct sed_session session;
};

static struct sedcli_options *opts = NULL;

enum sed_print_flags {
    SED_NORMAL,
    SED_UDEV,
};

enum sed_print_flags val_output_fmt(const char *fmt)
{
    if (!fmt)
        return -EINVAL;
    if (!strncmp(fmt, "normal", MAX_INPUT))
        return SED_NORMAL;
    if (!strncmp(fmt, "udev", MAX_INPUT))
        return SED_UDEV;
    return -EINVAL;
}

int sp_param_handle(char **arg, uint8_t *sp_uid, enum SED_SP_TYPE *target_sp)
{
    if (!strncmp(arg[0], "admin_sp", MAX_INPUT)) {
        *target_sp = SED_ADMIN_SP;
        return SED_SUCCESS;
    } else if (!strncmp(arg[0], "locking_sp", MAX_INPUT)) {
        *target_sp = SED_LOCKING_SP;
        return SED_SUCCESS;
    } else if (!strncmp(arg[0], "this_sp", MAX_INPUT)) {
        *target_sp = SED_THIS_SP;
        return SED_SUCCESS;
    } else {
        if (parse_uid(arg, sp_uid) == true) {
            *target_sp = SED_UID_SP;
            return SED_SUCCESS;
        }
    }

    return -EINVAL;
}

void authority_param_handle(char **arg)
{
    if (parse_uid(arg, opts->auth_uid))
        opts->auth_is_uid = true;
    else {
        strncpy(opts->auth, arg[0], sizeof(opts->auth) - 1);
        opts->auth[sizeof(opts->auth) - 1] = '\0';
        opts->auth_is_uid = false;
    }
}

void user_param_handle(char **arg)
{
    if (parse_uid(arg, opts->user_uid))
        opts->user_is_uid = true;
    else {
        strncpy(opts->user, arg[0], sizeof(opts->user) - 1);
        opts->user[sizeof(opts->user) - 1] = '\0';
        opts->user_is_uid = false;
    }
}

uint8_t props_count = 0;
uint8_t values_count = 0;

int host_prop_opts_parse(char *opt, char **arg)
{
    char *error;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "property", MAX_INPUT)) {
        strncpy(opts->props[props_count], arg[0], sizeof(char) * MAX_PROP_NAME_LEN - 1);
        opts->props[props_count][sizeof(char) * MAX_PROP_NAME_LEN - 1] = '\0';

        props_count++;
        if (props_count - values_count > 1 ||
            props_count >= NUM_HOST_PROPS) {
            sedcli_printf(LOG_ERR, "Too many properties provided.\n");
            return -EINVAL;
        }
    } else if (!strncmp(opt, "value", MAX_INPUT)) {
        opts->values[values_count] = strtoul(arg[0], &error, 10);
        if (error == arg[0]) {
            sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
            return -EINVAL;
        }
        values_count++;
        if (values_count > props_count) {
            sedcli_printf(LOG_ERR, "Only one value for property shall be provided.\n");
            return -EINVAL;
        }
    }

    return 0;
}

int fmt_flag = 0;
int discovery_opts_parse(char *opt, char **arg)
{
    if (fmt_flag == 0) {
        /* Set the print format to Normal by default */
        opts->print_fmt = SED_NORMAL;
    }

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "format", MAX_INPUT)) {
        opts->print_fmt = val_output_fmt(arg[0]);
        fmt_flag = 1;
    }

    return 0;
}

int parse_tper_state_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    }
    return 0;
}

int ownership_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;
}

bool target_sp = false;

bool range_start_length_policy_flag = false;
int activate_sp_opts_parse(char *opt, char **arg)
{
    char *error;

    if (range_start_length_policy_flag == false)
        opts->range_start_length_policy = (uint8_t)-1;

    // for activate-sp the default target SP is Locking
    if (target_sp == false)
        opts->target_sp = SED_LOCKING_SP;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "target-sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->target_sp_uid, &opts->target_sp) != SED_SUCCESS)
            goto err_parsing;
        target_sp = true;
    }  else if (!strncmp(opt, "locking-ranges", MAX_INPUT)) {
        if (strncmp(arg[0], "none", MAX_INPUT)) {
            strncpy(opts->lr_str, arg[0], sizeof(opts->lr_str) - 1);
            opts->lr_str[sizeof(opts->lr_str) - 1] = '\0';
        }
    }  else if (!strncmp(opt, "range-start-length-policy", MAX_INPUT)) {
        opts->range_start_length_policy = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
        range_start_length_policy_flag = true;
    } else if (!strncmp(opt, "datastore-table-sizes", MAX_INPUT)) {
        strncpy(opts->dsts_str, arg[0], sizeof(opts->dsts_str) - 1);
        opts->dsts_str[sizeof(opts->dsts_str) - 1] = '\0';
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int revert_opts_parse(char *opt, char **arg)
{
    // for revert the default SP is Admin
    if (target_sp == false)
        opts->target_sp = SED_ADMIN_SP;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "target-sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->target_sp_uid, &opts->target_sp) != SED_SUCCESS)
            goto err_parsing;
        target_sp = true;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int revert_lsp_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT))
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    else if (!strncmp(opt, "authority", MAX_INPUT))
        authority_param_handle(arg);
    else if (!strncmp(opt, "keep-global-range-key", MAX_INPUT))
        opts->keep_global_range_key = 1;
    else if (!strncmp(opt, "hex", MAX_INPUT))
        opts->pwd_is_hexencoded = true;

    return 0;
}

int lock_unlock_opts_parse(char *opt, char **arg)
{
    char *error;

    if (!strncmp(opt, "device", MAX_INPUT))
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    else if (!strncmp(opt, "authority", MAX_INPUT))
        authority_param_handle(arg);
    else if (!strncmp(opt, "access-type", MAX_INPUT)) {
        int err = get_access_type(arg[0], &opts->access_type);
        if (err == -EINVAL) {
            sedcli_printf(LOG_ERR, "Incorrect lock type\n");
            return -EINVAL;
        }
    } else if (!strncmp(opt, "locking-range", MAX_INPUT)) {
        opts->lr = strtoul(arg[0], &error, 10);
        if (error == arg[0]) {
            sedcli_printf(LOG_ERR, "Failed to parse the Locking Range provided\n");
            return -EINVAL;
        }
    } else if (!strncmp(opt, "sum", MAX_INPUT))
        opts->sum = true;
    else if (!strncmp(opt, "hex", MAX_INPUT))
        opts->pwd_is_hexencoded = true;

    return 0;
}

int setup_global_range_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "rle", MAX_INPUT)) {
        if (arg[0] == NULL)
            goto err_parsing;
        if (!strncmp(arg[0], "enabled", MAX_INPUT))
            opts->rle = SED_FLAG_ENABLED;
        else if (!strncmp(arg[0], "disabled", MAX_INPUT))
            opts->rle = SED_FLAG_DISABLED;
        else
            goto err_parsing;
    } else if (!strncmp(opt, "wle", MAX_INPUT)) {
        if (arg[0] == NULL)
            goto err_parsing;
        if (!strncmp(arg[0], "enabled", MAX_INPUT))
            opts->wle = SED_FLAG_ENABLED;
        else if (!strncmp(arg[0], "disabled", MAX_INPUT))
            opts->wle = SED_FLAG_DISABLED;
        else
            goto err_parsing;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int set_password_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "user", MAX_INPUT)) {
        user_param_handle(arg);
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

static int get_mbr_flag(char *mbr_flag)
{
    if (mbr_flag == NULL) {
        sedcli_printf(LOG_ERR, "User must provide TRUE/FALSE value\n");
        return -EINVAL;
    }

    if (!strncasecmp(mbr_flag, "TRUE", 4))
        return 1;
    if (!strncasecmp(mbr_flag, "FALSE", 5))
        return 0;

    sedcli_printf(LOG_ERR, "Invalid value given by the user\n");
    return -EINVAL;
}

bool mbr_enable = false;
bool mbr_done = false;
int mbr_control_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "enable", MAX_INPUT)) {
        mbr_enable = true;
        opts->enable = get_mbr_flag(arg[0]);
        if (opts->enable < 0)
            return opts->enable;
    } else if (!strncmp(opt, "done", MAX_INPUT)) {
        mbr_done = true;
        opts->done = get_mbr_flag(arg[0]);
        if (opts->done < 0)
            return opts->done;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;
}

bool offset_flag = false;
int write_mbr_opts_parse(char *opt, char **arg)
{
    char *error;

    if (!offset_flag)
        opts->offset = 0;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "file", MAX_INPUT)) {
        strncpy(opts->file_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "offset", MAX_INPUT)) {
        opts->offset = strtol(arg[0], &error, 10);
        if (error == arg[0]) {
            sedcli_printf(LOG_ERR,
                "Failed to parse user offset from string\n");
            return -EINVAL;
        }
        offset_flag = true;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;
}

int block_sid_opts_parse(char *opt, char **arg)
{
    /* No reset Block SID upon power events */
    int hwreset_flag = 0;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "hwreset", MAX_INPUT) && strlen(arg[0]) == 1) {
        if ((arg[0][0] != '0') && (arg[0][0] != '1')) {
            return -EINVAL;
        }
        hwreset_flag = atoi(arg[0]);
        opts->hardware_reset = (hwreset_flag == 1) ? true : false;
    }

    return 0;
}

int add_user_lr_opts_parse(char *opt, char **arg)
{
    char *error;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        strncpy(opts->auth, arg[0], sizeof(opts->auth) - 1);
        opts->auth[sizeof(opts->auth) - 1] = '\0';
    } else if(!strncmp(opt, "access-type", MAX_INPUT)) {
        int err = get_access_type(arg[0], &opts->access_type);
        if (err == -EINVAL) {
            sedcli_printf(LOG_ERR, "Incorrect lock type\n");
            return -EINVAL;
        }
    } else if(!strncmp(opt, "locking-range", MAX_INPUT)) {
        opts->lr = strtoul(arg[0], &error, 10);
        if (error == arg[0]) {
            sedcli_printf(LOG_ERR, "Failed to parse the Locking Range provided.\n");
            return -EINVAL;
        }
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;
}

int setup_lr_opts_parse(char *opt, char **arg)
{
    char *error;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "locking-range", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "rle", MAX_INPUT)) {
        if (arg[0] == NULL)
            goto err_parsing;
        if (!strncmp(arg[0], "enabled", MAX_INPUT))
            opts->rle = SED_FLAG_ENABLED;
        else if (!strncmp(arg[0], "disabled", MAX_INPUT))
            opts->rle = SED_FLAG_DISABLED;
        else
            goto err_parsing;
    } else if (!strncmp(opt, "wle", MAX_INPUT)) {
        if (arg[0] == NULL)
            goto err_parsing;
        if (!strncmp(arg[0], "enabled", MAX_INPUT))
            opts->wle = SED_FLAG_ENABLED;
        else if (!strncmp(arg[0], "disabled", MAX_INPUT))
            opts->wle = SED_FLAG_DISABLED;
        else
            goto err_parsing;
    } else if (!strncmp(opt, "range-start", MAX_INPUT)) {
        opts->range_start = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
    } else if (!strncmp(opt, "range-length", MAX_INPUT)) {
        opts->range_length = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int genkey_opts_parse(char *opt, char **arg)
{
    char *error;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "public-exponent", MAX_INPUT)) {
        opts->public_exponent = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
    } else if (!strncmp(opt, "pin-length", MAX_INPUT)) {
        opts->pin_length = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int erase_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "locking-range", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int enable_user_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "user", MAX_INPUT)) {
        user_param_handle(arg);
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int assign_opts_parse(char *opt, char **arg)
{
    char *error;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "namespace", MAX_INPUT)) {
        opts->nsid = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
    } else if (!strncmp(opt, "range-start", MAX_INPUT)) {
        opts->range_start = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
    } else if (!strncmp(opt, "range-length", MAX_INPUT)) {
        opts->range_length = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int deassign_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "keep-ns-global-range-key", MAX_INPUT)) {
        opts->keep_ns_global_range_key = true;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int table_next_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "where", MAX_INPUT)) {
        if (parse_uid(arg, opts->where) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "count", MAX_INPUT)) {
        opts->count = strtol(arg[0], NULL, 10);
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int reactivate_sp_opts_parse(char *opt, char **arg)
{
    char *error;

    if (range_start_length_policy_flag == false)
        opts->range_start_length_policy = (uint8_t)-1;

    // for reactivate-sp the default target SP is This
    if (target_sp == false)
        opts->target_sp = SED_THIS_SP;

    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "target-sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->target_sp_uid, &opts->target_sp) != SED_SUCCESS)
            goto err_parsing;
        target_sp = true;
    }  else if (!strncmp(opt, "locking-ranges", MAX_INPUT)) {
        if (strncmp(arg[0], "none", MAX_INPUT)) {
            strncpy(opts->lr_str, arg[0], sizeof(opts->lr_str) - 1);
            opts->lr_str[sizeof(opts->lr_str) - 1] = '\0';
        }
    }  else if (!strncmp(opt, "range-start-length-policy", MAX_INPUT)) {
        opts->range_start_length_policy = strtoul(arg[0], &error, 10);
        if (error == arg[0])
            goto err_parsing;
        range_start_length_policy_flag = true;
    } else if (!strncmp(opt, "admin1-pin", MAX_INPUT)) {
        if (strncmp(arg[0], "none", MAX_INPUT)) {
            strncpy(opts->admin1_pwd.key, arg[0], sizeof(opts->admin1_pwd.key) - 1);
            opts->admin1_pwd.key[sizeof(opts->admin1_pwd.key) - 1] = '\0';
            opts->admin1_pwd.len = strlen(opts->admin1_pwd.key);
        }
    } else if (!strncmp(opt, "datastore-table-sizes", MAX_INPUT)) {
        strncpy(opts->dsts_str, arg[0], sizeof(opts->dsts_str) - 1);
        opts->dsts_str[sizeof(opts->dsts_str) - 1] = '\0';
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int parse_int_or_hex(char **arg, uint64_t *var)
{
    if (!strncmp(arg[0], "0x", 2))
        *var = strtoul(arg[0], NULL, 16);
    else
        *var = strtoul(arg[0], NULL, 10);

    return SED_SUCCESS;
}

int get_object_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "start", MAX_INPUT)) {
        if (parse_int_or_hex(arg, &opts->start))
            goto err_parsing;
    } else if (!strncmp(opt, "end", MAX_INPUT)) {
        if (parse_int_or_hex(arg, &opts->end))
            goto err_parsing;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int get_acl_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "invoking-uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    }
    else if (!strncmp(opt, "method-uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->method) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }
    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int set_object_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "row", MAX_INPUT)) {
        opts->row = strtoul(arg[0], NULL, 10);
    } else if (!strncmp(opt, "type", MAX_INPUT)) {
        if (!strncmp(arg[0], "sint", MAX_INPUT))
            opts->type = SED_DATA_SINT;
        else if (!strncmp(arg[0], "uint", MAX_INPUT))
            opts->type = SED_DATA_UINT;
        else
            goto err_parsing;
    } else if (!strncmp(opt, "value", MAX_INPUT)) {
        if (opts->type == SED_DATA_SINT)
            opts->svalue = strtol(arg[0], NULL, 10);
        else if (opts->type == SED_DATA_UINT)
            opts->uvalue = strtoul(arg[0], NULL, 10);
        else
            goto err_parsing;
    } else if (!strncmp(opt, "buffer", MAX_INPUT)) {
        opts->buff = true;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int stack_reset_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "com-id", MAX_INPUT)) {
        opts->com_id = strtoul(arg[0], NULL, 10);
    } else if (!strncmp(opt, "extended-com-id", MAX_INPUT)) {
        if (parse_int_or_hex(arg, (uint64_t *)&opts->extended_com_id))
            goto err_parsing;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int tper_reset_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    }

    return 0;
}

int start_session_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (sp_param_handle(arg, opts->sp_uid, &opts->sp) != SED_SUCCESS)
            goto err_parsing;
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        authority_param_handle(arg);
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int end_session_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "hsn", MAX_INPUT)) {
        opts->session.hsn = atoi(arg[0]);
        if (opts->session.hsn == 0)
            goto err_parsing;
    } else if (!strncmp(opt, "tsn", MAX_INPUT)) {
        opts->session.tsn = atoi(arg[0]);
        if (opts->session.tsn == 0)
            goto err_parsing;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int get_byte_table_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (!strncmp(arg[0], "admin_sp", MAX_INPUT))
            opts->sp = SED_ADMIN_SP;
        else if (!strncmp(arg[0], "locking_sp", MAX_INPUT))
            opts->sp = SED_LOCKING_SP;
        else
            goto err_parsing;
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        strncpy(opts->auth, arg[0], sizeof(opts->auth) - 1);
        opts->auth[sizeof(opts->auth) - 1] = '\0';
    } else if (!strncmp(opt, "uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "start", MAX_INPUT)) {
        if (parse_int_or_hex(arg, &opts->start))
            goto err_parsing;
    } else if (!strncmp(opt, "end", MAX_INPUT)) {
        if (parse_int_or_hex(arg, &opts->end))
            goto err_parsing;
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

int set_byte_table_opts_parse(char *opt, char **arg)
{
    if (!strncmp(opt, "device", MAX_INPUT)) {
        strncpy(opts->dev_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "sp", MAX_INPUT)) {
        if (!strncmp(arg[0], "admin_sp", MAX_INPUT))
            opts->sp = SED_ADMIN_SP;
        else if (!strncmp(arg[0], "locking_sp", MAX_INPUT))
            opts->sp = SED_LOCKING_SP;
        else
            goto err_parsing;
    } else if (!strncmp(opt, "authority", MAX_INPUT)) {
        strncpy(opts->auth, arg[0], sizeof(opts->auth) - 1);
        opts->auth[sizeof(opts->auth) - 1] = '\0';
    } else if (!strncmp(opt, "uid", MAX_INPUT)) {
        if (parse_uid(arg, opts->uid) == false)
            goto err_parsing;
    } else if (!strncmp(opt, "start", MAX_INPUT)) {
        if (parse_int_or_hex(arg, &opts->start))
            goto err_parsing;
    } else if (!strncmp(opt, "end", MAX_INPUT)) {
        if (parse_int_or_hex(arg, &opts->end))
            goto err_parsing;
    } else if (!strncmp(opt, "file", MAX_INPUT)) {
        strncpy(opts->file_path, arg[0], PATH_MAX - 1);
    } else if (!strncmp(opt, "hex", MAX_INPUT)) {
        opts->pwd_is_hexencoded = true;
    }

    return 0;

err_parsing:
    sedcli_printf(LOG_ERR, "Failed to parse the value provided.\n");
    return -EINVAL;
}

static void print_level0_discovery_header(struct sed_opal_level0_discovery_header *header)
{
    sedcli_printf(LOG_INFO, "\nLEVEL 0 DISCOVERY HEADER\n");
    sedcli_printf(LOG_INFO, "---------------------------\n");

    sedcli_printf(LOG_INFO, "    Length          : %d\n", be32toh(header->len));
    sedcli_printf(LOG_INFO, "    Revision        : %d\n", be32toh(header->rev));
    sedcli_printf(LOG_INFO, "    Vendor Specific : ");
    for (uint8_t i = 0; i < 32; i++) {
        if (i != 0 && i % 8 == 0)
            sedcli_printf(LOG_INFO, "\n                      ");
        sedcli_printf(LOG_INFO, "0x%02x", header->vendor_specific[i]);
        if (i % 8 < 7)
            sedcli_printf(LOG_INFO, " ");
    }
    sedcli_printf(LOG_INFO, "\n");
}

static void print_tper_feat(struct sed_tper_feat *tper)
{
    sedcli_printf(LOG_INFO, "\nSED TPER FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "------------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code          : 0x%x\n", be16toh(tper->code));
    sedcli_printf(LOG_INFO, "    Version               : %d\n", tper->rev);
    sedcli_printf(LOG_INFO, "    Length                : %d\n", tper->len);
    sedcli_printf(LOG_INFO, "    Sync Supported        : %s\n", tper->sync_supp ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Async Supported       : %s\n", tper->async_supp ? "1" : "0");
    sedcli_printf(LOG_INFO, "    ACK/NAK Supported     : %s\n", tper->ack_nak_supp ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Buffer Mgmt Supported : %s\n", tper->buff_mgmt_supp ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Streaming Supported   : %s\n", tper->stream_supp ? "1" : "0");
    sedcli_printf(LOG_INFO, "    ComID Mgmt Supported  : %s\n", tper->comid_mgmt_supp ? "1" : "0");
}

static void print_locking_feat(struct sed_locking_feat *locking)
{
    sedcli_printf(LOG_INFO, "\nSED LOCKING FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "---------------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code                   : 0x%x\n", be16toh(locking->code));
    sedcli_printf(LOG_INFO, "    Version                        : %d\n", locking->rev);
    sedcli_printf(LOG_INFO, "    Length                         : %d\n", locking->len);
    sedcli_printf(LOG_INFO, "    Locking Supported              : %s\n", locking->locking_supp ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Locking Enabled                : %s\n", locking->locking_en ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Locked                         : %s\n", locking->locked ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Media Encryption               : %s\n", locking->media_enc ? "1" : "0");
    sedcli_printf(LOG_INFO, "    MBR Enabled                    : %s\n", locking->mbr_en ? "1" : "0");
    sedcli_printf(LOG_INFO, "    MBR Done                       : %s\n", locking->mbr_done ? "1" : "0");
    sedcli_printf(LOG_INFO, "    MBR Shadowing Not Supported    : %s\n", locking->mbr_shadowing_not_supported ? "1" : "0");
    sedcli_printf(LOG_INFO, "    HW Reset for LOR/DOR Supported : %s\n", locking->mbr_hw_reset_for_lor_dor_supported ? "1" : "0");
}

static void print_geometry_feat(struct sed_geometry_feat *geo)
{
    sedcli_printf(LOG_INFO, "\nSED GEOMETRY FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "----------------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code          : 0x%x\n", be16toh(geo->code));
    sedcli_printf(LOG_INFO, "    Version               : %d\n", geo->rev);
    sedcli_printf(LOG_INFO, "    Length                : %d\n", geo->len);
    sedcli_printf(LOG_INFO, "    Alignment required    : %s\n", geo->align.align ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Logical Block Size    : %d\n", be32toh(geo->logical_blk_sz));
    sedcli_printf(LOG_INFO, "    Alignment Granularity : %ld\n", be64toh(geo->alignmnt_granularity));
    sedcli_printf(LOG_INFO, "    Lowest Aligned LBA    : %ld\n", be64toh(geo->lowest_aligned_lba));
}

static void print_datastore_feat(struct sed_datastore_feat *datastore)
{
    sedcli_printf(LOG_INFO, "\nSED DATASTORE FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "-----------------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code               : 0x%x\n", be16toh(datastore->code));
    sedcli_printf(LOG_INFO, "    Version                    : %d\n", datastore->rev);
    sedcli_printf(LOG_INFO, "    Length                     : %d\n", datastore->len);
    sedcli_printf(LOG_INFO, "    Max DataStore tables       : %d\n", be16toh(datastore->max_num_datastores));
    sedcli_printf(LOG_INFO, "    Max size DataStore tables  : %d\n", be32toh(datastore->max_total_size_datastore_tables));
    sedcli_printf(LOG_INFO, "    DataStore table size align : %d\n", be32toh(datastore->datastore_size_align));
}

static void print_opalv100_feat(struct sed_opalv100_feat *opalv100)
{
    sedcli_printf(LOG_INFO, "\nSED OPAL v1.00 FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "------------------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code     : 0x%x\n", be16toh(opalv100->code));
    sedcli_printf(LOG_INFO, "    Version          : %d\n", opalv100->rev);
    sedcli_printf(LOG_INFO, "    Length           : %d\n", opalv100->len);
    sedcli_printf(LOG_INFO, "    Base ComID       : %d\n", be16toh(opalv100->v1_base_comid));
    sedcli_printf(LOG_INFO, "    Number of ComIDs : %d\n", be16toh(opalv100->v1_comid_num));
}

static void print_opalv200_header()
{
    sedcli_printf(LOG_INFO, "\nSED OPAL v2.00 FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "------------------------------------\n");
}

static void print_ruby_header()
{
    sedcli_printf(LOG_INFO, "\nSED RUBY FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "------------------------------\n");
}

static void print_opalv200_ruby_feat(struct sed_opalv200_feat *header)
{
    sedcli_printf(LOG_INFO, "    Feature Code                      : 0x%x\n", be16toh(header->code));
    sedcli_printf(LOG_INFO, "    Feature Descriptor Version Number : %d\n", header->rev.ver.feature_descriptor_version);
    sedcli_printf(LOG_INFO, "    SSC Minor Version Number          : %d\n", header->rev.ver.ssc_minor_version);
    sedcli_printf(LOG_INFO, "    Length                            : %d\n", header->len);
    sedcli_printf(LOG_INFO, "    Base ComID                        : %d\n", be16toh(header->base_comid));
    sedcli_printf(LOG_INFO, "    Number of ComIDs                  : %d\n", be16toh(header->comid_num));
    sedcli_printf(LOG_INFO, "    Range Crossing Behavior           : %d\n", header->range_crossing ? 1: 0);
    sedcli_printf(LOG_INFO, "    Admin Authorities LSP Supported   : %d\n", be16toh(header->admin_lp_auth_num));
    sedcli_printf(LOG_INFO, "    User Authorities LSP Supported    : %d\n", be16toh(header->user_lp_auth_num));
    sedcli_printf(LOG_INFO, "    Initial PIN                       : %d\n", header->init_pin);
    sedcli_printf(LOG_INFO, "    Revert PIN                        : %d\n", header->revert_pin);
}

static void print_pyrite_header(char *version)
{
    sedcli_printf(LOG_INFO, "\nSED PYRITE %s FEATURES SUPPORTED\n", version);
    sedcli_printf(LOG_INFO, "-------------------------------------\n");
}

static void print_pyrite_feat(struct sed_pyrite_feat *pyrite_feat)
{
    sedcli_printf(LOG_INFO, "    Base ComID                      : %u\n", be16toh(pyrite_feat->base_comid));
    sedcli_printf(LOG_INFO, "    Number of ComIDs                : %u\n", be16toh(pyrite_feat->comid_num));
    sedcli_printf(LOG_INFO, "    Initial PIN                     : %u\n", pyrite_feat->init_pin);
    sedcli_printf(LOG_INFO, "    Revert PIN                      : %u\n", pyrite_feat->revert_pin);
}

static void print_drm_info(struct sed_data_rm_feat *data_rm, uint8_t index)
{
    if (data_rm->supported_drm & (1 << index)) {
        switch (index) {
        case 0:
            sedcli_printf(LOG_INFO, "       Overwrite Data Erase  ");
            break;

        case 1:
            sedcli_printf(LOG_INFO, "       Block Erase           ");
            break;

        case 2:
            sedcli_printf(LOG_INFO, "       Cryptographic Erase   ");
            break;

        case 5:
            sedcli_printf(LOG_INFO, "       Vendor Specific Erase ");
            break;

        default:
            break;
        }

        sedcli_printf(LOG_INFO, "- Data Removal Time : ");
        if (data_rm->dr_time_for_supported_drm_bits[index] == 0)
            sedcli_printf(LOG_INFO, "Not reported");
        else {
            if (be16toh(data_rm->dr_time_for_supported_drm_bits[index] == 65535))
                sedcli_printf(LOG_INFO, ">= 131068 ");
            else
                sedcli_printf(LOG_INFO, "%u " , 2 * be16toh(data_rm->dr_time_for_supported_drm_bits[index]));

            if ((data_rm->dr_time_format_for_bit & (1 << index)) == 0)
                sedcli_printf(LOG_INFO, "seconds\n");
            else
                sedcli_printf(LOG_INFO, "minutes\n");
        }
    }
}

static void print_data_rm_feat(struct sed_data_rm_feat *data_rm)
{
    sedcli_printf(LOG_INFO, "\nDATA REMOVAL MECHANISM FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "--------------------------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code                       : 0x%x\n", be16toh(data_rm->code));
    sedcli_printf(LOG_INFO, "    Version                            : %u\n", data_rm->rev);
    sedcli_printf(LOG_INFO, "    Length                             : %u\n", data_rm->len);
    sedcli_printf(LOG_INFO, "    Data Removal Operation Interrupted : %u\n", data_rm->dr_operation_interrupted ? 1 : 0);
    sedcli_printf(LOG_INFO, "    Data Removal Operation Processing  : %u\n", data_rm->dr_operation_processing  ? 1 : 0);

    sedcli_printf(LOG_INFO, "    Supported Data Removal Mechanism   :\n");
    for (uint8_t i = 0; i < DR_TIME_FOR_SUPPORTED_DRM_BITS_COUNT; i++)
        print_drm_info(data_rm, i);
}

static void print_block_sid_feat(struct sed_block_sid_feat *block_sid)
{
    sedcli_printf(LOG_INFO, "\nBLOCK SID FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "-------------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code                  : 0x%x\n", be16toh(block_sid->code));
    sedcli_printf(LOG_INFO, "    Version                       : %u\n", block_sid->rev);
    sedcli_printf(LOG_INFO, "    Length                        : %u\n", block_sid->len);
    sedcli_printf(LOG_INFO, "    SID Value State               : %u\n", block_sid->sid_valuestate ? 1 : 0);
    sedcli_printf(LOG_INFO, "    SID Blocked State             : %u\n", block_sid->sid_blockstate ? 1 : 0);
    sedcli_printf(LOG_INFO, "    LockingSp Freeze Lock Support : %u\n", block_sid->lsp_freeze_lock_support ? 1 : 0);
    sedcli_printf(LOG_INFO, "    LockingSp Freeze Lock State   : %u\n", block_sid->lsp_freeze_lock_state ? 1 : 0);
    sedcli_printf(LOG_INFO, "    Hardware Reset Flag           : %u\n", block_sid->hardware_reset ? 1 : 0);
}

static void print_sum_feat(struct sed_sum_feat *sum)
{
    sedcli_printf(LOG_INFO, "\nSED SUM FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "-----------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code                        : 0x%x\n", be16toh(sum->code));
    sedcli_printf(LOG_INFO, "    Version                             : %u\n", sum->rev);
    sedcli_printf(LOG_INFO, "    Length                              : %u\n", sum->len);
    sedcli_printf(LOG_INFO, "    Number of Locking Objects Supported : %u\n", be32toh(sum->number_of_locking_objects_supported));
    sedcli_printf(LOG_INFO, "    Any                                 : %s\n", sum->any ? "1" : "0");
    sedcli_printf(LOG_INFO, "    All                                 : %s\n", sum->all ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Policy                              : %s\n", sum->policy ? "1" : "0");
}

static void print_cnl_feat(struct sed_cnl_feat *cnl)
{
    sedcli_printf(LOG_INFO, "\nSED CNL FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "-----------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code                 : 0x%x\n", be16toh(cnl->code));
    sedcli_printf(LOG_INFO, "    Version                      : %u\n", cnl->rev);
    sedcli_printf(LOG_INFO, "    Length                       : %u\n", cnl->len);
    sedcli_printf(LOG_INFO, "    Range_C                      : %s\n", cnl->range_c ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Range_P                      : %s\n", cnl->range_p ? "1" : "0");
    sedcli_printf(LOG_INFO, "    SUM_C                        : %s\n", cnl->sum_c ? "1" : "0");
    sedcli_printf(LOG_INFO, "    Maximum Key Count            : %u\n", be32toh(cnl->max_key_count));
    sedcli_printf(LOG_INFO, "    Unused Key Count             : %u\n", be32toh(cnl->unused_key_count));
    sedcli_printf(LOG_INFO, "    Maximum Ranges Per Namespace : %u\n", be32toh(cnl->max_ranges_per_ns));
}

static void print_siis_feat(struct sed_siis_feat *siis)
{
    sedcli_printf(LOG_INFO, "\nSED SIIS FEATURES SUPPORTED\n");
    sedcli_printf(LOG_INFO, "------------------------------\n");

    sedcli_printf(LOG_INFO, "    Feature Code             : 0x%x\n", be16toh(siis->code));
    sedcli_printf(LOG_INFO, "    Data Structure Version   : %u\n", siis->data_structure_version);
    sedcli_printf(LOG_INFO, "    Length                   : %u\n", siis->len);
    sedcli_printf(LOG_INFO, "    SIIS Revision Number     : TCG Storage Interface Interactions Specification v1.%02u r1.00\n", siis->siis_revision_number);
    sedcli_printf(LOG_INFO, "    Identifier Usage Scope   : %u\n", siis->identifier_usage_scope);
    sedcli_printf(LOG_INFO, "    Key Change Zone Behavior : %u\n", siis->key_change_zone_behavior);
}

static void print_tper_properties(struct sed_tper_properties *tper, char *prop_name)
{
    bool any_props = false;
    for (uint8_t i = 0; i < NUM_TPER_PROPS; i++) {
        if (strncmp(tper->property[i].key_name, "", 32) != 0) {
            any_props =  true;
            break;
        }
    }

    if (any_props == false)
        return;

    sedcli_printf(LOG_INFO, "\n%s\n", prop_name);
    sedcli_printf(LOG_INFO, "------------------\n");

    for (uint8_t i = 0; i < NUM_TPER_PROPS; i++) {
        if (strncmp(tper->property[i].key_name, "", 32) == 0)
            break;
        sedcli_printf(LOG_INFO, "    %-25s : %ld\n", tper->property[i].key_name, tper->property[i].value);
    }
}

static void sed_discovery_print_normal(struct sed_opal_device_discovery *discovery, const char *dev_path)
{
    uint16_t comid = 0;

    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_opalv200) {
        comid = be16toh(discovery->sed_lvl0_discovery.sed_opalv200.base_comid);
    } else if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_opalv100) {
        comid = be16toh(discovery->sed_lvl0_discovery.sed_opalv100.v1_base_comid);
    } else if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_ruby) {
        comid = be16toh(discovery->sed_lvl0_discovery.sed_ruby.base_comid);
    } else if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_pyritev200) {
        comid = be16toh(discovery->sed_lvl0_discovery.sed_pyritev200.base_comid);
    } else if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_pyritev100) {
        comid = be16toh(discovery->sed_lvl0_discovery.sed_pyritev100.base_comid);
    }

    if (!comid) {
        sedcli_printf(LOG_INFO, "Invalid disk, %s is NOT SED-OPAL compliant!\n", dev_path);
        return;
    }

    print_level0_discovery_header(&discovery->sed_lvl0_discovery_header);

    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_tper)
        print_tper_feat(&discovery->sed_lvl0_discovery.sed_tper);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_locking)
        print_locking_feat(&discovery->sed_lvl0_discovery.sed_locking);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_geometry)
        print_geometry_feat(&discovery->sed_lvl0_discovery.sed_geometry);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_siis)
        print_siis_feat(&discovery->sed_lvl0_discovery.sed_siis);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_datastore)
        print_datastore_feat(&discovery->sed_lvl0_discovery.sed_datastore);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_opalv100)
        print_opalv100_feat(&discovery->sed_lvl0_discovery.sed_opalv100);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_opalv200) {
        print_opalv200_header();
        print_opalv200_ruby_feat(&discovery->sed_lvl0_discovery.sed_opalv200);
    }
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_pyritev100) {
        print_pyrite_header(PYRITE_V100);
        print_pyrite_feat(&discovery->sed_lvl0_discovery.sed_pyritev100);
    }
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_pyritev200) {
        print_pyrite_header(PYRITE_V200);
        print_pyrite_feat(&discovery->sed_lvl0_discovery.sed_pyritev200);
    }
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_data_rm)
        print_data_rm_feat(&discovery->sed_lvl0_discovery.sed_data_rm);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_ruby) {
        print_ruby_header();
        print_opalv200_ruby_feat(&discovery->sed_lvl0_discovery.sed_ruby);
    }
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_block_sid)
        print_block_sid_feat(&discovery->sed_lvl0_discovery.sed_block_sid);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_sum)
        print_sum_feat(&discovery->sed_lvl0_discovery.sed_sum);
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_cnl)
        print_cnl_feat(&discovery->sed_lvl0_discovery.sed_cnl);

    print_tper_properties(&discovery->sed_tper_props, "TPER PROPERTIES");
    print_tper_properties(&discovery->sed_host_props, "HOST PROPERTIES");

    sedcli_printf(LOG_INFO, "\n");
}

static int host_prop_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret) {
        sedcli_printf(LOG_ERR, "%s: Error initializing device\n", opts->dev_path);
        return -EINVAL;
    }

    ret = sed_host_prop(dev, (const char *)opts->props, opts->values);
    if (ret) {
        sedcli_printf(LOG_ERR, "Command error\n");
        goto deinit;
    }

    print_tper_properties(&dev->discovery.sed_host_props, "HOST PROPERTIES");
    sedcli_printf(LOG_INFO, "\n");

    FILE *tfp = fopen("properties", "w");
    if (tfp) {
        struct sed_tper_properties *host_props = &dev->discovery.sed_host_props;
        for (uint8_t i = 0; i < NUM_TPER_PROPS; i++) {
            if (strncmp(host_props->property[i].key_name, "", 32) != 0) {
                fprintf(tfp, "%s\n", host_props->property[i].key_name);
                fprintf(tfp, "%lu\n", host_props->property[i].value);
            }
        }
        fclose(tfp);
    }

deinit:
    sed_deinit(dev);

    return ret;
}

#define SED_ENABLE "ENABLED"
#define SED_DISABLE "DISABLED"

char *DEV_SED_COMPATIBLE;
char *DEV_SED_LOCKED;

static void sed_discovery_print_udev(struct sed_opal_device_discovery *discovery)
{
    bool locking_enabled;
    uint16_t comid = 0;

    locking_enabled = discovery->sed_lvl0_discovery.sed_locking.locking_en ? true : false;
    if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_opalv200) {
        comid = discovery->sed_lvl0_discovery.sed_opalv200.base_comid;
    } else if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_ruby) {
        comid = discovery->sed_lvl0_discovery.sed_ruby.base_comid;
    } else if (discovery->sed_lvl0_discovery.feat_avail_flag.feat_opalv100) {
        comid = discovery->sed_lvl0_discovery.sed_opalv100.v1_base_comid;
    }

    if (!comid)
        DEV_SED_COMPATIBLE = SED_DISABLE;
    else
        DEV_SED_COMPATIBLE = SED_ENABLE;

    if (locking_enabled)
        DEV_SED_LOCKED = SED_ENABLE;
    else
        DEV_SED_LOCKED = SED_DISABLE;

    sedcli_printf(LOG_INFO, "DEV_SED_COMPATIBLE=%s\n", DEV_SED_COMPATIBLE);
    sedcli_printf(LOG_INFO, "DEV_SED_LOCKED=%s\n", DEV_SED_LOCKED);
}

static int discovery_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    struct sed_opal_device_discovery discovery;
    ret = sed_dev_discovery(dev, &discovery);
    if (ret) {
        sedcli_printf(LOG_ERR, "Command NOT supported for this interface.\n");
        goto deinit;
    }

    switch (opts->print_fmt) {
    case SED_NORMAL:
        sed_discovery_print_normal(&discovery, opts->dev_path);
        ret = 0;
        break;

    case SED_UDEV:
        sed_discovery_print_udev(&discovery);
        ret = 0;
        break;

    default:
        sedcli_printf(LOG_ERR, "Invalid format provided\n");
        ret = -EINVAL;
        break;
    }

deinit:
    sed_deinit(dev);

    return ret;
}

static void print_tper_state(struct sed_tper_state *tper_state)
{
    sedcli_printf(LOG_INFO, "TPer State:\n");
    sedcli_printf(LOG_INFO, "    Session Open            : %s\n",
            tper_state->session_open == SED_UNKNOWN_ERROR ? "Unknown" : (tper_state->session_open ? "YES" : "NO"));
    sedcli_printf(LOG_INFO, "    Has Owner               : %s\n",
            tper_state->blk_sid_val_state == SED_UNKNOWN_ERROR ? "Unknown" : (tper_state->blk_sid_val_state ? "YES" : "NO"));
    sedcli_printf(LOG_INFO, "    Locking SP Activated    : %s\n",
            tper_state->locking_en == SED_UNKNOWN_ERROR ? "Unknown" : (tper_state->locking_en ? "YES" : "NO"));
    sedcli_printf(LOG_INFO, "    Admin SP LifeCycle      : %s\n",
            tper_state->admisp_lc == SED_UNKNOWN_ERROR ? "Unknown" :
            (tper_state->admisp_lc == SED_OPAL_MANUFACTURED_INACTIVE ? "MANUFACTURED-INACTIVE" : "MANUFACTURED"));
    sedcli_printf(LOG_INFO, "    Locking SP LifeCycle    : %s\n",
            tper_state->lsp_lc == SED_UNKNOWN_ERROR ? "Unknown" :
            (tper_state->lsp_lc == SED_OPAL_MANUFACTURED_INACTIVE ? "MANUFACTURED-INACTIVE" : "MANUFACTURED"));
}

static int parse_tper_state_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    struct sed_tper_state tper_state;
    ret = sed_parse_tper_state(dev, &tper_state);
    if (ret) {
        sedcli_printf(LOG_ERR, "Error obtaining the tper state: %d\n", ret);
        goto deinit;
    }

    print_tper_state(&tper_state);

deinit:
    sed_deinit(dev);

    return ret;
}

static int ownership_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "New SID password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    sedcli_printf(LOG_INFO, "Repeat new SID password:");
    ret = read_password(&opts->repeated_pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    if (opts->pwd.len != opts->repeated_pwd.len ||
	  0 != memcmp(opts->pwd.key, opts->repeated_pwd.key, opts->pwd.len)) {
        sedcli_printf(LOG_ERR, "Error: passwords don't match\n");
        ret = -EINVAL;
        goto deinit;
    }

    ret = sed_take_ownership(dev, &opts->pwd);

deinit:
    sed_deinit(dev);

    return ret;
}

static int activate_sp_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter SID password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->target_sp, opts->target_sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = sed_activate_sp(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->target_sp_uid, opts->lr_str,
        opts->range_start_length_policy, opts->dsts_str);

deinit:
    sed_deinit(dev);

    return ret;
}

static int start_session_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->target_sp, opts->target_sp_uid);
    if (ret)
        goto deinit;

    struct sed_session session;
    ret = sed_start_session(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, &session);
    if (ret == SED_SUCCESS) {
        sedcli_printf(LOG_INFO, "HSN: %d\n", session.hsn);
        sedcli_printf(LOG_INFO, "TSN: %d\n", session.tsn);
    }

deinit:
    sed_deinit(dev);

    return ret;
}

static int end_session_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    ret = sed_end_session(dev, &opts->session);

    sed_deinit(dev);

    return ret;
}

static int revert_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->target_sp, opts->target_sp_uid);
    if (ret)
        goto deinit;

    ret = sed_revert(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->target_sp_uid);

deinit:
    sed_deinit(dev);

    return ret;
}

static int revert_lsp_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = sed_revert_lsp(dev, &opts->pwd, opts->auth_uid, opts->keep_global_range_key);

deinit:
    sed_deinit(dev);

    return ret;
}

static int lock_unlock_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = sed_lock_unlock(dev, &opts->pwd, opts->auth_uid, opts->lr, opts->sum, opts->access_type);

deinit:
    sed_deinit(dev);

    return ret;
}

static int setup_global_range_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    sedcli_printf(LOG_INFO,"RLE = %d, WLE = %d\n", opts->rle, opts->wle);

    ret = sed_setup_global_range(dev, &opts->pwd, opts->rle, opts->wle);

deinit:
    sed_deinit(dev);

    return ret;
}

static int setup_lr_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = sed_setup_lr(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid, opts->range_start, opts->range_length, opts->rle, opts->wle);

deinit:
    sed_deinit(dev);

    return ret;
}

static int genkey_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = sed_genkey(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid, opts->public_exponent, opts->pin_length);

deinit:
    sed_deinit(dev);

    return ret;
}

static int erase_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = sed_erase(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid);

deinit:
    sed_deinit(dev);

    return ret;
}

static int enable_user_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->user, opts->user_is_uid, opts->user_uid);
    if (ret)
        goto deinit;

    ret = sed_enable_user(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->user_uid);

deinit:
    sed_deinit(dev);

    return ret;
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

void print_col_info(uint8_t col, struct sed_opal_col_info *col_info)
{
    sedcli_printf(LOG_INFO, "col %u: ", col);

    uint token = 0;
    while (col_info && col_info->data) {
        // token number
        sedcli_printf(LOG_INFO, "#%u ", token++);
        // token type
        sedcli_printf(LOG_INFO, "<0x%02x> ", col_info->opal_type);

        switch (col_info->type) {
        case SED_DATA_SINT:
        case SED_DATA_UINT:
            switch (col_info->opal_type) {
            case 0x00 ... TINY_ATOM_BYTE:
            case (TINY_ATOM_BYTE + 1) ... SHORT_ATOM_BYTE:
                sedcli_printf(LOG_INFO, "[ 0x%02lx ]", *(uint64_t*)col_info->data);
                break;

            case (SHORT_ATOM_BYTE + 1) ... MEDIUM_ATOM_BYTE:
            case (MEDIUM_ATOM_BYTE + 1) ... LONG_ATOM_BYTE:
                // to be added
                sedcli_printf(LOG_ERR, "Type not supported: %u\n", col_info->opal_type);
                break;
            }
            break;

        case SED_DATA_BYTESTRING:
            // token data
            sedcli_printf(LOG_INFO, "[ ");
            for (uint8_t i = 0; i < col_info->len; i++) {
                uint data = 0;
                memcpy(&data, (uint8_t*)col_info->data + i, sizeof(uint8_t));
                sedcli_printf(LOG_INFO, "0x%02x ", (unsigned int)data);
            }
            sedcli_printf(LOG_INFO, "]");
            break;

        case SED_DATA_TOKEN:
            switch (col_info->opal_type) {
            case OPAL_STARTLIST:
                sedcli_printf(LOG_INFO, "start_list");
                break;

            case OPAL_ENDLIST:
                sedcli_printf(LOG_INFO, "end_list");
                break;

            case OPAL_STARTNAME:
                sedcli_printf(LOG_INFO, "start_name");
                break;

            case OPAL_ENDNAME:
                sedcli_printf(LOG_INFO, "end_name");
                break;

            case OPAL_CALL:
                sedcli_printf(LOG_INFO, "call");
                break;

            case OPAL_ENDOFDATA:
                sedcli_printf(LOG_INFO, "end_of_data");
                break;

            case OPAL_ENDOFSESSION:
                sedcli_printf(LOG_INFO, "end_of_session");
                break;

            case OPAL_STARTTRANSACTON:
                sedcli_printf(LOG_INFO, "start_transaction");
                break;

            case OPAL_ENDTRANSACTON:
                sedcli_printf(LOG_INFO, "end_transaction");
                break;

            case OPAL_EMPTYATOM:
                sedcli_printf(LOG_INFO, "empty");
                break;

            default:
                break;
            }
            break;

        case SED_DATA_TOKEN_INVALID:
            sedcli_printf(LOG_INFO, "[ invalid ]");
            break;
        }

        col_info = col_info->next_col;

        if (col_info && col_info->data)
            sedcli_printf(LOG_INFO, "\n       ");
    }
    sedcli_printf(LOG_INFO, "\n");
}

static int get_object_handle(void)
{
    if (opts->start > opts->end)
        return SED_INVALID_PARAMETER;

    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    // create cols table
    struct sed_opal_col_info **cols;
    uint8_t last_col = 0;
    cols = malloc(sizeof(struct sed_opal_col_info *) * (opts->end - opts->start + 1));
    if (cols == NULL) {
        ret = -ENOMEM;
        goto cleanup;
    }

    // get cols
    for (uint64_t i = opts->start; i <= opts->end && ret == SED_SUCCESS; i++) {
        struct sed_opal_col_info *col_info = malloc(sizeof(struct sed_opal_col_info));
        if (col_info == NULL) {
            ret = -ENOMEM;
            goto cleanup;
        }

        cols[last_col++] = col_info;
        memset(col_info, 0, sizeof(struct sed_opal_col_info));

        ret = sed_get_set_col_val(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid, i, true /* get */, col_info);
    }

    // print cols
    if (ret == SED_SUCCESS) {
        for (uint8_t i = 0; i < last_col; i++)
            print_col_info(i + opts->start, cols[i]);
    }

cleanup:
    if (cols) {
        for (uint8_t i = 0; i < last_col; i++)
            free_col_info(cols[i]);

        free(cols);
    }

deinit:
    sed_deinit(dev);

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

#define OPAL_U8    1
#define OPAL_U64   2
#define OPAL_BYTES 3

int read_input(char *input, size_t size)
{

    if (fgets(input, size, stdin) == NULL)
        return -EINVAL;

    return SED_SUCCESS;
}

#define MAX_SET_BYTES     1024
#define SET_CMD_START_LEN 5
#define SET_CMD_END_LEN   3
static int set_buff(struct sed_device *dev)
{
    struct opal_req_item cmd_start[] = {
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
        { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
        { .type = OPAL_U64, .len = 1, .val = { .uint = opts->row } },
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
    while (true) {
        // scan line
        char temp[MAX_SET_BYTES] = { 0 };
        if (read_input(temp, ARRAY_SIZE(temp)))
            return -EINVAL;

        // break if user prompted an empty line
        if (temp[0] == '\n') {
            break;
        }

        // parse all tokens from scanned line, separated by a ' ' space char
        char *ptr = temp;
        while (ptr != NULL) {
            uint64_t token;
            if (get_buf_val(ptr, &token))
                return -EINVAL;

            cmd_buff[item].type = OPAL_U8;
            cmd_buff[item].len = 1;
            cmd_buff[item].val.byte = token;

            if (item++ >= MAX_SET_BYTES - 1)
                return -EINVAL;

            ptr = strchr(ptr, ' ');
            if (ptr != NULL)
                ptr++;
        }
    }

    memcpy(cmd + SET_CMD_START_LEN, cmd_buff, sizeof(struct opal_req_item) * item);
    memcpy(cmd + SET_CMD_START_LEN + item, cmd_end, sizeof(struct opal_req_item) * SET_CMD_END_LEN);
    size_t cmd_len = SET_CMD_START_LEN + SET_CMD_END_LEN + item;

    int ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        return ret;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        return ret;

    return sed_set_with_buf(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid, cmd, cmd_len);
}

static int set_object_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    if (opts->buff) {
        sedcli_printf(LOG_INFO, "Provide tokens separated by a space, with an empty line at the end:\n");
        ret = set_buff(dev);
    } else {
        struct sed_opal_col_info col_info;
        col_info.type = (enum SED_TOKEN_TYPE)opts->type;
        col_info.len = 1;
        col_info.data = NULL;

        switch (col_info.type) {
        case SED_DATA_SINT:
            col_info.data = (int64_t*)malloc(sizeof(int64_t));
            if (col_info.data == NULL) {
                ret = -ENOMEM;
                goto deinit;
            }

            memcpy(col_info.data, &opts->svalue, sizeof(int64_t));
            break;

        case SED_DATA_UINT:
            col_info.data = (uint64_t*)malloc(sizeof(uint64_t));
            if (col_info.data == NULL) {
                ret = -ENOMEM;
                goto deinit;
            }

            memcpy(col_info.data, &opts->uvalue, sizeof(uint64_t));
            break;

        default:
            ret = -EINVAL;
            sedcli_printf(LOG_ERR, "Wrong type: %d\n", col_info.type);
            goto cleanup;
        }

        ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
        if (ret)
            goto cleanup;

        ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
        if (ret)
            goto cleanup;

        ret = sed_get_set_col_val(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid, opts->row, false, &col_info);

cleanup:
        if (col_info.data)
            free(col_info.data);
    }

deinit:
    sed_deinit(dev);

    return ret;
}

static int stack_reset_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    uint8_t response[16] = { 0 };
    ret = sed_stack_reset(dev, opts->com_id, opts->extended_com_id, response);
    if (ret == SED_SUCCESS && be16toh(response[10]) != 0)
    {
        sedcli_printf(LOG_INFO, "Extended ComID        : 0x%08x\n", be32toh(response[0]));
        sedcli_printf(LOG_INFO, "Request Code          : 0x%08x\n", be32toh(response[4]));
        sedcli_printf(LOG_INFO, "Available Data Length : 0x%04x\n", be16toh(response[10]));
        sedcli_printf(LOG_INFO, "Success/Failure       : 0x%08x\n", be16toh(response[12]));
    }

    sed_deinit(dev);

    return ret;
}

static int tper_reset_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    ret = sed_tper_reset(dev);

    sed_deinit(dev);

    return ret;
}

void printf_buffer(uint8_t *buffer, size_t buffer_size)
{
    uint32_t bytes_to_print = buffer_size / sizeof(uint8_t);
    uint32_t rows_to_print = bytes_to_print % 16 == 0 ? bytes_to_print / 16 : bytes_to_print / 16 + 1;
    uint32_t byte_pos = 0;

    sedcli_printf(LOG_INFO, "Received data:\n");

    for (uint32_t i = 1; i <= rows_to_print; i++)
    {
        sedcli_printf(LOG_INFO, "0x%04x ", i * 16); // print offset
        for (uint8_t y = 0; y < 16; y++)
        {
            sedcli_printf(LOG_INFO, "%02x", byte_pos < buffer_size ? buffer[byte_pos++] : 0);

            if (y != 0  && (y % 4 == 3))
                sedcli_printf(LOG_INFO, " ");
        }
        sedcli_printf(LOG_INFO, "\n");
    }
}

static int byte_table_handle(bool is_set)
{
    if (opts->start > opts->end)
        return SED_INVALID_PARAMETER;

    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    size_t buffer_size = sizeof(uint8_t) * (opts->end - opts->start + 1);

    uint8_t *buffer = calloc((opts->end - opts->start + 1), sizeof(uint8_t));
    if (buffer == NULL) {
        ret = -ENOMEM;
        goto deinit;
    }

    // open file and get size
    if (is_set)
    {
        int fd = open(opts->file_path, O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            sedcli_printf(LOG_ERR, "Error opening/fstating file: %s\n", opts->file_path);
            ret = -ENOENT;
            goto cleanup;
        }

        struct stat file_st;
        if (fstat(fd, &file_st) == -1) {
            sedcli_printf(LOG_ERR, "Error opening/fstating file: %s\n", opts->file_path);
            close(fd);
            ret = -ENOENT;
            goto cleanup;
        }

        // create cols table
        size_t file_size = file_st.st_size;
        if (buffer_size < file_size)
            sedcli_printf(LOG_WARNING, "Error size of given file is greater than requested num of rows: %s\n", opts->file_path);

        // read file to buffer
        ret = read(fd, buffer, buffer_size);
        if (ret < 0)
        {
            sedcli_printf(LOG_ERR, "Error during reading file: %s\n", opts->file_path);
            close(fd);
            ret = -EINVAL;
            goto cleanup;
        }

        close(fd);
    }

    ret = sed_get_set_byte_table(dev, &opts->pwd, opts->sp, opts->auth, opts->uid, opts->start, opts->end, buffer, is_set);

    // print buffer
    if (!is_set && ret == SED_SUCCESS)
        printf_buffer(buffer, buffer_size);

cleanup:
    if (buffer)
        free(buffer);

deinit:
    sed_deinit(dev);

    return ret;
}

static int get_byte_table_handle(void)
{
    return byte_table_handle(false);
}

static int set_byte_table_handle(void)
{
    return byte_table_handle(true);
}

static int reactivate_sp_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->target_sp, opts->target_sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = sed_reactivate_sp(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->target_sp_uid, opts->lr_str, opts->range_start_length_policy,
        &opts->admin1_pwd, opts->dsts_str);

deinit:
    sed_deinit(dev);

    return ret;
}

static int assign_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    struct sed_locking_object locking_object;
    ret = sed_assign(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->nsid, opts->range_start, opts->range_length, &locking_object);

    if (ret == SED_SUCCESS) {
        sedcli_printf(LOG_INFO, "Namespace ID: %u\n", locking_object.nsid);
        sedcli_printf(LOG_INFO, "UID (hex): ");
        for (uint8_t i = 0; i < OPAL_UID_LENGTH; i++) {
            sedcli_printf(LOG_INFO, "%02x", locking_object.uid[i]);
            if (i < OPAL_UID_LENGTH - 1)
                sedcli_printf(LOG_INFO, "-");
            else
                sedcli_printf(LOG_INFO, "\n");
        }
        sedcli_printf(LOG_INFO, "Namespace Global Range: ");
        locking_object.nsgid == 1 ? sedcli_printf(LOG_INFO, "True\n") : sedcli_printf(LOG_INFO, "False\n");
    }

deinit:
    sed_deinit(dev);

    return ret;
}

static int deassign_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = sed_deassign(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid, opts->keep_ns_global_range_key);

deinit:
    sed_deinit(dev);

    return ret;
}

static int table_next_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    uint8_t *where = opts->where;
    uint8_t opal_uid_none[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    if (compare_uid(opts->where, opal_uid_none))
        where = NULL;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    struct sed_next_uids next_uids = { 0 };
    ret = sed_table_next(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid, where, opts->count, &next_uids);
    if (ret == SED_SUCCESS) {
        sedcli_printf(LOG_INFO, "rows (%d):\n", next_uids.size);
        for (uint16_t i = 0; i < next_uids.size; i++) {
            sedcli_printf(LOG_INFO, "%04d: ", i);
            for (uint8_t j = 0; j < OPAL_UID_LENGTH; j++) {
                sedcli_printf(LOG_INFO, "%02x", next_uids.uids[i][j]);
                if (j < OPAL_UID_LENGTH - 1 )
                    sedcli_printf(LOG_INFO, "-");
            }
            sedcli_printf(LOG_INFO, "\n");
        }
    }

    if (next_uids.size > 0) {
        for (uint16_t i = 0; i < next_uids.size; i++)
            free(next_uids.uids[i]);
        free(next_uids.uids);
    }

deinit:
    sed_deinit(dev);

    return ret;
}

static int get_acl_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    struct sed_next_uids next_uids = { 0 };
    ret = sed_get_acl(dev, &opts->pwd, opts->sp_uid, opts->auth_uid, opts->uid, opts->method, &next_uids);
    if (ret == SED_SUCCESS) {
        sedcli_printf(LOG_INFO, "rows (%d):\n", next_uids.size);
        for (uint16_t i = 0; i < next_uids.size; i++) {
            sedcli_printf(LOG_INFO, "%04d: ", i);
            for (uint8_t j = 0; j < OPAL_UID_LENGTH; j++) {
                sedcli_printf(LOG_INFO, "%02x", next_uids.uids[i][j]);
                if (j < OPAL_UID_LENGTH - 1 )
                    sedcli_printf(LOG_INFO, "-");
            }
            sedcli_printf(LOG_INFO, "\n");
        }
    }

    if (next_uids.size > 0) {
        for (uint16_t i = 0; i < next_uids.size; i++)
            free(next_uids.uids[i]);
        free(next_uids.uids);
    }

deinit:
    sed_deinit(dev);

    return ret;
}

static int set_password_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter authority password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    sedcli_printf(LOG_INFO, "New user password:");
    struct sed_key new_key = { 0 };
    ret = read_password(&new_key, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    sedcli_printf(LOG_INFO, "Repeat new user password:");
    struct sed_key new_key_repeated = { 0 };
    ret = read_password(&new_key_repeated, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    if (new_key.len != new_key_repeated.len ||
	  0 != memcmp(new_key.key, new_key_repeated.key, new_key.len)) {
        sedcli_printf(LOG_ERR, "Error: passwords don't match\n");
        ret = -EINVAL;
        goto deinit;
    }

    ret = get_opal_user_auth_uid(opts->auth, opts->auth_is_uid, opts->auth_uid);
    if (ret)
        goto deinit;

    ret = get_opal_user_auth_uid(opts->user, opts->user_is_uid, opts->user_uid);
    if (ret)
        goto deinit;

    ret = get_opal_sp_uid(opts->sp, opts->sp_uid);
    if (ret)
        goto deinit;

    ret = sed_set_password(dev, opts->sp_uid, opts->auth_uid, &opts->pwd, opts->user_uid, &new_key_repeated);

deinit:
    sed_deinit(dev);

    return ret;
}

static int check_current_levl0_discovery(struct sed_device *dev)
{
    struct sed_opal_device_discovery discovery;
    int ret = sed_dev_discovery(dev, &discovery);
    if (ret) {
        if (ret == -EOPNOTSUPP) {
            sedcli_printf(LOG_WARNING, "Level0 discovery not supported for this interface.\n");
            /*
             * Continue the operations even if the interface doesn't
             * support level0 discovery, the kernel takes care of it
             */
            return 0;
        } else {
            sedcli_printf(LOG_ERR, "Error doing level0 discovery\n");
            return ret;
        }
    }

    /*
     * Check the current status of any level0 feture (Add them here)
     * Return zero on successful checks and -1 on unsuccessful checks
     */
    if (!discovery.sed_lvl0_discovery.sed_locking.locking_en) {
        sedcli_printf(LOG_INFO, "LSP NOT ACTIVATED\n");
        ret = -1;
    }

    return ret;
}

static int mbr_control_handle(void)
{
    if (!opts->enable && opts->done) {
        sedcli_printf(LOG_ERR, "Error: disabling MBR shadow and setting MBR done doesn't take any effect.\n");
        return -EINVAL;
    }

    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = check_current_levl0_discovery(dev);
    if (ret)
        goto deinit;

    if (mbr_enable) {
        ret = sed_shadow_mbr(dev, &opts->pwd, opts->enable);
        if (ret)
            goto deinit;
    }

    if (mbr_done)
        ret = sed_mbr_done(dev, &opts->pwd, opts->done);

deinit:
    sed_deinit(dev);

    return ret;
}

static int write_mbr_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = check_current_levl0_discovery(dev);
    if (ret)
        goto deinit;

    int fd = open(opts->file_path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        sedcli_printf(LOG_ERR, "Error opening file: %s\n", opts->file_path);
        ret = -ENOENT;
        goto deinit;
    }

    struct stat mbr_st;
    if (fstat(fd, &mbr_st) == -1) {
        sedcli_printf(LOG_ERR, "Error fstating file: %s\n", opts->file_path);
        ret = -ENOENT;
        goto close_fd;
    }

    void *mbr_mmap = mmap(NULL, mbr_st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mbr_mmap == MAP_FAILED) {
        sedcli_printf(LOG_ERR, "Error mmaping file: %s\n", opts->file_path);
        ret = -1;
        goto close_fd;
    }

    ret = sed_write_shadow_mbr(dev, &opts->pwd, (const uint8_t *)mbr_mmap, mbr_st.st_size, opts->offset);

    munmap(mbr_mmap, mbr_st.st_size);

close_fd:
    close(fd);

deinit:
    sed_deinit(dev);

    return ret;
}

static int block_sid_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    ret = sed_issue_block_sid_cmd(dev, opts->hardware_reset);

    sed_deinit(dev);

    return ret;
}

static int add_user_lr_handle(void)
{
    struct sed_device *dev = NULL;
    int ret = sed_init(&dev, opts->dev_path, false);
    if (ret)
        return ret;

    sedcli_printf(LOG_INFO, "Enter password:");
    ret = read_password(&opts->pwd, opts->pwd_is_hexencoded);
    if (ret)
        goto deinit;

    ret = sed_add_user_to_lr(dev, &opts->pwd, opts->auth, opts->access_type, opts->lr);

deinit:
    sed_deinit(dev);

    return ret;
}

static int version_handle(void)
{
    sedcli_printf(LOG_INFO, "sedcli %s\n", SEDCLI_VERSION);

    return SUCCESS;
}

static int help_handle(void)
{
    app app_values;
    app_values.name = "sedcli";
    app_values.info = "<command> [option...]";
    app_values.title = SEDCLI_TITLE;
    app_values.doc = "";
    app_values.man = "sedcli";
    app_values.block = 0;

    print_help(&app_values, sedcli_commands);
    return 0;
}

static int hex_decode(char *buf, uint16_t buf_sz, struct sed_key *pwd)
{
    int i = 0;

    for (i = 0; i < buf_sz; i += 2) {
        int b;
        if (sscanf(buf+i, "%2x", &b) != 1) {
            return -EINVAL;
        }
        pwd->key[i/2] = b;
    }
    pwd->len = buf_sz / 2;

    return 0;
}

static int read_password(struct sed_key *pwd, bool hex_encoded)
{
    int ret = 0;
    uint16_t in_size;

    if (hex_encoded) {
        char buf[SED_MAX_KEY_LEN*2+1];

        ret = get_password(buf, &in_size, SED_MAX_KEY_LEN*2);
        if (ret) {
            return ret;
        }

        ret = hex_decode(buf, in_size, pwd);
    } else {
        ret = get_password(pwd->key, &in_size, SED_MAX_KEY_LEN);
        if (ret) {
            return ret;
        }
        pwd->len = in_size;
    }

    return ret;
}

int main(int argc, char *argv[])
{
    // Set CLI to standard, this will cause in different status handling.
    sed_cli = SED_CLI_STANDARD;

    int blocked = 0, status;
    app app_values;

    app_values.name = argv[0];
    app_values.info = "<command> [option...]";
    app_values.title = SEDCLI_TITLE;
    app_values.doc = "";
    app_values.man = "sedcli";
    app_values.block = blocked;

    opts = alloc_locked_buffer(sizeof(*opts));
    if (opts == NULL) {
        sedcli_printf(LOG_ERR, "sedcli: Failed to allocated memory\n");
        return -ENOMEM;
    }

    status = args_parse(&app_values, sedcli_commands, argc, argv);

    free_locked_buffer(opts, sizeof(*opts));

    return status;
}
