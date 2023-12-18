/*
 * Copyright (C) 2018-2019, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "../config.h" // include first

#include <linux/fs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include "nvme_pt_ioctl.h"
#include "nvme_access.h"
#include "sed_util.h"
#include "sedcli_log.h"
#include "opal_parser.h"


#define OPAL_FEAT_TPER       0x0001
#define OPAL_FEAT_LOCKING    0x0002
#define OPAL_FEAT_GEOMETRY   0x0003
#define OPAL_FEAT_DATASTORE  0x0202
#define OPAL_FEAT_SUM        0x0201
#define OPAL_FEAT_OPALV100   0x0200
#define OPAL_FEAT_OPALV200   0x0203
#define OPAL_FEAT_PYRITEV100 0x0302
#define OPAL_FEAT_PYRITEV200 0x0303
#define OPAL_FEAT_RUBY       0x0304
#define OPAL_FEAT_BLOCK_SID  0x0402
#define OPAL_FEAT_CNL        0x0403
#define OPAL_FEAT_DATA_RM    0x0404

#define SUM_RANGES                    0x060000 // SingleUserModeSelectionList
#define SUM_RANGE_START_LENGHT_POLICY 0x060001 // RangeStartRangeLengthPolicy
#define SUM_ADMIN1_PIN                0x060002 // Admin1PIN
#define SUM_DATASTORE_TABLE_SIZES     0x060003 // DataStoreTableSizes

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define MIN_IO_BUFFER_LEN 2048

#define OPAL_BLOCK_SID_COMID  5
#define BLOCK_SID_PAYLOAD_SZ  512

#define STACK_RESET_PAYLOAD_SZ 64

#define OPAL_TPER_RESET_COMID 0x0004

#define MIN(x,y) \
   ({ __typeof__ (x) _x = (x); \
       __typeof__ (y) _y = (y); \
     _x < _y ? _x : _y; })

struct opal_device {
    uint16_t comid;

    uint8_t *req_buf;
    uint8_t *resp_buf;
    uint64_t req_buf_size;
    uint64_t resp_buf_size;

    struct opal_parsed_payload payload;

    struct {
        uint32_t hsn;
        uint32_t tsn;
    } session;
};

uint8_t opal_uid[][OPAL_UID_LENGTH] = {
    [OPAL_SM_UID] =
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff },
    [OPAL_THIS_SP_UID] =
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
    [OPAL_ADMIN_SP_UID] =
        { 0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x01 },
    [OPAL_LOCKING_SP_UID] =
        { 0x00, 0x00, 0x02, 0x05, 0x00, 0x00, 0x00, 0x02 },
    [OPAL_ENTERPRISE_LOCKING_SP_UID] =
        { 0x00, 0x00, 0x02, 0x05, 0x00, 0x01, 0x00, 0x01 },

    /* authority */
    [OPAL_ANYBODY_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01 },
    [OPAL_ADMINS_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02 },
    [OPAL_MAKERS_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x03 },
    [OPAL_MAKERSYMK_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x04 },
    [OPAL_MAKERPUK_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x05 },
    [OPAL_SID_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06 },
    [OPAL_PSID_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0xff, 0x01 },
    [OPAL_TPERSIGN_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x07 },
    [OPAL_TPEREXCH_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x08 },
    [OPAL_ADMINEXCH_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x09 },
    [OPAL_ISSUERS_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x02, 0x01 },
    [OPAL_EDITORS_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x02, 0x02 },
    [OPAL_DELETERS_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x02, 0x03 },
    [OPAL_SERVERS_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x02, 0x04 },
    [OPAL_RESERVE0_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x02, 0x05 },
    [OPAL_RESERVE1_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x02, 0x06 },
    [OPAL_RESERVE2_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x02, 0x07 },
    [OPAL_RESERVE3_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x02, 0x08 },
    [OPAL_ADMIN_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x00 },
    [OPAL_ADMIN1_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01 },
    [OPAL_ADMIN2_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x02 },
    [OPAL_ADMIN3_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x03 },
    [OPAL_ADMIN4_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x04 },
    [OPAL_USERS_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x00 },
    [OPAL_USER_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x00 },
    [OPAL_USER1_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x01 },
    [OPAL_USER2_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x02 },
    [OPAL_USER3_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x03 },
    [OPAL_USER4_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x04 },
    [OPAL_USER5_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x05 },
    [OPAL_USER6_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x06 },
    [OPAL_USER7_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x07 },
    [OPAL_USER8_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x08 },
    [OPAL_USER9_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x00, 0x09 },
    [OPAL_ENTERPRISE_BANDMASTER0_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x80, 0x01 },
    [OPAL_ENTERPRISE_ERASEMASTER_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x84, 0x01 },

    /* tables UIDs*/
    [OPAL_TABLE_TABLE_UID] =
        { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 },
    [OPAL_LOCKING_TABLE_UID] =
        { 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00 },
    [OPAL_LOCKINGRANGE_GLOBAL_UID] =
        { 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x01 },
    [OPAL_LOCKINGRANGE_ACE_RDLOCKED_UID] =
        { 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0xE0, 0x01 },
    [OPAL_LOCKINGRANGE_ACE_WRLOCKED_UID] =
        { 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0xE8, 0x01 },
    [OPAL_MBRCONTROL_UID] =
        { 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x01 },
    [OPAL_MBR_UID] =
        { 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00 },
    [OPAL_AUTHORITY_TABLE_UID] =
        { 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00},
    [OPAL_C_PIN_TABLE_UID] =
        { 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00},
    [OPAL_LOCKING_INFO_TABLE_UID] =
        { 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x01 },
    [OPAL_ENTERPRISE_LOCKING_INFO_TABLE_UID] =
        { 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00 },
    [OPAL_DATASTORE_UID] =
        { 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00 },
    [OPAL_ACCESS_CONTROL_UID] =
        { 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00 },

    /* C_PIN_TABLE object UIDs */
    [OPAL_C_PIN_MSID_UID] =
        { 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x84, 0x02},
    [OPAL_C_PIN_SID_UID] =
        { 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01},
    [OPAL_C_PIN_ADMIN_SP_ADMIN1_UID] =
        { 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x02, 0x01}, // ADMIN SP
    [OPAL_C_PIN_LOCKING_SP_ADMIN1_UID] =
        { 0x00, 0x00, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x01}, // LOCKING SP
    [OPAL_C_PIN_USER1_UID] =
        { 0x00, 0x00, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x01},

    /* half UID's (only first 4 bytes used) */
    [OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID] =
        { 0x00, 0x00, 0x0C, 0x05, 0xff, 0xff, 0xff, 0xff },
    [OPAL_HALF_UID_BOOLEAN_ACE_UID] =
        { 0x00, 0x00, 0x04, 0x0E, 0xff, 0xff, 0xff, 0xff },

    /* ACE DS UIDs */
    [OPAL_ACE_DS_GET_ALL_UID] =
        { 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0xfc, 0x00 },
    [OPAL_ACE_DS_SET_ALL_UID] =
        { 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0xfc, 0x01 },

    /* special value for omitted optional parameter */
    [OPAL_UID_HEXFF_UID] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
};

static uint8_t opal_method[][OPAL_UID_LENGTH] = {
    [OPAL_PROPERTIES_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01 },
    [OPAL_STARTSESSION_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02 },
    [OPAL_REVERT_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x02, 0x02 },
    [OPAL_ACTIVATE_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x02, 0x03 },
    [OPAL_EGET_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06 },
    [OPAL_ESET_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07 },
    [OPAL_NEXT_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08 },
    [OPAL_EAUTHENTICATE_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0c },
    [OPAL_GETACL_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0d },
    [OPAL_GENKEY_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x10 },
    [OPAL_REVERTSP_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x11 },
    [OPAL_GET_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x16 },
    [OPAL_SET_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x17 },
    [OPAL_AUTHENTICATE_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1c },
    [OPAL_RANDOM_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x06, 0x01 },
    [OPAL_ERASE_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x08, 0x03 },
    [OPAL_REACTIVATE_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x08, 0x01 },
    [OPAL_ASSIGN_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x08, 0x04 },
    [OPAL_DEASSIGN_METHOD_UID] =
        { 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x08, 0x05 },
};

extern uint32_t nvme_error;

static int opal_dev_discovery(struct sed_device *dev);

static int opal_host_prop(struct sed_device *dev, const char *props, uint32_t *vals);

static int opal_level0_discovery_pt(struct sed_device *device)
{
    struct opal_l0_feat *curr_feat;
    struct opal_level0_header *header;
    struct opal_level0_feat_desc *desc;
    struct opal_l0_disc disc_data;
    struct opal_device *dev = device->priv;
    struct sed_opal_level0_discovery *discv = &device->discv.sed_lvl0_discv;

    int pos, end, feat_no;
    uint16_t feat_code;
    uint8_t *buffer;

    SEDCLI_DEBUG_MSG("Starting discovery.\n");
    int ret = opal_recv(device->fd, TCG_SECP_01, OPAL_DISCOVERY_COMID, dev->resp_buf, dev->resp_buf_size);
    if (ret) {
        SEDCLI_DEBUG_PARAM("NVMe error during discovery: %d\n", ret);
        nvme_error = ret;
        return ret;
    }
    SEDCLI_DEBUG_MSG("Discovery done.\n");


    buffer = dev->resp_buf;

    /* level 0 header */
    header = (struct opal_level0_header *)buffer;
    device->discv.sed_lvl0_discv_header.len = header->len;
    device->discv.sed_lvl0_discv_header.rev = header->rev;
    for (uint8_t i = 0; i < 32; i++)
        device->discv.sed_lvl0_discv_header.vendor_specific[i] = header->vendor_specific[i];

    memset(&disc_data, 0, sizeof(struct opal_l0_disc));
    disc_data.rev = be32toh(header->rev);

    /* processing level 0 features */
    pos = 0;
    feat_no = 0;
    pos += sizeof(*header);
    end = be32toh(header->len);

    while (pos < end) {
        desc = (struct opal_level0_feat_desc *)(buffer + pos);
        feat_code = be16toh(desc->code);

        pos += desc->len + 4;

        switch (feat_code) {
        case OPAL_FEAT_TPER:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_tper, (struct tper_feat *)&desc->feat.tper.flags, sizeof(struct tper_feat));
            discv->feat_avail_flag.feat_tper = 1;
            discv->sed_tper.code = desc->code;
            discv->sed_tper.rev = desc->rev;
            discv->sed_tper.len = desc->len;

            feat_no++;
            break;

        case OPAL_FEAT_LOCKING:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_locking, (struct locking_feat *)&desc->feat.locking.flags, sizeof(struct locking_feat));
            discv->feat_avail_flag.feat_locking = 1;
            discv->sed_locking.code = desc->code;
            discv->sed_locking.rev = desc->rev;
            discv->sed_locking.len = desc->len;

            feat_no++;
            break;

        case OPAL_FEAT_GEOMETRY:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_geometry, (struct geometry_feat *)&desc->feat.geometry, sizeof(struct geometry_feat));
            discv->feat_avail_flag.feat_geometry = 1;
            discv->sed_geometry.code = desc->code;
            discv->sed_geometry.rev = desc->rev;
            discv->sed_geometry.len = desc->len;

            feat_no++;
            break;

        case OPAL_FEAT_DATASTORE:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_datastore, (struct datastore_feat *)&desc->feat.datastore.datastore, sizeof(struct datastore_feat));
            discv->feat_avail_flag.feat_datastore = 1;
            discv->sed_datastore.code = desc->code;
            discv->sed_datastore.rev = desc->rev;
            discv->sed_datastore.len = desc->len;

            feat_no++;
            break;

        case OPAL_FEAT_SUM:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_sum, (struct sum_feat *)&desc->feat.sum, sizeof(struct sum_feat));
            discv->feat_avail_flag.feat_sum = 1;
            discv->sed_sum.code = desc->code;
            discv->sed_sum.rev = desc->rev;
            discv->sed_sum.len = desc->len;

            feat_no++;
            break;

        case OPAL_FEAT_BLOCK_SID:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_block_sid, (struct block_sid_feat *)&desc->feat.block_sid, sizeof(struct block_sid_feat));
            discv->feat_avail_flag.feat_block_sid = 1;
            discv->sed_block_sid.code = desc->code;
            discv->sed_block_sid.rev = desc->rev;
            discv->sed_block_sid.len = desc->len;

            feat_no++;
            break;

        case OPAL_FEAT_OPALV100:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_opalv100, (struct opalv100_feat *)&desc->feat.opalv100, sizeof(struct opalv100_feat));
            discv->feat_avail_flag.feat_opalv100 = 1;
            discv->sed_opalv100.code = desc->code;
            discv->sed_opalv100.rev = desc->rev;
            discv->sed_opalv100.len = desc->len;

            feat_no++;
            break;

        case OPAL_FEAT_OPALV200:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_opalv200, (struct opalv200_feat *)&desc->feat.opalv200, sizeof(struct opalv200_feat));
            discv->feat_avail_flag.feat_opalv200 = 1;
            discv->sed_opalv200.code = desc->code;
            discv->sed_opalv200.rev.rev = desc->rev;
            discv->sed_opalv200.len = desc->len;

            curr_feat->feat.opalv200.base_comid = be16toh(desc->feat.opalv200.base_comid);
            disc_data.comid = curr_feat->feat.opalv200.base_comid;

            feat_no++;
            break;

        case OPAL_FEAT_RUBY:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            // ruby is opalv200 feature struct
            memcpy(&discv->sed_ruby, (struct opalv200_feat *)&desc->feat.ruby, sizeof(struct opalv200_feat));
            discv->feat_avail_flag.feat_ruby = 1;
            discv->sed_ruby.code = desc->code;
            discv->sed_ruby.rev.rev = desc->rev;
            discv->sed_ruby.len = desc->len;

            curr_feat->feat.ruby.base_comid = be16toh(desc->feat.ruby.base_comid);
            disc_data.comid = curr_feat->feat.ruby.base_comid;

            feat_no++;
            break;

        case OPAL_FEAT_PYRITEV100:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_pyritev100, (struct pyrite_feat *)&desc->feat.pyritev100, sizeof(struct pyrite_feat));
            discv->feat_avail_flag.feat_pyritev100 = 1;
            discv->sed_pyritev100.code = desc->code;
            discv->sed_pyritev100.rev = desc->rev;
            discv->sed_pyritev100.len = desc->len;

            curr_feat->feat.pyritev100.base_comid = be16toh(desc->feat.pyritev100.base_comid);
            disc_data.comid = curr_feat->feat.pyritev100.base_comid;

            feat_no++;
            break;

        case OPAL_FEAT_PYRITEV200:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_pyritev200, (struct pyrite_feat *)&desc->feat.pyritev200, sizeof(struct pyrite_feat));
            discv->feat_avail_flag.feat_pyritev200 = 1;
            discv->sed_pyritev200.code = desc->code;
            discv->sed_pyritev200.rev = desc->rev;
            discv->sed_pyritev200.len = desc->len;

            curr_feat->feat.pyritev200.base_comid = be16toh(desc->feat.pyritev200.base_comid);
            disc_data.comid = curr_feat->feat.pyritev200.base_comid;

            feat_no++;
            break;

        case OPAL_FEAT_DATA_RM:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_data_rm, (struct data_rm_feat *)&desc->feat.data_rm, sizeof(struct data_rm_feat));
            discv->feat_avail_flag.feat_data_rm = 1;

            feat_no++;
            break;

        case OPAL_FEAT_CNL:
            curr_feat = &disc_data.feats[feat_no];
            curr_feat->type = feat_code;
            memcpy(&discv->sed_cnl, (struct cnl_feat *)&desc->feat.cnl, sizeof(struct cnl_feat));
            discv->feat_avail_flag.feat_cnl = 1;
            discv->sed_cnl.code = desc->code;
            discv->sed_cnl.rev = desc->rev;
            discv->sed_cnl.len = desc->len;

            feat_no++;
            break;

        default:
            break;
        }
    }

    dev->comid = disc_data.comid;

    return SED_SUCCESS;
}

void opal_deinit_pt(struct sed_device *dev)
{
    if (dev->fd != 0) {
        close(dev->fd);
        dev->fd = 0;
    }

    if (dev->priv != NULL) {
        struct opal_device *opal_dev = dev->priv;

        if (opal_dev->req_buf != NULL) {
            free(opal_dev->req_buf);
            opal_dev->req_buf = NULL;
        }

        free(dev->priv);
        dev->priv = NULL;
    }

    opal_parser_deinit();
}

static uint64_t tper_prop_to_val(struct sed_device *dev, const char *tper_prop_name, uint64_t *val)
{
    struct sed_tper_properties *tper = &dev->discv.sed_tper_props;

    for (uint8_t j = 0; j < NUM_TPER_PROPS; j++) {
        if (strncmp(tper_prop_name, tper->property[j].key_name, strlen(tper_prop_name)) == 0) {
            *val = tper->property[j].value;
            return SED_SUCCESS;
        }
    }

    SEDCLI_DEBUG_PARAM("Invalid TPer property name: %s\n", tper_prop_name);
    return -EINVAL;
}

static int resize_io_buf(struct opal_device *dev, uint64_t size)
{
    if (dev == NULL)
        return -EINVAL;

    if (dev->req_buf != NULL)
        free(dev->req_buf);

    /*
     * Allocate memory for request and response buffers in a
     * single malloc request and split it later.
     */
    uint8_t *ptr = malloc(sizeof(*dev->req_buf) * 2 * size);
    if (!ptr)
        return -ENOMEM;

    memset(ptr, 0, sizeof(*ptr) * 2 * size);

    dev->req_buf = &ptr[0];
    dev->resp_buf = &ptr[size];
    dev->req_buf_size = sizeof(*dev->req_buf) * size;
    dev->resp_buf_size = sizeof(*dev->resp_buf) * size;

    return SED_SUCCESS;
}

int opal_init_pt(struct sed_device *dev, const char *device_path, bool try)
{
    dev->fd = 0;
    dev->priv = NULL;

    int ret = open_dev(device_path, try);
    if (ret < 0) {
        SEDCLI_DEBUG_PARAM("Error in opening the device: %d", ret);
        return -ENODEV;
    }

    dev->fd = ret;

    /* Initializing the parser list */
    ret = opal_parser_init();
    if (ret) {
        SEDCLI_DEBUG_MSG("Error in initializing the parser list.\n");
        ret = -EINVAL;
        goto init_deinit;
    }

    struct opal_device *opal_dev = malloc(sizeof(*opal_dev));
    if (opal_dev == NULL) {
        SEDCLI_DEBUG_MSG("Unable to allocate memory.\n");
        dev->priv = NULL;
        ret = -ENOMEM;
        goto init_deinit;
    }

    memset(opal_dev, 0, sizeof(*opal_dev));
    dev->priv = opal_dev;

    opal_dev->session.tsn = opal_dev->session.hsn = 0;
    opal_dev->req_buf = opal_dev->resp_buf = NULL;

    ret = resize_io_buf(opal_dev, MIN_IO_BUFFER_LEN);
    if (ret) {
        SEDCLI_DEBUG_MSG("Unable to resize IO buffer.\n");
        goto init_deinit;
    }

    ret = opal_dev_discovery(dev);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error in discovery.\n");
        goto init_deinit;
    }

    int host_prop_ret = opal_host_prop(dev, NULL, NULL);
    if (host_prop_ret == SED_SUCCESS) {
        uint64_t max_com_pkt_sz = 0;
        ret = tper_prop_to_val(dev, "MaxComPacketSize", &max_com_pkt_sz);
        if (ret)
            goto init_deinit;

        ret = resize_io_buf(opal_dev, max_com_pkt_sz);
        if (ret) {
            SEDCLI_DEBUG_MSG("Error re-sizing the IO buffer\n");
            return ret;
        }
    }

    // SEDCLI_DEBUG_PARAM("The device comid is: %u, MaxComPacketSize = %ld\n", opal_dev->comid, max_com_pkt_sz);

init_deinit:
    if (ret)
        opal_deinit_pt(dev);

    return ret;
}

static int opal_dev_discovery(struct sed_device *dev)
{
    if (dev == NULL)
        return -EINVAL;

    int ret = opal_level0_discovery_pt(dev);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error in dev discovery / level0 discovery.\n");
        return ret;
    }

    ret = opal_host_prop(dev, NULL, NULL);
    SEDCLI_DEBUG_PARAM("Setting host props status: %d.\n", ret);

    return ret;
}

int opal_dev_discovery_pt(struct sed_device *dev, struct sed_opal_device_discovery *discv)
{
    if (dev == NULL || discv == NULL)
        return -EINVAL;

    memcpy(discv, &dev->discv, sizeof(*discv));

    return 0;
}

static void build_ext_comid(uint8_t *buff, uint16_t comid)
{
    buff[0] = comid >> 8;
    buff[1] = comid & 0xFF;
    buff[2] = 0;
    buff[3] = 0;
}

static void init_req(struct opal_device *dev)
{
    memset(dev->req_buf, 0, dev->req_buf_size);
    struct opal_header *header = (struct opal_header*)dev->req_buf;

    build_ext_comid(header->compacket.ext_comid, dev->comid);
}

static void build_gr_lr(uint8_t *uid, uint8_t lr)
{
    memset(uid, 0, OPAL_UID_LENGTH);
    memcpy(uid, opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], OPAL_UID_LENGTH);

    if (lr == 0)
        return;

    uid[5] = LOCKING_RANGE_NON_GLOBAL;
    uid[7] = lr;

    return;
}

static int opal_rw_lock(struct opal_device *dev, uint8_t *lr_buff, uint32_t l_state, uint8_t lr,
    uint8_t *rl, uint8_t *wl)
{
    init_req(dev);

    build_gr_lr(lr_buff, lr);

    switch (l_state) {
    case SED_ACCESS_RO:
        *rl = 0;
        *wl = 1;
        break;

    case SED_ACCESS_WO:
        *rl = 1;
        *wl = 0;
        break;

    case SED_ACCESS_RW:
        *rl = *wl = 0;
        break;

    case SED_ACCESS_LK:
        *rl = *wl = 1;
        break;

    default:
        SEDCLI_DEBUG_MSG("Invalid locking state.\n");
        return OPAL_INVALID_PARAM;
    }

    return 0;
}

static void prepare_cmd_init(struct opal_device *dev, uint8_t *buf, size_t buf_len, int *pos,
    const uint8_t *uid, const uint8_t *method)
{
    /* setting up the comid */
    init_req(dev);

    /* Initializing the command */
    *pos += append_u8(buf + *pos, buf_len - *pos, OPAL_CALL);
    *pos += append_bytes(buf + *pos, buf_len - *pos, uid, OPAL_UID_LENGTH);
    *pos += append_bytes(buf + *pos, buf_len - *pos, method, OPAL_METHOD_LENGTH);
    *pos += append_u8(buf + *pos, buf_len - *pos, OPAL_STARTLIST);
}

static void prepare_cmd_end(uint8_t *buf, size_t buf_len, int *pos)
{
    /* Ending the command */
    *pos += append_u8(buf + *pos, buf_len - *pos, OPAL_ENDLIST);
    *pos += append_u8(buf + *pos, buf_len - *pos, OPAL_ENDOFDATA);
    *pos += append_u8(buf + *pos, buf_len - *pos, OPAL_STARTLIST);
    *pos += append_u8(buf + *pos, buf_len - *pos, 0);
    *pos += append_u8(buf + *pos, buf_len - *pos, 0);
    *pos += append_u8(buf + *pos, buf_len - *pos, 0);
    *pos += append_u8(buf + *pos, buf_len - *pos, OPAL_ENDLIST);
}

static void prepare_cmd_header(struct opal_device *dev, uint8_t *buf, uint64_t pos)
{
    struct opal_header *header;

    /* Update the request buffer pointer */
    buf += pos;

    pos += sizeof(*header);
    if (pos >= dev->req_buf_size) {
        SEDCLI_DEBUG_MSG("Command header out of buffer!.\n");
        return;
    }

    header = (struct opal_header *)dev->req_buf;

    /* Update the sessions to the headers */
    header->packet.session.tsn = htobe32(dev->session.tsn);
    header->packet.session.hsn = htobe32(dev->session.hsn);

    /* Update lengths and padding in Opal packet constructs */
    header->subpacket.length = htobe32(pos - sizeof(*header));

    if (pos % 4)
        pos += 4 - pos % 4;

    header->packet.length = htobe32(pos - sizeof(header->compacket) - sizeof(header->packet));
    header->compacket.length = htobe32(pos - sizeof(header->compacket));
}

static void prepare_req_buf(struct opal_device *dev, struct opal_req_item *data, int data_len,
    const uint8_t *uid, const uint8_t *method)
{
    int i, pos = 0;

    uint8_t *buf = dev->req_buf + sizeof(struct opal_header);
    size_t buf_len = dev->req_buf_size - sizeof(struct opal_header);

    prepare_cmd_init(dev, buf, buf_len, &pos, uid, method);

    if (data == NULL || data_len == 0)
        goto prep_end;

    for (i = 0; i < data_len; i++) {
        switch (data[i].type) {
        case OPAL_U8:
            pos += append_u8(buf + pos, buf_len - pos, data[i].val.byte);
            break;

        case OPAL_U64:
            pos += append_u64(buf + pos, buf_len - pos, data[i].val.uint);
            break;

        case OPAL_BYTES:
            pos += append_bytes(buf + pos, buf_len - pos, data[i].val.bytes, data[i].len);
            break;
        }
    }

prep_end:
    prepare_cmd_end(buf, buf_len, &pos);

    prepare_cmd_header(dev, buf, pos);
}

static int check_header_lengths(struct opal_device *dev, size_t *sub_len)
{
    struct opal_header *header = (struct opal_header *)dev->resp_buf;

    size_t com_len = be32toh(header->compacket.length);
    size_t pack_len = be32toh(header->packet.length);
    *sub_len = be32toh(header->subpacket.length);

    // SEDCLI_DEBUG_PARAM("Response size: compacket: %ld, packet: %ld, subpacket: %ld\n", com_len, pack_len, sub_len);

    if (com_len == 0 || pack_len == 0 || *sub_len == 0) {
        SEDCLI_DEBUG_PARAM("Bad header length. Compacket: %ld, Packet: %ld, Subpacket: %ld\n", com_len, pack_len, *sub_len);
        SEDCLI_DEBUG_MSG("The response can't be parsed.\n");
        return -EINVAL;
    }

    return SED_SUCCESS;
}

static bool resp_token_match(const struct opal_token *token, uint8_t match)
{
    if (token == NULL || token->type != OPAL_DTA_TOKENID_TOKEN ||
        token->pos[0] != match)
        return false;

    return true;
}

static uint8_t check_resp_status(struct opal_parsed_payload *payload)
{
    struct opal_token *token = payload->tokens[0];
    if (resp_token_match(token, OPAL_ENDOFSESSION))
        return 0;

    if (resp_token_match(token, OPAL_STARTTRANSACTON))
        return 0;

    int num = payload->len;
    if (num < 5)
        return DTAERROR_NO_METHOD_STATUS;

    uint8_t shift = 0;
    if (resp_token_match(payload->tokens[num - 1], OPAL_EMPTYATOM))
        shift = 1;

    if (resp_token_match(token, OPAL_ENDTRANSACTON))
        return payload->tokens[num - 1 - shift]->vals.uint;

    token = payload->tokens[num - 5 - shift];
    if (!resp_token_match(token, OPAL_STARTLIST))
        return DTAERROR_NO_METHOD_STATUS;

    token = payload->tokens[num - 1 - shift];
    if (!resp_token_match(token, OPAL_ENDLIST))
        return DTAERROR_NO_METHOD_STATUS;

    return payload->tokens[num - 4 - shift]->vals.uint;
}

static int opal_snd_rcv_cmd_parse_chk(int fd, struct opal_device *dev, bool end_session)
{
    /* Send command and receive results */
    int ret = opal_send_recv(fd, TCG_SECP_01, dev->comid, dev->req_buf, dev->req_buf_size, dev->resp_buf,
        dev->resp_buf_size);
    if (ret) {
        SEDCLI_DEBUG_PARAM("NVM error: %d\n", ret);
        nvme_error = ret;
        return ret;
    }

    size_t subpacket_len = 0;
    ret = check_header_lengths(dev, &subpacket_len);
    if (ret)
        return ret;

    if (end_session) {
        dev->session.tsn = 0;
        dev->session.hsn = 0;
    }

    uint8_t *data_buf = dev->resp_buf + sizeof(struct opal_header);
    ret = opal_parse_data_payload(data_buf, subpacket_len, &dev->payload);
    if (ret == -EINVAL) {
        SEDCLI_DEBUG_MSG("Error in parsing the response\n");
        return ret;
    }

    ret = check_resp_status(&dev->payload);

    return ret;
}

static uint8_t get_payload_string(struct opal_device *dev, uint8_t num)
{
    uint8_t jmp;

    // Check if token is a byte string.
    if (dev->payload.tokens[num]->type != OPAL_DTA_TOKENID_BYTESTRING)
        return 0;

    switch (dev->payload.tokens[num]->width) {
        case OPAL_WIDTH_TINY:
        case OPAL_WIDTH_SHORT:
            jmp = 1;
            break;

        case OPAL_WIDTH_MEDIUM:
            jmp = 2;
            break;

        case OPAL_WIDTH_LONG:
            jmp = 4;
            break;

        default:
            SEDCLI_DEBUG_MSG("Token has invalid width and can't be parsed\n");
            return 0;
    }

    return jmp;
}

static int validate_session(struct opal_device *dev)
{
    dev->session.hsn = dev->payload.tokens[4]->vals.uint;
    dev->session.tsn = dev->payload.tokens[5]->vals.uint;

    // SEDCLI_DEBUG_PARAM("Session hsn: %d, session tsn: %d\n", dev->session.hsn, dev->session.tsn);

    if (dev->session.hsn != GENERIC_HOST_SESSION_NUM ||
        dev->session.tsn < RSVD_TPER_SESSION_NUM) {
        SEDCLI_DEBUG_MSG("Error syncing session(invalid session numbers)\n");
        return -EINVAL;
    }

    return 0;
}

static void parse_tper_host_prop(struct sed_device *device)
{
    struct opal_device *dev = device->priv;
    int payload_len = dev->payload.len;
    struct sed_tper_properties *tper = &device->discv.sed_tper_props;

    /* TPer properties are returned as key-value pairs */
    for (uint8_t i = 0, j = 0; i < payload_len; i++) {
        if (resp_token_match(dev->payload.tokens[i], OPAL_STARTNAME)) {
            int jmp = get_payload_string(dev, i + 1);
            if (jmp == 0) {
                tper = &device->discv.sed_host_props;
                j = 0;
                continue;
            }

            uint8_t key_len = dev->payload.tokens[i + 1]->len - jmp;

            assert(j < NUM_TPER_PROPS);
            memcpy(tper->property[j].key_name,
                dev->payload.tokens[i + 1]->pos + jmp,
                key_len);
            tper->property[j].value = dev->payload.tokens[i + 2]->vals.uint;
            j++;
        }
    }
}

static int opal_set_buf_prep(struct sed_device *device, uint8_t *uid, struct opal_req_item *cmd, size_t cmd_len)
{
    prepare_req_buf(device->priv, cmd, cmd_len, uid, opal_method[OPAL_SET_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(device->fd, device->priv, false);

    struct opal_device *dev = device->priv;
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item host_to_tper_cmd_prefix[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_HOSTPROPERTIES } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
};

static struct opal_req_item host_to_tper_cmd_chunk[] ={
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } },
    { .type = OPAL_U64, .len = 1, .val = { .uint =  0 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static struct opal_req_item host_to_tper_cmd_postfix[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static struct opal_req_item host_to_tper_cmd_all[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_HOSTPROPERTIES } }, // HostProperties
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } },
    { .type = OPAL_U64, .len = 1, .val = { .uint =  1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } },
    { .type = OPAL_U64, .len = 1, .val = { .uint =  1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } },
    { .type = OPAL_U64, .len = 1, .val = { .uint =  1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } },
    { .type = OPAL_U64, .len = 1, .val = { .uint =  1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } },
    { .type = OPAL_U64, .len = 1, .val = { .uint =  1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } },
    { .type = OPAL_U64, .len = 1, .val = { .uint =  1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_host_prop(struct sed_device *device, const char *props, uint32_t *vals)
{
    SEDCLI_DEBUG_MSG("Starting host props.\n");

    int ret = 0;

    struct opal_req_item *req = NULL;
    struct opal_req_item *host_to_tper_cmd_chunks = NULL;
    struct opal_req_item *host_to_tper_cmd = NULL;
    size_t size = 0;

    struct opal_device *dev = device->priv;

    if (props) {
        uint8_t props_count = 0;
        while (props[props_count * MAX_PROP_NAME_LEN] != 0 && props_count < NUM_HOST_PROPS)
            props_count++;

        if (props_count == 0) {
            SEDCLI_DEBUG_MSG("Host props - no props to send.\n");
            return -EINVAL;
        }

        const size_t chunk_size = ARRAY_SIZE(host_to_tper_cmd_chunk);
        const size_t props_size = props_count * chunk_size;

        host_to_tper_cmd_chunks = (struct opal_req_item *)malloc(sizeof(struct opal_req_item) * props_size);
        if (host_to_tper_cmd_chunks == NULL) {
            ret = -ENOMEM;
            goto put_tokens;
        }

        for (uint8_t i = 0; i < props_count; i++) {
            memcpy(host_to_tper_cmd_chunks + chunk_size * i, host_to_tper_cmd_chunk, sizeof(struct opal_req_item) * chunk_size);
            char *prop_name = (char *)&props[i * MAX_PROP_NAME_LEN];
            host_to_tper_cmd_chunks[1 + chunk_size * i].val.bytes = (uint8_t *)prop_name;
            host_to_tper_cmd_chunks[1 + chunk_size * i].len = strlen(prop_name);
            host_to_tper_cmd_chunks[2 + chunk_size * i].val.uint = vals[i];
        }

        host_to_tper_cmd = (struct opal_req_item *)malloc(sizeof(struct opal_req_item) *
            (ARRAY_SIZE(host_to_tper_cmd_prefix) + ARRAY_SIZE(host_to_tper_cmd_postfix) + props_size));
        if (host_to_tper_cmd == NULL) {
            ret = -ENOMEM;
            goto put_tokens;
        }

        memcpy(host_to_tper_cmd, host_to_tper_cmd_prefix,
            sizeof(struct opal_req_item) * ARRAY_SIZE(host_to_tper_cmd_prefix));
        memcpy(host_to_tper_cmd + ARRAY_SIZE(host_to_tper_cmd_prefix), host_to_tper_cmd_chunks,
            sizeof(struct opal_req_item) * props_size);
        memcpy(host_to_tper_cmd + ARRAY_SIZE(host_to_tper_cmd_prefix) + props_count * chunk_size, host_to_tper_cmd_postfix,
            sizeof(struct opal_req_item) * ARRAY_SIZE(host_to_tper_cmd_postfix));

        req = host_to_tper_cmd;
        size = ARRAY_SIZE(host_to_tper_cmd_prefix) + ARRAY_SIZE(host_to_tper_cmd_postfix) + props_size;
    } else {
        char *names[] = { "MaxComPacketSize", "MaxPacketSize", "MaxIndTokenSize", "MaxPackets", "MaxSubpackets",
            "MaxMethods" };
        uint32_t values[NUM_HOST_PROPS] = { 0 };

        FILE *tfp = fopen("properties", "r");
        if (tfp) {
            char line[256] = { 0 } ;
            while (fgets(line, sizeof(line), tfp)) {
                for (uint8_t i = 0; i < ARRAY_SIZE(names); i++) {
                    char name_tmp[256] = { 0 };
                    memcpy(name_tmp, names[i], strlen(names[i]));
                    memcpy(name_tmp + strlen(name_tmp), "\n", 1);
                    if (strncmp(line, name_tmp, 255) == 0) {
                        if (fgets(line, sizeof(line), tfp)) {
                            values[i] = strtoul(line, NULL, 10);
                            break;
                        }
                    }
                }

                memset(line, 0, sizeof(line));
            }
            fclose(tfp);
        }

        bool any_found = false;
        for (uint8_t i = 0; i < ARRAY_SIZE(names); i++) {
            host_to_tper_cmd_all[4 + 4 * i].val.bytes = (uint8_t *)names[i];
            host_to_tper_cmd_all[4 + 4 * i].len = strlen(names[i]);

            struct sed_tper_properties *tper = &device->discv.sed_tper_props;
            for (uint8_t j = 0; j < NUM_TPER_PROPS; j++) {
                if (strncmp(names[i], tper->property[j].key_name, 255) == 0 || values[i] != 0) {
                    uint32_t val = values[i] != 0 ? values[i] : tper->property[j].value;
                    host_to_tper_cmd_all[5 + 4 * i].val.uint = val;
                    //SEDCLI_DEBUG_PARAM("Host prop %s: %lu\n", host_to_tper_cmd_all[4 + 4 * i].val.bytes, host_to_tper_cmd_all[5 + 4 * i].val.uint);
                    any_found = true;
                    break;
                }
            }
        }

        if (any_found) {
            req = host_to_tper_cmd_all;
            size = ARRAY_SIZE(host_to_tper_cmd_all);
        }
    }

    prepare_req_buf(dev, req, size, opal_uid[OPAL_SM_UID], opal_method[OPAL_PROPERTIES_METHOD_UID]);

    ret = opal_snd_rcv_cmd_parse_chk(device->fd, dev, false);
    if (ret) {
        SEDCLI_DEBUG_MSG("Host props - send receive error.\n");
        goto put_tokens;
    }

    parse_tper_host_prop(device);

put_tokens:
    if (host_to_tper_cmd_chunks)
        free(host_to_tper_cmd_chunks);

    if (host_to_tper_cmd)
        free(host_to_tper_cmd);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    SEDCLI_DEBUG_MSG("Host props done.\n");

    return ret;
}

static struct opal_req_item start_sess_cmd[] = {
    { .type = OPAL_U64, .len = 8, .val = { .uint = GENERIC_HOST_SESSION_NUM } },
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } }, /* Admin SP | Locking SP */
    { .type = OPAL_U8, .len = 1, .val = { .byte = 1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } },
    { .type = OPAL_BYTES, .len = 1, .val = { .bytes = NULL } }, /* Host Challenge -> key; key_len */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 3 } },
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } }, /* Host Signing Authority: MSID, SID, PSID */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

int opal_host_prop_pt(struct sed_device *dev, const char *props, uint32_t *vals)
{
    if (dev == NULL)
        return -EINVAL;

    uint8_t props_count = 0;
    while (props[props_count * MAX_PROP_NAME_LEN] != 0 && props_count < NUM_HOST_PROPS)
        props_count++;

    uint8_t values_count = 0;
    while (vals[values_count] != 0 && values_count < NUM_HOST_PROPS)
        values_count++;

    if (props_count != values_count) {
        SEDCLI_DEBUG_MSG("Properties count do not match with values count.\n");
        return -EINVAL;
    }

    int ret = opal_host_prop(dev, props, vals);
    if (ret)
        return ret;

    return 0;
}

static void prep_session_buff(uint8_t *sp_uid, const struct sed_key *key, uint8_t *auth_uid)
{
    /* SP */
    start_sess_cmd[1].val.bytes = sp_uid;

    if (!key)
        return;

    /* Host Challenge */
    start_sess_cmd[5].val.bytes = (uint8_t *)key->key;
    start_sess_cmd[5].len = key->len;

    /* Host Signing Authority */
    start_sess_cmd[9].val.bytes = auth_uid;
}

static int opal_start_generic_session(int fd, struct opal_device *dev, uint8_t *sp_uid, uint8_t *auth_uid,
    const struct sed_key *key)
{
    bool auth_is_anybody = compare_uid(auth_uid, opal_uid[OPAL_ANYBODY_UID]);
    if (auth_is_anybody == false && key == NULL) {
        SEDCLI_DEBUG_MSG("Must provide password for this authority\n");
        return -EINVAL;
    }

    int cmd_len = ARRAY_SIZE(start_sess_cmd);

    if (auth_is_anybody == false) {
        prep_session_buff(sp_uid, key, auth_uid);
    } else {
        prep_session_buff(sp_uid, NULL, NULL);
        /* Only the first 3 tokens are required for anybody authority */
        cmd_len = 3;
    }

    SEDCLI_DEBUG_MSG("Starting generic session.\n");
    prepare_req_buf(dev, start_sess_cmd, cmd_len, opal_uid[OPAL_SM_UID], opal_method[OPAL_STARTSESSION_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
    if (ret) {
        SEDCLI_DEBUG_PARAM("Error in starting the session with status: %d\n", ret);
        goto put_tokens;
    }

    ret = validate_session(dev);
    if (ret) {
        SEDCLI_DEBUG_PARAM("Error in validating the session with status: %d\n", ret);
        goto put_tokens;
    }

    SEDCLI_DEBUG_MSG("Session started.\n");

put_tokens:
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int opal_start_sid_asp_session(int fd, struct opal_device *dev, char *msid_pin, size_t msid_pin_len)
{
    struct sed_key key;
    if (msid_pin_len > sizeof(key.key)) {
        SEDCLI_DEBUG_MSG("MSID_PIN Length Out of Boundary\n");
        return -ERANGE;
    }

    sed_key_init(&key, (char *)msid_pin, msid_pin_len);

    return opal_start_generic_session(fd, dev, opal_uid[OPAL_ADMIN_SP_UID], opal_uid[OPAL_SID_UID], &key);
}

static int opal_start_admin1_lsp_session(int fd, struct opal_device *dev, const struct sed_key *key)
{
    return opal_start_generic_session(fd, dev, opal_uid[OPAL_LOCKING_SP_UID], opal_uid[OPAL_ADMIN1_UID], key);
}

static int opal_start_auth_session(int fd, struct opal_device *dev, bool sum, uint8_t lr, const uint8_t *lr_uid,
    const uint8_t *auth_uid, const struct sed_key *key)
{
    uint8_t user_uid[OPAL_UID_LENGTH];
    if (sum) {
        if (lr_uid != NULL)
            memcpy(user_uid, lr_uid, OPAL_UID_LENGTH);
        else {
            memcpy(user_uid, opal_uid[OPAL_USER1_UID], OPAL_UID_LENGTH);
            user_uid[7] = lr;
        }
    } else {
        memcpy(user_uid, auth_uid, OPAL_UID_LENGTH);
    }

    prep_session_buff(opal_uid[OPAL_LOCKING_SP_UID], key, user_uid);

    SEDCLI_DEBUG_MSG("Starting authority session.\n");
    prepare_req_buf(dev, start_sess_cmd, ARRAY_SIZE(start_sess_cmd), opal_uid[OPAL_SM_UID], opal_method[OPAL_STARTSESSION_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error in Starting a auth session\n");
        goto put_tokens;
    }

    ret = validate_session(dev);

put_tokens:
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int opal_end_session(int fd, struct opal_device *dev)
{
    init_req(dev);

    uint8_t *buf = dev->req_buf + sizeof(struct opal_header);
    size_t buf_len = dev->req_buf_size - sizeof(struct opal_header);
    int pos = append_u8(buf, buf_len, OPAL_ENDOFSESSION);

    prepare_cmd_header(dev, buf, pos);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, true);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    SEDCLI_DEBUG_MSG("Session ended.\n");

    return ret;
}

static int opal_transactions(int fd, struct opal_device *dev, bool start, uint8_t status)
{
    init_req(dev);

    uint8_t *buf = dev->req_buf + sizeof(struct opal_header);
    size_t buf_len = dev->req_buf_size - sizeof(struct opal_header);
    int pos = 0;

    if (start) {
        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTTRANSACTON);
        pos += append_u8(buf + pos, buf_len - pos, 0x0);
    } else {
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDTRANSACTON);
        pos += append_u8(buf + pos, buf_len - pos, status);
    }

    prepare_cmd_header(dev, buf, pos);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

     return ret;
}

static int opal_revert(int fd, struct opal_device *dev, uint8_t *uid)
{
    prepare_req_buf(dev, NULL, 0, uid, opal_method[OPAL_REVERT_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item opal_revert_sp_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U64, .len = 4, .val = { .uint = KEEP_GLOBAL_RANGE_KEY } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_FALSE } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_revert_lsp(int fd, struct opal_device *dev, bool keep_global_range_key)
{
    opal_revert_sp_cmd[2].val.byte = keep_global_range_key ? OPAL_TRUE : OPAL_FALSE;

    prepare_req_buf(dev, opal_revert_sp_cmd, ARRAY_SIZE(opal_revert_sp_cmd),
        opal_uid[OPAL_THIS_SP_UID],
        opal_method[OPAL_REVERTSP_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item opal_generic_get_column_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTCOLUMN } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* start column */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDCOLUMN } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* end column */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
};

static int opal_generic_get_column(int fd, struct opal_device *dev, const uint8_t *uid, uint64_t start_col,
    uint64_t end_col)
{
    opal_generic_get_column_cmd[3].val.uint = start_col;
    opal_generic_get_column_cmd[7].val.uint = end_col;

    prepare_req_buf(dev, opal_generic_get_column_cmd, ARRAY_SIZE(opal_generic_get_column_cmd), uid,
        opal_method[OPAL_GET_METHOD_UID]);

    return opal_snd_rcv_cmd_parse_chk(fd, dev, false);
}

static struct opal_req_item opal_generic_set_column_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_generic_set_column(int fd, struct opal_device *dev, const uint8_t *uid, uint64_t col,
    struct sed_opal_col_info *col_info)
{
    opal_generic_set_column_cmd[4].val.uint = col;

    if (col_info->type ==  SED_DATA_BYTESTRING) {
        opal_generic_set_column_cmd[5].type = OPAL_BYTES;
        opal_generic_set_column_cmd[5].val.bytes = (uint8_t *)col_info->data;
        opal_generic_set_column_cmd[5].len = col_info->len;
    } else if (col_info->type ==  SED_DATA_SINT || col_info->type ==  SED_DATA_UINT ||
               col_info->type == SED_DATA_TOKEN) {
        opal_generic_set_column_cmd[5].type = OPAL_U64;
        opal_generic_set_column_cmd[5].val.uint = *((uint64_t *)col_info->data);
        opal_generic_set_column_cmd[5].len = 1;
    } else {
        SEDCLI_DEBUG_MSG("Invalid data type specified\n");
        return -EINVAL;
    }

    prepare_req_buf(dev, opal_generic_set_column_cmd, ARRAY_SIZE(opal_generic_set_column_cmd), uid,
        opal_method[OPAL_SET_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item opal_generic_get_byte_table_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTROW } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* start row */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDROW } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* end row */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
};

static int opal_generic_get_byte_table(int fd, struct opal_device *dev, const uint8_t *uid, uint64_t start_row,
    uint64_t end_row)
{
    opal_generic_get_byte_table_cmd[3].val.uint = start_row;
    opal_generic_get_byte_table_cmd[7].val.uint = end_row;

    prepare_req_buf(dev, opal_generic_get_byte_table_cmd, ARRAY_SIZE(opal_generic_get_column_cmd), uid,
        opal_method[OPAL_GET_METHOD_UID]);

    return opal_snd_rcv_cmd_parse_chk(fd, dev, false);
}

/*
 * ENDLIST, ENDOFDATA, STARTLIST, 0, 0, 0 and ENDLIST.
 * These 7 bytes are always required to conclude the opal command.
 */
#define CMD_END_BYTES_NUM 7

static int opal_generic_set_byte_table(int fd, struct opal_device *dev, const uint8_t *uid, uint64_t start_row,
    uint64_t end_row, uint8_t *buffer)
{
    uint8_t *buf;
    uint64_t len = 0, remaining_buff_size;
    int pos = 0, ret = 0;
    size_t buf_len, size;

    size = end_row - start_row + 1;

    buf = dev->req_buf + sizeof(struct opal_header);
    buf_len = dev->req_buf_size - sizeof(struct opal_header);

    prepare_cmd_init(dev, buf, buf_len, &pos, uid, opal_method[OPAL_SET_METHOD_UID]);

    pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
    pos += append_u8(buf + pos, buf_len - pos, OPAL_WHERE);
    pos += append_u64(buf + pos, buf_len - pos, 0);
    pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);

    pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
    pos += append_u8(buf + pos, buf_len - pos, OPAL_VALUES);

    /*
     * The append_bytes used below, dependng upon the len, either uses
     * short_atom_bytes_header (returns 1) or medium_atom_bytes_header
     * (returns 2) or long_atom_bytes_header (returns 4).
     * Hence we consider the MAX of the three i.e, 4.
     *
     * The 1 byte is for the following ENDNAME token.
     */
    remaining_buff_size = buf_len - (pos + 4 + 1 + CMD_END_BYTES_NUM);

    len = MIN(remaining_buff_size, size);

    pos += append_bytes(buf + pos, buf_len - pos, buffer, len);
    pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);

    prepare_cmd_end(buf, buf_len, &pos);
    prepare_cmd_header(dev, buf, pos);

    ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int opal_get_msid(int fd, struct opal_device *dev, char *key, uint8_t *key_len)
{
    int ret = opal_generic_get_column(fd, dev, opal_uid[OPAL_C_PIN_MSID_UID], OPAL_PIN, OPAL_PIN);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error parsing payload\n");
        goto put_tokens;
    }

    uint8_t jmp = get_payload_string(dev, 4);
    *key_len = dev->payload.tokens[4]->len - jmp;
    memcpy(key, dev->payload.tokens[4]->pos + jmp, *key_len);

put_tokens:
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int opal_get_lsp_lifecycle(int fd, struct opal_device *dev, enum opaluid sp_uid)
{
    int ret = opal_generic_get_column(fd, dev, opal_uid[sp_uid], OPAL_LIFECYCLE, OPAL_LIFECYCLE);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error parsing payload\n");
        goto put_tokens;
    }

    ret = dev->payload.tokens[4]->vals.uint;

put_tokens:
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int opal_activate_sp(int fd, struct opal_device *dev, uint8_t *target_sp_uid, bool reactivate, uint32_t *lr,
    uint8_t num_lrs, bool is_locking_table, uint8_t range_start_length_policy, uint32_t *dsts, uint8_t num_dsts,
    const struct sed_key *admin1_pwd)
{
    uint8_t *buf = dev->req_buf + sizeof(struct opal_header);
    size_t buf_len = dev->req_buf_size - sizeof(struct opal_header);

    int pos = 0;
    prepare_cmd_init(dev, buf, buf_len, &pos,
        target_sp_uid,
        opal_method[reactivate ? OPAL_REACTIVATE_METHOD_UID : OPAL_ACTIVATE_METHOD_UID]);

    if (is_locking_table && num_lrs == 1) {
        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
        pos += append_u64(buf + pos, buf_len - pos, SUM_RANGES);
        pos += append_bytes(buf + pos, buf_len - pos, opal_uid[OPAL_LOCKING_TABLE_UID], OPAL_UID_LENGTH);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);
    }
    else if (num_lrs > 0) {
        uint8_t user_lr[OPAL_UID_LENGTH];
        memcpy(user_lr, opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], OPAL_UID_LENGTH);
        user_lr[5] = LOCKING_RANGE_NON_GLOBAL;

        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
        pos += append_u64(buf + pos, buf_len - pos, SUM_RANGES);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTLIST);
        for (uint8_t i = 0; i < num_lrs; i++) {
            if (lr[i] == 0)
                pos += append_bytes(buf + pos, buf_len - pos, opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], OPAL_UID_LENGTH);
            else {
                user_lr[7] = lr[i];
                pos += append_bytes(buf + pos, buf_len - pos, user_lr, OPAL_UID_LENGTH);
            }
        }
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDLIST);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);
    }

    if (range_start_length_policy != (uint8_t)-1) {
        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
        pos += append_u64(buf + pos, buf_len - pos, SUM_RANGE_START_LENGHT_POLICY);
        pos += append_u8(buf + pos, buf_len - pos, range_start_length_policy);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);
    }

    if (num_dsts && dsts[0] != 0) {
        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
        pos += append_u64(buf + pos, buf_len - pos, SUM_DATASTORE_TABLE_SIZES);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTLIST);
        for (uint8_t i = 0; i < num_dsts; i++) {
            pos += append_u64(buf + pos, buf_len - pos, dsts[i]);
        }
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDLIST);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);
    }

    if (admin1_pwd && admin1_pwd->key[0] != 0) {
        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
        pos += append_u64(buf + pos, buf_len - pos, SUM_ADMIN1_PIN);
        pos += append_bytes(buf + pos, buf_len - pos, (uint8_t *)admin1_pwd->key, admin1_pwd->len);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);
    }

    prepare_cmd_end(buf, buf_len, &pos);

    prepare_cmd_header(dev, buf, pos);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item add_user_to_lr_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 3 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 4, .val = { .bytes = opal_uid[OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID] } },
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 4, .val = { .bytes = opal_uid[OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID] } },
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 4, .val = { .bytes = opal_uid[OPAL_HALF_UID_BOOLEAN_ACE_UID] } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 1 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int add_user_to_lr(int fd, struct opal_device *dev, uint32_t access_type, uint8_t lr, uint32_t who, bool admin)
{
    uint8_t lr_buff[OPAL_UID_LENGTH];
    memcpy(lr_buff, opal_uid[OPAL_LOCKINGRANGE_ACE_RDLOCKED_UID], OPAL_UID_LENGTH);

    if (access_type == OPAL_RW)
        memcpy(lr_buff, opal_uid[OPAL_LOCKINGRANGE_ACE_WRLOCKED_UID], OPAL_UID_LENGTH);

    lr_buff[7] = lr;

    uint8_t user_uid[OPAL_UID_LENGTH];
    if (admin)
        memcpy(user_uid, opal_uid[OPAL_ADMIN1_UID], OPAL_UID_LENGTH);
    else
        memcpy(user_uid, opal_uid[OPAL_USER1_UID], OPAL_UID_LENGTH);
    user_uid[7] = who;

    add_user_to_lr_cmd[8].val.bytes = user_uid;
    add_user_to_lr_cmd[12].val.bytes = user_uid;

    prepare_req_buf(dev, add_user_to_lr_cmd, ARRAY_SIZE(add_user_to_lr_cmd), lr_buff, opal_method[OPAL_SET_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item enable_user_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 5 } }, /* Enable */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_TRUE } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_enable_user(int fd, struct opal_device *dev, uint8_t *user_uid)
{
    prepare_req_buf(dev, enable_user_cmd, ARRAY_SIZE(enable_user_cmd), user_uid, opal_method[OPAL_SET_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item generic_enable_disable_global_lr_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_READLOCKENABLED } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Read Lock Enabled */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_WRITELOCKENABLED } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Write Lock Enabled*/
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_READLOCKED } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Read Locked */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_WRITELOCKED } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Write Locked */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static void generic_enable_disable_global_lr(struct opal_device *dev, const uint8_t *uid, bool rle, bool wle,
    bool rl, bool wl)
{
    generic_enable_disable_global_lr_cmd[5].val.byte = rle;
    generic_enable_disable_global_lr_cmd[9].val.byte = wle;
    generic_enable_disable_global_lr_cmd[13].val.byte = rl;
    generic_enable_disable_global_lr_cmd[17].val.byte = wl;

    prepare_req_buf(dev, generic_enable_disable_global_lr_cmd, ARRAY_SIZE(generic_enable_disable_global_lr_cmd), uid,
        opal_method[OPAL_SET_METHOD_UID]);
}

int opal_setup_global_range_pt(struct sed_device *dev, const struct sed_key *key, enum SED_FLAG_TYPE rle,
    enum SED_FLAG_TYPE wle)
{
    struct opal_device *opal_dev = dev->priv;

    int status = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
    if (status)
        goto end_session;

    generic_enable_disable_global_lr_cmd[5].val.byte = rle == SED_FLAG_ENABLED ? 1 : 0;
    generic_enable_disable_global_lr_cmd[9].val.byte = wle == SED_FLAG_ENABLED ? 1 : 0;

    prepare_req_buf(opal_dev, generic_enable_disable_global_lr_cmd, ARRAY_SIZE(generic_enable_disable_global_lr_cmd),
        opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], opal_method[OPAL_SET_METHOD_UID]);

    status = opal_snd_rcv_cmd_parse_chk(dev->fd, opal_dev, false);

    opal_put_all_tokens(opal_dev->payload.tokens, &opal_dev->payload.len);

end_session:
    opal_end_session(dev->fd, opal_dev);

    return status;
}

static struct opal_req_item setup_locking_range_prefix[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_RANGESTART } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* Range Start */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_RANGELENGTH } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* Range Length */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static struct opal_req_item setup_locking_range_postifix[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static struct opal_req_item setup_locking_range_rwle[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_READLOCKENABLED } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_setup_locking_range(int fd, struct opal_device *dev, uint8_t *uid, uint64_t range_start,
    uint64_t range_length, enum SED_FLAG_TYPE rle, enum SED_FLAG_TYPE wle)
{
    uint8_t nonglobal_lr[OPAL_UID_LENGTH];
    memcpy(nonglobal_lr, opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], OPAL_UID_LENGTH);
    nonglobal_lr[5] = LOCKING_RANGE_NON_GLOBAL;
    nonglobal_lr[7] = 0;

    struct opal_req_item *cmd = NULL;

    if (!memcmp(uid, nonglobal_lr, ARRAY_SIZE(nonglobal_lr))) {
        generic_enable_disable_global_lr(dev, uid, rle, wle, 0, 0);
    } else {
        setup_locking_range_prefix[5].val.uint = range_start;
        setup_locking_range_prefix[9].val.uint = range_length;

        size_t prefix_size = ARRAY_SIZE(setup_locking_range_prefix);
        size_t postfix_size = ARRAY_SIZE(setup_locking_range_postifix);
        size_t flag_size = ARRAY_SIZE(setup_locking_range_rwle);
        size_t cmd_size = prefix_size + 2 * flag_size + postfix_size;
        cmd = malloc(sizeof(struct opal_req_item) * cmd_size);
        if (cmd == NULL)
            return -ENOMEM;

        memcpy(cmd, setup_locking_range_prefix, sizeof(struct opal_req_item) * prefix_size);

        uint8_t flags = 0;
        if (rle != SED_FLAG_UNDEFINED) {
            setup_locking_range_rwle[1].val.byte = OPAL_READLOCKENABLED;
            setup_locking_range_rwle[2].val.byte = rle == SED_FLAG_ENABLED ? 1 : 0;
            memcpy(cmd + prefix_size, setup_locking_range_rwle, sizeof(struct opal_req_item) * flag_size);
            flags++;
        }

        if (wle != SED_FLAG_UNDEFINED) {
            setup_locking_range_rwle[1].val.byte = OPAL_WRITELOCKENABLED;
            setup_locking_range_rwle[2].val.byte = wle == SED_FLAG_ENABLED ? 1 : 0;
            memcpy(cmd + prefix_size + flag_size * flags, setup_locking_range_rwle, sizeof(struct opal_req_item) * flag_size);
            flags++;
        }

        memcpy(cmd + prefix_size + flag_size * flags, setup_locking_range_postifix, sizeof(struct opal_req_item) * postfix_size);

        prepare_req_buf(dev, cmd, cmd_size, uid, opal_method[OPAL_SET_METHOD_UID]);
    }

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    if (cmd)
        free(cmd);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int opal_lock_unlock_sum(int fd, struct opal_device *dev, uint32_t access_type, uint8_t lr)
{
    uint8_t lr_buff[OPAL_UID_LENGTH];
    uint8_t read_lock = 1, write_lock = 1;
    int ret = opal_rw_lock(dev, lr_buff, access_type, lr, &read_lock, &write_lock);
    if (ret)
        return ret;

    generic_enable_disable_global_lr(dev, lr_buff, 1, 1, read_lock, write_lock);

    ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item opal_lock_unlock_no_sum_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_READLOCKED } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Read Locked */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_WRITELOCKED } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Write Locked */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_lock_unlock_no_sum(int fd, struct opal_device *dev, uint32_t access_type, uint8_t lr)
{
    uint8_t lr_buff[OPAL_UID_LENGTH];
    uint8_t read_lock = 1, write_lock = 1;
    int ret = opal_rw_lock(dev, lr_buff, access_type, lr, &read_lock, &write_lock);
    if (ret)
        return ret;

    opal_lock_unlock_no_sum_cmd[5].val.byte = read_lock;
    opal_lock_unlock_no_sum_cmd[9].val.byte = write_lock;

    prepare_req_buf(dev, opal_lock_unlock_no_sum_cmd, ARRAY_SIZE(opal_lock_unlock_no_sum_cmd), lr_buff,
        opal_method[OPAL_SET_METHOD_UID]);

    ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item generic_pwd_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_PIN } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } }, /* The new pwd */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static void generic_pwd_func(struct opal_device *dev, const struct sed_key *key, const uint8_t *auth_uid)
{
    generic_pwd_cmd[5].val.bytes = (uint8_t *)key->key;
    generic_pwd_cmd[5].len = key->len;

    prepare_req_buf(dev, generic_pwd_cmd, ARRAY_SIZE(generic_pwd_cmd), auth_uid, opal_method[OPAL_SET_METHOD_UID]);
}

static int opal_set_password(int fd, struct opal_device *dev, uint8_t uid[OPAL_UID_LENGTH], const struct sed_key *key)
{
    generic_pwd_func(dev, key, uid);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static struct opal_req_item opal_set_mbr_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* MBR done or not */

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_set_mbr(int fd, struct opal_device *dev, uint8_t val, uint8_t en_disable)
{
    opal_set_mbr_cmd[4].val.byte = val;
    opal_set_mbr_cmd[5].val.byte = en_disable;

    prepare_req_buf(dev, opal_set_mbr_cmd, ARRAY_SIZE(opal_set_mbr_cmd), opal_uid[OPAL_MBRCONTROL_UID],
        opal_method[OPAL_SET_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int opal_set_mbr_done(int fd, struct opal_device *dev, uint8_t en_disable)
{
    return opal_set_mbr(fd, dev, OPAL_MBRDONE, en_disable);
}

static int opal_set_mbr_en_disable(int fd, struct opal_device *dev, uint8_t en_disable)
{
    return opal_set_mbr(fd, dev, OPAL_MBRENABLE, en_disable);
}

static int opal_erase(int fd, struct opal_device *dev, const uint8_t *uid)
{
    prepare_req_buf(dev, NULL, 0, uid, opal_method[OPAL_ERASE_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int get_table_length(int fd, struct opal_device *dev, enum opaluid table, uint64_t *len)
{
    uint8_t uid[OPAL_UID_LENGTH];
    const int half = OPAL_UID_LENGTH / 2;
    memcpy(uid, opal_uid[OPAL_TABLE_TABLE_UID], half);
    memcpy(uid + half, opal_uid[table], half);

    int ret = opal_generic_get_column(fd, dev, uid, OPAL_TABLE_ROW, OPAL_TABLE_ROW);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error parsing payload\n");
        ret = -1;
        goto put_tokens;
    }

    *len = dev->payload.tokens[4]->vals.uint;

put_tokens:
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int opal_generic_write_table(int fd, struct opal_device *dev, enum opaluid table, const uint8_t *data,
    uint64_t offset, uint64_t size)
{
    uint8_t *buf;
    uint64_t len = 0, index = 0, remaining_buff_size;
    int pos = 0;
    size_t buf_len;

    if (size == 0)
        return 0;

    int ret = get_table_length(fd, dev, table, &len);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error retrieving table length\n");
        return ret;
    }

    SEDCLI_DEBUG_PARAM("Table length is: %lu\n", len);

    if (size > len || offset > len - size) {
        SEDCLI_DEBUG_PARAM("The data doesn't fit in the table (%lu v/s %lu)\n", offset + size, len);
        return -ENOSPC;
    }

    while (index < size) {
        buf = dev->req_buf + sizeof(struct opal_header);
        buf_len = dev->req_buf_size - sizeof(struct opal_header);

        prepare_cmd_init(dev, buf, buf_len, &pos, opal_uid[table], opal_method[OPAL_SET_METHOD_UID]);

        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_WHERE);
        pos += append_u64(buf + pos, buf_len - pos, offset + index);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);

        pos += append_u8(buf + pos, buf_len - pos, OPAL_STARTNAME);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_VALUES);

        /*
         * The append_bytes used below, dependng upon the len either uses
         * short_atom_bytes_header (returns 1) or medium_atom_bytes_header
         * (returns 2) or long_atom_bytes_header (returns 4).
         * Hence we consider the MAX of the three i.e, 4.
         *
         * The 1 byte is for the following ENDNAME token.
         */
        remaining_buff_size = buf_len - (pos + 4 + 1 + CMD_END_BYTES_NUM);

        len = MIN(remaining_buff_size, (size - index));

        pos += append_bytes(buf + pos, buf_len - pos, data, len);
        pos += append_u8(buf + pos, buf_len - pos, OPAL_ENDNAME);
        prepare_cmd_end(buf, buf_len, &pos);
        prepare_cmd_header(dev, buf, pos);

        ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

        opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

        if (ret)
            break;

        index += len;
        pos = 0;
    }

    return ret;
}

static int opal_write_datastore(int fd, struct opal_device *dev, const uint8_t *data, uint64_t offset, uint64_t size)
{
    return opal_generic_write_table(fd, dev, OPAL_DATASTORE_UID, data, offset, size);
}

static int opal_write_mbr(int fd, struct opal_device *dev, const uint8_t *data, uint64_t offset, uint64_t size)
{
    return opal_generic_write_table(fd, dev, OPAL_MBR_UID, data, offset, size);
}

static struct opal_req_item opal_generic_read_table_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTROW } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* Start Reading from */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDROW } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, /* End reading here */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
};

/*
 * IO_BUFFER_LENGTH = 2048
 * sizeof(header) = 56
 * No. of Token Bytes in the Response = 11
 * MAX size of data that can be carried in response buffer
 * at a time is : 2048 - (56 + 11) = 1981 = 0x7BD.
 */
#define OPAL_MAX_READ_TABLE 0x7BD

static int opal_generic_read_table(int fd, struct opal_device *dev, enum opaluid table, uint8_t *data, uint64_t offset,
    uint64_t size)
{
    uint64_t len = 0, index = 0, end_row = size - 1;
    uint8_t jmp;
    size_t data_len;

    if (size == 0)
        return 0;

    int ret = get_table_length(fd, dev, table, &len);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error retrieving table length\n");
        return ret;
    }

    SEDCLI_DEBUG_PARAM("Table Length is: %lu\n", len);

    if (size > len || offset > len - size) {
        SEDCLI_DEBUG_PARAM("Read size/offset exceeding the table limits %lu in %lu\n", offset + size, len);
        return -EINVAL;
    }

    while (index < end_row) {
        opal_generic_read_table_cmd[3].val.uint = index + offset;

        len = MIN((uint64_t)OPAL_MAX_READ_TABLE, (end_row - index));
        opal_generic_read_table_cmd[7].val.uint = index + offset + len;

        prepare_req_buf(dev, opal_generic_read_table_cmd,
                ARRAY_SIZE(opal_generic_read_table_cmd),
                opal_uid[table],
                opal_method[OPAL_GET_METHOD_UID]);

        ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
        if (ret) {
            opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);
            break;
        }

        /* Reading the Data from the response */
        jmp = get_payload_string(dev, 1);
        data_len = dev->payload.tokens[1]->len - jmp;
        memcpy(data + index, dev->payload.tokens[1]->pos + jmp, data_len);

        opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

        index += len;
    }

    return ret;
}

static int opal_read_datastore(int fd, struct opal_device *dev, uint8_t *data, uint64_t offset, uint64_t size)
{
    return opal_generic_read_table(fd, dev, OPAL_DATASTORE_UID, data, offset, size);
}

static int get_num_lrs(int fd, struct opal_device *dev, uint8_t *lr_num)
{
    int ret = opal_generic_get_column(fd, dev, opal_uid[OPAL_LOCKING_INFO_TABLE_UID], OPAL_MAXRANGES, OPAL_MAXRANGES);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error parsing payload\n");
        ret = -1;
        goto put_tokens;
    }

    *lr_num = dev->payload.tokens[4]->vals.uint + 1;

put_tokens:
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

static int list_lr(int fd, struct opal_device *dev, struct sed_opal_locking_ranges *lrs)
{
    int ret = get_num_lrs(fd, dev, &lrs->lr_num);
    if (ret)
        return ret;

    if (lrs->lr_num > SED_OPAL_MAX_LRS)
        lrs->lr_num = SED_OPAL_MAX_LRS;

    SEDCLI_DEBUG_PARAM("The number of ranges discovered is: %d\n", lrs->lr_num);

    uint8_t uid[OPAL_UID_LENGTH];
    for (uint8_t i = 0; i < lrs->lr_num; i++) {
        build_gr_lr(uid, i);

        ret = opal_generic_get_column(fd, dev, uid, OPAL_RANGESTART, OPAL_WRITELOCKED);
        if (ret) {
            opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);
            return ret;
        }

        struct sed_opal_lockingrange *lr = &lrs->lrs[i];

        lr->lr_id = i;
        lr->start = dev->payload.tokens[4]->vals.uint;
        lr->length = dev->payload.tokens[8]->vals.uint;
        lr->rle = dev->payload.tokens[12]->vals.uint;
        lr->wle = dev->payload.tokens[16]->vals.uint;
        lr->read_locked = dev->payload.tokens[20]->vals.uint;
        lr->write_locked = dev->payload.tokens[24]->vals.uint;

        opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);
    }

    return ret;
}

static struct opal_req_item opal_genkey_prefix_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } }
};

static struct opal_req_item opal_genkey_postfix_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } }
};

static struct opal_req_item opal_genkey_public_exponent_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0x00 } }, // PublicExponent
    { .type = OPAL_U64, .len = 1, .val = { .uint =  0 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } }
};

static struct opal_req_item opal_genkey_pin_length_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0x01 } }, // PinLength
    { .type = OPAL_U64, .len = 1, .val = { .uint =  0 } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

int opal_genkey(struct opal_device *dev, int fd, uint8_t *uid, uint32_t public_exponent, uint32_t pin_length)
{
    size_t genkey_size = 0;

    size_t genkey_prefix_size = ARRAY_SIZE(opal_genkey_prefix_cmd);
    size_t genkey_postfix_size = ARRAY_SIZE(opal_genkey_postfix_cmd);
    if (public_exponent != 0 || pin_length != 0) {
        genkey_size += genkey_prefix_size;
        genkey_size += genkey_postfix_size;
    }

    size_t genkey_public_exponent_size = ARRAY_SIZE(opal_genkey_public_exponent_cmd);
    if (public_exponent != 0) {
        opal_genkey_public_exponent_cmd[3].val.uint = public_exponent;
        genkey_size += genkey_public_exponent_size;
    }

    size_t genkey_pin_length_size = ARRAY_SIZE(opal_genkey_pin_length_cmd);
    if (pin_length != 0) {
        opal_genkey_pin_length_cmd[3].val.uint = pin_length;
        genkey_size += genkey_pin_length_size;
    }

    size_t item_size = sizeof(struct opal_req_item);
    struct opal_req_item *opal_genkey_cmd = NULL;
    if (genkey_size > 0) {
        opal_genkey_cmd = malloc(item_size * genkey_size);
        if (opal_genkey_cmd == NULL)
            return -ENOMEM;
    }

    uint8_t copied = 0;

    if (opal_genkey_cmd) {
        memcpy(opal_genkey_cmd, opal_genkey_prefix_cmd, item_size * ARRAY_SIZE(opal_genkey_prefix_cmd));
        copied += genkey_prefix_size;

        if (public_exponent != 0) {
            memcpy(opal_genkey_cmd + copied, opal_genkey_public_exponent_cmd, item_size * genkey_public_exponent_size);
            copied += genkey_public_exponent_size;
        }

        if (pin_length != 0) {
            memcpy(opal_genkey_cmd + copied, opal_genkey_public_exponent_cmd, item_size * genkey_pin_length_size);
            copied += genkey_pin_length_size;
        }

        memcpy(opal_genkey_cmd + copied, opal_genkey_postfix_cmd, item_size * genkey_postfix_size);
        copied += genkey_postfix_size;
    }

    prepare_req_buf(dev, opal_genkey_cmd, copied, uid, opal_method[OPAL_GENKEY_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    if (opal_genkey_cmd)
        free(opal_genkey_cmd);

    return ret;
}

int opal_get_msid_pin_pt(struct sed_device *dev, struct sed_key *msid_pin)
{
    memset(msid_pin, 0, sizeof(*msid_pin));

    int ret = opal_start_generic_session(dev->fd, dev->priv, opal_uid[OPAL_ADMIN_SP_UID], opal_uid[OPAL_ANYBODY_UID], NULL);
    if (ret)
        goto end_session;

    ret = opal_get_msid(dev->fd, dev->priv, msid_pin->key, &msid_pin->len);
    if (ret)
        goto end_session;

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_take_ownership_pt(struct sed_device *dev, const struct sed_key *key)
{
    if (key == NULL) {
        SEDCLI_DEBUG_MSG("Must Provide a password.\n");
        return -EINVAL;
    }

    int ret = opal_start_generic_session(dev->fd, dev->priv, opal_uid[OPAL_ADMIN_SP_UID], opal_uid[OPAL_ANYBODY_UID], NULL);
    if (ret)
        goto end_session;

    uint8_t msid_pin_len = 0;
    char msid_pin[SED_MAX_KEY_LEN] = { 0 };
    ret = opal_get_msid(dev->fd, dev->priv, msid_pin, &msid_pin_len);
    if (ret)
        goto end_session;

    ret = opal_end_session(dev->fd, dev->priv);
    if (ret)
        goto end_session;

    ret = opal_start_sid_asp_session(dev->fd, dev->priv, msid_pin, msid_pin_len);
    if (ret)
        goto end_session;

    ret = opal_set_password(dev->fd, dev->priv, opal_uid[OPAL_C_PIN_SID_UID], key);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_revert_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *target_sp_uid)
{
    if (dev == NULL || key == NULL) {
        SEDCLI_DEBUG_MSG("Must provide a password or a valid device\n");
        return -EINVAL;
    }

    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_revert(dev->fd, dev->priv, target_sp_uid);
    if (ret) {
        SEDCLI_DEBUG_PARAM("Revert failed with status: %d\n", ret);
        goto end_session;
    }

    if (compare_uid(target_sp_uid, opal_uid[OPAL_ADMIN_SP_UID]))
        return ret;

end_session:
    SEDCLI_DEBUG_MSG("Revert with end session.\n");
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

static int parse_lr_str(char *item_str, uint32_t *item, size_t item_size, bool *is_locking_table)
{
    char *num, *errchk;
    uint8_t count = 0, num_lrs = 0;

    if (item_str == NULL || item_str[0] == 0) {
        num_lrs = 0;
    } else {
        num = strtok(item_str, ",");
        while (num != NULL && count < item_size) {
            uint8_t uid[OPAL_UID_LENGTH] = { 0 };
            uint id = 0;
            char *p = num;
            while (id < 8) {
                // parse two-chars num as hex
                char byte[3] = { 0 };
                memcpy(byte, p, sizeof(char) * 2);
                byte[2] = 0;
                uid[id++] = (int)strtoul(p, &errchk, 16);
                if (errchk == p) {
                    SEDCLI_DEBUG_MSG("Invalid hex number.\n");
                    return -EINVAL;
                }

                // skip 2 bytes for already parsed num and 1 byte for dash '-'
                p += 3;
            }

            uint32_t parsed = (uint32_t)-1;
            if (!memcmp(uid, opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], sizeof(uint8_t) * OPAL_UID_LENGTH))
                parsed = 0;
            else if (!memcmp(uid, opal_uid[OPAL_LOCKING_TABLE_UID], sizeof(uint8_t) * OPAL_UID_LENGTH)) {
                parsed = 0;
                *is_locking_table = true;
            }
            else {
                uint8_t user_lr[OPAL_UID_LENGTH];
                memcpy(user_lr, opal_uid[OPAL_LOCKINGRANGE_GLOBAL_UID], OPAL_UID_LENGTH);
                user_lr[5] = LOCKING_RANGE_NON_GLOBAL;

                if (!memcmp(uid, user_lr, sizeof(uint8_t) * (OPAL_UID_LENGTH - 1)))
                    parsed = uid[OPAL_UID_LENGTH - 1];
                else
                    return -EINVAL;
            }

            if (count < item_size) {
                item[count] = parsed;
                SEDCLI_DEBUG_PARAM("added %u to item list at index %u\n", parsed, count);
            }

            num = strtok(NULL, ",");
            if (num != NULL && *num == ' ')
                num++;

            count++;
        }
        num_lrs = count;

        if (num_lrs == 0)
            return -EINVAL;
    }

    if (num_lrs > item_size)
        return  -EINVAL;

    return num_lrs;
}

static int parse_dsts_str(char *item_str, uint32_t *item, size_t item_size)
{
    char *num, *errchk;
    uint8_t count = 0, num_lrs = 0;
    unsigned long parsed;

    if (item_str == NULL || item_str[0] == 0) {
        num_lrs = 0;
    } else {
        num = strtok(item_str, ",");
        while (num != NULL && count < item_size) {
            parsed = strtoul(num, &errchk, 10);
            if (errchk == num)
                continue;

            if (count < item_size) {
                item[count] = parsed;
                SEDCLI_DEBUG_PARAM("added %lu to item list at index %u\n", parsed, count);
            }
            num = strtok(NULL, ",");
            count++;
        }
        num_lrs = count;

        if (num_lrs == 0)
            return -EINVAL;
    }

    if (num_lrs > item_size)
        return  -EINVAL;

    return num_lrs;
}

int opal_activate_sp_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *target_sp_uid, char *lr_str, uint8_t range_start_length_policy, char *dsts_str)
{
    if (key == NULL) {
        SEDCLI_DEBUG_MSG("Must Provide a password.\n");
        return -EINVAL;
    }

    uint32_t lr[OPAL_MAX_LRS] = { 0 };
    bool is_locking_table = false;
    int num_lrs = parse_lr_str(lr_str, lr, OPAL_MAX_LRS, &is_locking_table);
    if ((is_locking_table && num_lrs > 1) ||
        (num_lrs < 0 && is_locking_table == false)) {
        SEDCLI_DEBUG_MSG("Invalid Locking Ranges number.\n");
        return -EINVAL;
    }

    uint32_t dsts[OPAL_MAX_DSTS] = { 0 };
    int num_dsts = parse_dsts_str(dsts_str, dsts, OPAL_MAX_DSTS);
    if (num_dsts < 0) {
        SEDCLI_DEBUG_MSG("Invalid DataStore Table number.\n");
        return -EINVAL;
    }

    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_get_lsp_lifecycle(dev->fd, dev->priv, OPAL_LOCKING_SP_UID);
    SEDCLI_DEBUG_PARAM("current lifecycle is: %d\n", ret);

    ret = opal_activate_sp(dev->fd, dev->priv, target_sp_uid, false, lr, num_lrs, is_locking_table, range_start_length_policy, dsts, num_dsts, NULL);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_revert_lsp_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *auth_uid, bool keep_global_range_key)
{
    if (key == NULL) {
        SEDCLI_DEBUG_MSG("Must Provide a password.\n");
        return -EINVAL;
    }

    int ret = opal_start_generic_session(dev->fd, dev->priv, opal_uid[OPAL_LOCKING_SP_UID], auth_uid, key);
    if (ret)
        goto end_session;

    return opal_revert_lsp(dev->fd, dev->priv, keep_global_range_key);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_add_user_to_lr_pt(struct sed_device *dev, const struct sed_key *key, const char *user,
    enum SED_ACCESS_TYPE access_type, uint8_t lr)
{
    if (access_type > SED_ACCESS_LK || key == NULL || user == NULL) {
        SEDCLI_DEBUG_MSG("Need to supply user, lock type and password!\n");
        return -EINVAL;
    }

    bool admin;
    uint32_t who;
    if (sed_get_user_admin(user, &who, &admin))
        return -EINVAL;

    int ret = opal_start_admin1_lsp_session(dev->fd, dev->priv, key);
    if (ret)
        goto end_session;

    ret = add_user_to_lr(dev->fd, dev->priv, access_type, lr, who, admin);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_enable_user_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *user_uid)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_enable_user(dev->fd, dev->priv, user_uid);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_setup_lr_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *lr_uid, uint64_t range_start, uint64_t range_length, enum SED_FLAG_TYPE rle, enum SED_FLAG_TYPE wle)
{
    if (range_start == (uint64_t)-1 || range_length == (uint64_t)-1 || key == NULL) {
        SEDCLI_DEBUG_MSG("Incorrect parameters, please try again\n");
        return -EINVAL;
    }

    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_setup_locking_range(dev->fd, dev->priv, lr_uid, range_start, range_length, rle, wle);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_lock_unlock_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *auth_uid, uint8_t lr, bool sum,
    enum SED_ACCESS_TYPE access_type)
{
    if (access_type > SED_ACCESS_LK) {
        SEDCLI_DEBUG_MSG("Need to supply lock type and password!\n");
        return -EINVAL;
    }

    int ret = opal_start_auth_session(dev->fd, dev->priv, sum, lr, NULL, auth_uid, key);
    if (ret)
        goto end_session;

    if (sum)
        ret = opal_lock_unlock_sum(dev->fd, dev->priv, access_type, lr);
    else
        ret = opal_lock_unlock_no_sum(dev->fd, dev->priv, access_type, lr);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_set_password_pt(struct sed_device *dev, uint8_t *sp_uid, uint8_t *auth_uid, const struct sed_key *auth_key,
    uint8_t *user_uid, const struct sed_key *new_user_key)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, auth_key);
    if (ret)
        goto end_session;

    uint8_t uid[OPAL_UID_LENGTH] = { 0 };

    if (compare_uid(user_uid, opal_uid[OPAL_SID_UID]))
        memcpy(&uid, opal_uid[OPAL_C_PIN_SID_UID], sizeof(uint8_t) * OPAL_UID_LENGTH);
    else if(compare_uid_range(user_uid, opal_uid[OPAL_ADMIN1_UID], 1, 4)) {
        memcpy(&uid, opal_uid[OPAL_C_PIN_LOCKING_SP_ADMIN1_UID], sizeof(uint8_t) * OPAL_UID_LENGTH);
        // align last admin uid byte to given admin id
        uid[7] = user_uid[7];
    } else if(compare_uid_range(user_uid, opal_uid[OPAL_USER1_UID], 1, 9)) {
        memcpy(&uid, opal_uid[OPAL_C_PIN_USER1_UID], sizeof(uint8_t) * OPAL_UID_LENGTH);
        // align last admin uid byte to given admin id
        uid[7] = user_uid[7];
    } else if (compare_uid(user_uid, opal_uid[OPAL_C_PIN_SID_UID])) {
        memcpy(&uid, opal_uid[OPAL_C_PIN_SID_UID], sizeof(uint8_t) * OPAL_UID_LENGTH);
    } else if(compare_uid_range(user_uid, opal_uid[OPAL_C_PIN_ADMIN_SP_ADMIN1_UID], 1, 4)) {
        memcpy(&uid, user_uid, sizeof(uint8_t) * OPAL_UID_LENGTH);
    } else if(compare_uid_range(user_uid, opal_uid[OPAL_C_PIN_LOCKING_SP_ADMIN1_UID], 1, 4)) {
        memcpy(&uid, user_uid, sizeof(uint8_t) * OPAL_UID_LENGTH);
    } else {
        SEDCLI_DEBUG_MSG("User not supported.\n");
        ret = -EINVAL;
        goto end_session;
    }

    ret = opal_set_password(dev->fd, dev->priv, uid, new_user_key);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_mbr_done_pt(struct sed_device *dev, const struct sed_key *key, bool mbr_done)
{
    if (key == NULL) {
        SEDCLI_DEBUG_MSG("User must provide ADMIN1 password\n");
        return -EINVAL;
    }

    int ret = opal_start_admin1_lsp_session(dev->fd, dev->priv, key);
    if (ret)
        goto end_session;

    uint8_t done = mbr_done ? OPAL_TRUE : OPAL_FALSE;
    ret = opal_set_mbr_done(dev->fd, dev->priv, done);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_shadow_mbr_pt(struct sed_device *dev, const struct sed_key *key, bool enable)
{
    if (key == NULL) {
        SEDCLI_DEBUG_MSG("Need ADMIN1 password for mbr shadow enable disable\n");
        return -EINVAL;
    }

    int ret = opal_start_admin1_lsp_session(dev->fd, dev->priv, key);
    if (ret)
        goto end_session;

    uint8_t opal_enable = enable ? OPAL_TRUE : OPAL_FALSE;
    ret = opal_set_mbr_en_disable(dev->fd, dev->priv, opal_enable);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_erase_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_erase(dev->fd, dev->priv, uid);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_ds_read_pt(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key, uint8_t *to,
    uint32_t size, uint32_t offset)
{
    if (to == NULL) {
        SEDCLI_DEBUG_MSG("Must provide a valid destination pointer\n");
        return -EINVAL;
    }

    uint8_t auth_id;
    int ret = get_opal_auth_id(auth, &auth_id);
    if (ret)
        return ret;

    ret = opal_start_generic_session(dev->fd, dev->priv, opal_uid[OPAL_LOCKING_SP_UID], opal_uid[auth_id], key);
    if (ret)
        goto end_session;

    ret = opal_read_datastore(dev->fd, dev->priv, to, offset, size);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_ds_write_pt(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key, const uint8_t *from,
    uint32_t size, uint32_t offset)
{
    if (from == NULL) {
        SEDCLI_DEBUG_MSG("Must provide a valid source pointer\n");
        return -EINVAL;
    }

    uint8_t auth_id;
    int ret = get_opal_auth_id(auth, &auth_id);
    if (ret)
        return ret;

    ret = opal_start_generic_session(dev->fd, dev->priv, opal_uid[OPAL_LOCKING_SP_UID], opal_uid[auth_id], key);
    if (ret)
        goto end_session;

    ret = opal_write_datastore(dev->fd, dev->priv, from, offset, size);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

static struct opal_req_item opal_ds_add_anybody_set_cmd[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 1 } }, /* Values */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0x03 } }, /* BooleanExpr */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_BYTES, .len = 4, .val = { .bytes = opal_uid[OPAL_HALF_UID_AUTHORITY_OBJ_REF_UID] } },
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = opal_uid[OPAL_ANYBODY_UID] } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDLIST } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

/**
 * Change ACL in such way so anybody user can read the data but only
 * Admin1 can write to it.
 * Admin1 key needs to be provided
 */
int opal_ds_add_anybody_get_pt(struct sed_device *dev, const struct sed_key *key)
{
    if (key == NULL) {
        SEDCLI_DEBUG_MSG("Must provide password\n");
        return -EINVAL;
    }

    struct opal_device *opal_dev = dev->priv;
    int ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
    if (ret)
        goto end_session;

    prepare_req_buf(opal_dev, opal_ds_add_anybody_set_cmd, ARRAY_SIZE(opal_ds_add_anybody_set_cmd),
        opal_uid[OPAL_ACE_DS_GET_ALL_UID], opal_method[OPAL_SET_METHOD_UID]);

    ret = opal_snd_rcv_cmd_parse_chk(dev->fd, opal_dev, false);

    opal_put_all_tokens(opal_dev->payload.tokens, &opal_dev->payload.len);

end_session:
    opal_end_session(dev->fd, opal_dev);

    return ret;
}

int opal_list_lr_pt(struct sed_device *dev, const struct sed_key *key, struct sed_opal_locking_ranges *lrs)
{
    if (key == NULL) {
        SEDCLI_DEBUG_MSG("Must provide the password.\n");
        return -EINVAL;
    }

    if (!lrs) {
        SEDCLI_DEBUG_MSG("Must provide a valid destination pointer\n");
        return -EINVAL;
    }

    struct opal_device *opal_dev = dev->priv;
    int ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
    if (ret)
        goto end_session;

    ret = list_lr(dev->fd, opal_dev, lrs);

end_session:
    opal_end_session(dev->fd, opal_dev);

    return ret;
}

static int opal_read_mbr(int fd, struct opal_device *dev, uint8_t *data, uint64_t offset, uint64_t size)
{
    return opal_generic_read_table(fd, dev, OPAL_MBR_UID, data, offset, size);
}

int opal_read_shadow_mbr_pt(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key, uint8_t *to,
    uint32_t size, uint32_t offset)
{
    if (to == NULL) {
        SEDCLI_DEBUG_MSG("Must provide a valid destination pointer\n");
        return -EINVAL;
    }

    uint8_t auth_id;
    int ret = get_opal_auth_id(auth, &auth_id);
    if (ret)
        return ret;

    ret = opal_start_generic_session(dev->fd, dev->priv, opal_uid[OPAL_LOCKING_SP_UID], opal_uid[auth_id], key);
    if (ret)
        goto end_session;

    ret = opal_read_mbr(dev->fd, dev->priv, to, offset, size);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_write_shadow_mbr_pt(struct sed_device *dev, const struct sed_key *key, const uint8_t *from, uint32_t size,
    uint32_t offset)
{
    if (from == NULL) {
        SEDCLI_DEBUG_MSG("Must provide a valid source pointer\n");
        return -EINVAL;
    }

    struct opal_device *opal_dev = dev->priv;

    int ret = opal_start_admin1_lsp_session(dev->fd, opal_dev, key);
    if (ret)
        goto end_session;

    ret = opal_write_mbr(dev->fd, opal_dev, from, offset, size);

end_session:
    opal_end_session(dev->fd, opal_dev);

    return ret;
}

int opal_block_sid_pt(struct sed_device *dev, bool hw_reset)
{
    /* Send Block SID authentication command, no
     * IF_RECV response is expected. Set Hardware
     * Reset in LSB of the first byte in BlockSID
     * payload based on Clear Event flag user
     * supplied through hwreset argument */

    struct opal_device *opal_dev = dev->priv;
    *(opal_dev->req_buf) = hw_reset ? 1 : 0;


    int ret = opal_send(dev->fd, TCG_SECP_02, OPAL_BLOCK_SID_COMID, opal_dev->req_buf, BLOCK_SID_PAYLOAD_SZ);
    if (ret) {
        SEDCLI_DEBUG_PARAM("NVMe error during block-sid: %d\n", ret);
        nvme_error = ret;
    }

    return ret;
}

int opal_stack_reset_pt(struct sed_device *device, int32_t com_id, uint64_t extended_com_id, uint8_t *response)
{
    struct opal_device *dev = device->priv;
    memset(dev->req_buf, 0, dev->req_buf_size);
    memset(dev->resp_buf, 0, dev->resp_buf_size);

    if (extended_com_id == 0)
        build_ext_comid(dev->req_buf, dev->comid);
    else
    {
        dev->req_buf[0] = (extended_com_id >> 24) & 0xFF;
        dev->req_buf[1] = (extended_com_id >> 16) & 0xFF;
        dev->req_buf[2] = (extended_com_id >> 8) & 0xFF;
        dev->req_buf[3] = extended_com_id & 0xFF;
    }

    /*
     * Stack Reset Request Code: 00 00 00 02 (Payload bytes 4 to 7)
     */
    dev->req_buf[4] = 0;
    dev->req_buf[5] = 0;
    dev->req_buf[6] = 0;
    dev->req_buf[7] = 2;

    int32_t dev_com_id = com_id != 0 ? com_id : dev->comid;
    int ret = opal_send_recv(device->fd, TCG_SECP_02, dev_com_id, dev->req_buf, STACK_RESET_PAYLOAD_SZ, dev->resp_buf,
        STACK_RESET_PAYLOAD_SZ);
    if (ret) {
        SEDCLI_DEBUG_PARAM("NVMe error during stack-reset: %d\n", ret);
        nvme_error = ret;
        return ret;
    }

    if (dev->resp_buf[10] == 0 && dev->resp_buf[11] == 0)
        return 0;
    else
        memcpy(response, dev->resp_buf, sizeof(uint8_t) * 16);

    return dev->resp_buf[15];
}

int opal_start_generic_session_pt(struct sed_device *device, const struct sed_key *key, int sp, int auth)
{
    int ret = opal_start_generic_session(device->fd, device->priv, opal_uid[sp], opal_uid[auth], key);
    if (ret)
        opal_end_session(device->fd, device->priv);

    return ret;
}

int opal_start_session_pt(struct sed_device *device, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    struct sed_session *session)
{
    int ret = opal_start_generic_session(device->fd, device->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;
    else {
        struct opal_device *dev = device->priv;
        session->hsn = dev->session.hsn;
        session->tsn = dev->session.tsn;
    }

    return SED_SUCCESS;

end_session:
    opal_end_session(device->fd, device->priv);

    return ret;
}

int opal_end_session_pt(struct sed_device *device, struct sed_session *session)
{
    struct opal_device *dev = device->priv;
    if (dev->session.hsn != 0 || dev->session.tsn != 0) {
        SEDCLI_DEBUG_MSG("Session shall be initialized outside sedcli device struct!\n");
        return -EINVAL;
    }

    dev->session.hsn = session->hsn;
    dev->session.tsn = session->tsn;

    return opal_end_session(device->fd, device->priv);
}

int opal_start_end_transactions_pt(struct sed_device *dev, bool start, uint8_t status)
{
    return opal_transactions(dev->fd, dev->priv, start, status);
}

int opal_genkey_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint32_t public_exponent, uint32_t pin_length)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_genkey(dev->priv, dev->fd, uid, public_exponent, pin_length);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_parse_tper_state_pt(struct sed_device *dev, struct sed_tper_state *tper_state)
{
    if (tper_state == NULL) {
        SEDCLI_DEBUG_MSG("User must provide valid tper state pointer.\n");
        return -EINVAL;
    }

    int ret = opal_level0_discovery_pt(dev);
    if (ret) {
        SEDCLI_DEBUG_MSG("Error in level0 discovery.\n");
        return ret;
    }

    tper_state->locking_en = dev->discv.sed_lvl0_discv.sed_locking.locking_en ? 1 : 0;

    ret = opal_start_generic_session(dev->fd, dev->priv, opal_uid[OPAL_ADMIN_SP_UID], opal_uid[OPAL_ANYBODY_UID], NULL);
    tper_state->session_open = ret;
    bool end_session = !ret;

    /* If a session is already open */
    if (ret) {
        tper_state->blk_sid_val_state = SED_UNKNOWN_ERROR;
        tper_state->admisp_lc = SED_UNKNOWN_ERROR;
        tper_state->lsp_lc = SED_UNKNOWN_ERROR;
    } else {
        tper_state->blk_sid_val_state = dev->discv.sed_lvl0_discv.sed_block_sid.sid_valuestate ? 1 : 0;

        ret = opal_get_lsp_lifecycle(dev->fd, dev->priv, OPAL_ADMIN_SP_UID);
        tper_state->admisp_lc = ret;

        ret = opal_get_lsp_lifecycle(dev->fd, dev->priv, OPAL_LOCKING_SP_UID);
        tper_state->lsp_lc = ret;
    }

    if (end_session)
        opal_end_session(dev->fd, dev->priv);

    return SED_SUCCESS;
}

static int fill_col_info(struct sed_opal_col_info *col_info, struct opal_token *current_token)
{
    // fill current col info from current token
    col_info->opal_type = current_token->pos[0];
    col_info->type = (enum SED_TOKEN_TYPE)current_token->type;
    col_info->len = current_token->len;

    // modify length for bytestring tokens to not include current token in the array, just skip it
    int jmp = 0;
    if (col_info->type == SED_DATA_BYTESTRING) {
        jmp = 1;
        col_info->len -= jmp;
    }

    if (col_info->type == SED_DATA_SINT || col_info->type == SED_DATA_UINT)
        col_info->data = malloc(sizeof(uint64_t) * col_info->len);
    else
        col_info->data = malloc(sizeof(uint8_t) * col_info->len);
    if (col_info->data == NULL)
        return -ENOMEM;

    if (col_info->type == SED_DATA_SINT || col_info->type == SED_DATA_UINT) {
        uint64_t *data = (uint64_t *)col_info->data;
        *data = *current_token->pos;
    } else
        memcpy(col_info->data, current_token->pos + jmp, sizeof(uint8_t) * col_info->len);

    return SED_SUCCESS;
}

static int prepare_next_col_info(struct sed_opal_col_info **next_col)
{
    *next_col = (struct sed_opal_col_info *)malloc(sizeof(struct sed_opal_col_info));
    if ((*next_col) == NULL)
        return -ENOMEM;

    memset((*next_col), 0, sizeof(struct sed_opal_col_info));

    return SED_SUCCESS;
}

static int create_col_info_list(struct opal_device *opal_dev, struct sed_opal_col_info *col_info)
{
    int ret = SED_SUCCESS;

    // first 4 tokens is a payload
    uint32_t current_token_num = 4;

    // skip tokens to start with a startlist token
    if (opal_dev->payload.tokens[current_token_num]->pos[0] == OPAL_STARTNAME) {
        while (opal_dev->payload.tokens[current_token_num]->pos[0] != OPAL_STARTLIST) {
            current_token_num++;
            if (current_token_num == OPAL_MAX_TOKENS)
                return -1;
        }
    }

    for (; current_token_num < OPAL_MAX_TOKENS; current_token_num++) {
        // fill col info based on current token
        struct opal_token *current_token = opal_dev->payload.tokens[current_token_num];
        ret = fill_col_info(col_info, current_token);
        if (ret)
            return ret;

        // break if token is endlist
        if (current_token->type == OPAL_DTA_TOKENID_TOKEN &&
            current_token->len == 1 &&
            current_token->pos[0] == OPAL_ENDLIST)
            return SED_SUCCESS;
        else {
            // create next col info
            ret = prepare_next_col_info(&col_info->next_col);
            if (ret)
                return ret;
            col_info = col_info->next_col;
        }
    }

    return ret;
}

static int parse_col_value(struct opal_device *opal_dev, struct sed_opal_col_info *col_info)
{
    int jmp, ret;

    struct opal_token *token = opal_dev->payload.tokens[4];

    col_info->type = (enum SED_TOKEN_TYPE)token->type;
    col_info->opal_type = (uint8_t)token->pos[0];

    switch (token->type) {
    case OPAL_DTA_TOKENID_BYTESTRING:
        jmp = get_payload_string(opal_dev, 4);
        col_info->len = token->len - jmp;

        col_info->data = (uint8_t *)malloc(sizeof(uint8_t) * col_info->len);
        if (col_info->data == NULL) {
            ret = -ENOMEM;
            goto no_mem;
        }

        memcpy(col_info->data, token->pos + (uint8_t)jmp, col_info->len);
        ret = 0;
        break;

    case OPAL_DTA_TOKENID_SINT:
        col_info->len = token->len;
        col_info->data = (int64_t *)malloc(sizeof(int64_t));
        if (col_info->data == NULL) {
            ret = -ENOMEM;
            goto no_mem;
        }

        memcpy(col_info->data, &token->vals.sint, sizeof(int64_t));
        ret = 0;
        break;

    case OPAL_DTA_TOKENID_UINT:
        col_info->len = token->len;
        col_info->data = (uint64_t *)malloc(sizeof(uint64_t));
        if (col_info->data == NULL) {
            ret = -ENOMEM;
            goto no_mem;
        }

        memcpy(col_info->data, &token->vals.uint, sizeof(uint64_t));
        ret = 0;
        break;

    case OPAL_DTA_TOKENID_TOKEN: {
        if (token->len == 1 &&
            (token->pos[0] == OPAL_STARTLIST ||
             token->pos[0] == OPAL_STARTNAME)) {
            ret = create_col_info_list(opal_dev, col_info);
            if (ret == -ENOMEM)
                goto no_mem;
        }
        else {
            col_info->len = token->len;
            col_info->data = (uint64_t *)malloc(sizeof(uint64_t));
            if (col_info->data == NULL) {
                ret = -ENOMEM;
                goto no_mem;
            }

            memcpy(col_info->data, &token->vals.uint, sizeof(uint64_t));
            ret = 0;
        }
        break;
    }

    default:
        ret = -EINVAL;
        break;
    }

no_mem:
    opal_put_all_tokens(opal_dev->payload.tokens, &opal_dev->payload.len);

    return ret;
}

static int parse_get_byte_buffer(struct opal_device *opal_dev, uint8_t *buffer)
{
    int ret, jmp;
    size_t len;

    struct opal_token *token = opal_dev->payload.tokens[1];

    if (token->type != OPAL_DTA_TOKENID_BYTESTRING) // we expecting here only bytestring
    {
        ret = -EINVAL;
        goto error;
    }

    jmp = get_payload_string(opal_dev, 1); // get length of token header
    len = token->len - jmp;
    memcpy(buffer, token->pos + (uint8_t)jmp, len);
    ret = 0;

error:
    opal_put_all_tokens(opal_dev->payload.tokens, &opal_dev->payload.len);

    return ret;
}

int opal_set_with_buf_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, struct opal_req_item *cmd, size_t cmd_len)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_set_buf_prep(dev, uid, cmd, cmd_len);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_get_set_col_val_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint64_t col, bool get, struct sed_opal_col_info *col_info)
{
    if (!get && col_info->data == NULL) {
        SEDCLI_DEBUG_MSG("Must provide a valid data pointer to SET the column value\n");
        return -EINVAL;
    }

    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    if (get) {
        ret = opal_generic_get_column(dev->fd, dev->priv, uid, col, col);
        if (ret)
            goto end_session;

        ret = parse_col_value(dev->priv, col_info);
    } else
        ret = opal_generic_set_column(dev->fd, dev->priv, uid, col, col_info);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

int opal_get_set_byte_table_pt(struct sed_device *dev, const struct sed_key *key, const enum SED_SP_TYPE sp,
    const char *user, uint8_t *uid, uint64_t start, uint64_t end, uint8_t *buffer, bool is_set)
{
    if (buffer == NULL) {
        SEDCLI_DEBUG_MSG("Must provide a valid data pointer to buffer\n");
        return -EINVAL;
    }

    uint8_t user_uid;
    int ret = sed_get_authority_uid(user, &user_uid);
    if (ret)
        return ret;

    uint8_t sp_uid[OPAL_UID_LENGTH];
    ret = get_opal_sp_uid(sp, sp_uid);
    if (ret)
        return ret;

    ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, opal_uid[user_uid], key);
    if (ret)
        goto error;

    if (is_set) {
        ret = opal_generic_set_byte_table(dev->fd, dev->priv, uid, start, end, buffer);
    } else {
        ret = opal_generic_get_byte_table(dev->fd, dev->priv, uid, start, end);
    }

    if (ret) {
        SEDCLI_DEBUG_PARAM("Error during %s byte table\n", is_set ? "set" : "get");
        goto end_session;
    }

    if (!is_set)
        ret = parse_get_byte_buffer(dev->priv, buffer);

end_session:
    opal_end_session(dev->fd, dev->priv);

error:
    return ret;
}

int opal_tper_reset_pt(struct sed_device *dev)
{
    int ret = SED_SUCCESS;


    struct opal_device *device = dev->priv;
    ret = opal_send(dev->fd, TCG_SECP_02, OPAL_TPER_RESET_COMID, device->req_buf, BLOCK_SID_PAYLOAD_SZ);
    if (ret) {
        SEDCLI_DEBUG_PARAM("NVMe error during tper-reset: %d\n", ret);
        nvme_error = ret;
    }

    return ret;
}

int opal_reactivate_sp_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *target_sp_uid, char *lr_str, uint8_t range_start_length_policy, const struct sed_key *admin1_pwd, char *dsts_str)
{
    if (key == NULL) {
        SEDCLI_DEBUG_MSG("Must Provide a password.\n");
        return -EINVAL;
    }

    uint32_t lr[OPAL_MAX_LRS] = { 0 };
    bool is_locking_table = false;
    int num_lrs = parse_lr_str(lr_str, lr, OPAL_MAX_LRS, &is_locking_table);
    if ((is_locking_table && num_lrs > 1) ||
        (num_lrs < 0 && is_locking_table == false)) {
        SEDCLI_DEBUG_MSG("Invalid Locking Ranges number.\n");
        return -EINVAL;
    }

    uint32_t dsts[OPAL_MAX_DSTS] = { 0 };
    int num_dsts = parse_dsts_str(dsts_str, dsts, OPAL_MAX_DSTS);
    if (num_dsts < 0) {
        SEDCLI_DEBUG_MSG("Invalid DataStore Table number.\n");
        return -EINVAL;
    }

    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret) {
        opal_end_session(dev->fd, dev->priv);
        return ret;
    }

    ret = opal_activate_sp(dev->fd, dev->priv, target_sp_uid, true, lr, num_lrs, is_locking_table, range_start_length_policy, dsts, num_dsts, admin1_pwd);
    if (ret)
        opal_end_session(dev->fd, dev->priv);

    return ret;
}

static void build_nsid_array(uint8_t *arr, uint32_t size, uint32_t nsid)
{
    memset(arr, 0, sizeof(uint8_t) * size);

    for (uint8_t i = 0; i < size; i++) {
        arr[i] = nsid & 0xFF;
        nsid = nsid >> 8;
    }
}

#define BYTE_4 (4)

static struct opal_req_item assign_cmd[] = {
    { .type = OPAL_BYTES, .len = BYTE_4, .val = { .bytes = NULL } }, /* The NS-ID byte-4 list */

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_RANGESTART } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Range Start */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_RANGELENGTH } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } }, /* Range Length */
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

static int opal_assign(int fd, struct opal_device *dev, uint32_t nsid, uint8_t range_start, uint8_t range_length,
    struct sed_locking_object *info)
{
    uint8_t nsid_arr[BYTE_4];
    build_nsid_array(nsid_arr, BYTE_4, nsid);

    assign_cmd[0].val.bytes = nsid_arr;
    assign_cmd[3].val.byte = range_start;
    assign_cmd[7].val.byte = range_length;

    prepare_req_buf(dev, assign_cmd, ARRAY_SIZE(assign_cmd),
        opal_uid[OPAL_LOCKING_TABLE_UID],
        opal_method[OPAL_ASSIGN_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    /* Send the LO uid back to the user for deassign operation */
    int jmp = get_payload_string(dev, 1);
    memcpy(info->uid, dev->payload.tokens[1]->pos + jmp, 8);
    info->nsid = nsid;
    info->nsgid = dev->payload.tokens[2]->vals.uint;

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

int opal_assign_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint32_t nsid, uint8_t range_start, uint8_t range_len, struct sed_locking_object *info)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_assign(dev->fd, dev->priv, nsid, range_start, range_len, info);
    if (ret)
        memset(info, 0, sizeof(*info));

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

static struct opal_req_item deassign_cmd[] = {
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } }, /* LO UID */
};

static int opal_deassign(int fd, struct opal_device *dev, const uint8_t *uid, bool keep_ns_global_range_key)
{
    deassign_cmd[0].val.bytes = uid;

    prepare_req_buf(dev, deassign_cmd, ARRAY_SIZE(deassign_cmd), opal_uid[OPAL_LOCKING_TABLE_UID],
        opal_method[OPAL_DEASSIGN_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    SEDCLI_DEBUG_PARAM("keep global range key is unused! %d\n", keep_ns_global_range_key);

    return ret;
}

int opal_deassign_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    const uint8_t *uid, bool keep_ns_global_range_key)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_deassign(dev->fd, dev->priv, uid, keep_ns_global_range_key);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

static int parse_next_uids(struct opal_device *dev, struct sed_next_uids *next_uids)
{
    size_t size = 0;
    next_uids->uids = (uint8_t **)malloc(sizeof(uint8_t *) * (size + 1));
    if (next_uids->uids == NULL)
        return -ENOMEM;

    for (uint32_t i = 0; i < dev->payload.len; i++) {
        if (dev->payload.tokens[i]->type == OPAL_DTA_TOKENID_BYTESTRING) {
            next_uids->uids = (uint8_t **)realloc(next_uids->uids, sizeof(uint8_t*) * (size + 1));
            if (next_uids->uids == NULL)
                goto deinit;

            next_uids->uids[size] = (uint8_t *)calloc(OPAL_UID_LENGTH, sizeof(uint8_t));
            if (next_uids->uids[size] == NULL)
                goto deinit;

            int jmp = get_payload_string(dev, i);
            memcpy(next_uids->uids[size], dev->payload.tokens[i]->pos + jmp, OPAL_UID_LENGTH);

            size++;
        }
    }

    next_uids->size = size;

    return SED_SUCCESS;

deinit:
    if (next_uids->uids) {
        for (uint16_t i = 0; i < next_uids->size; i++)
            free(next_uids->uids[i]);
        free(next_uids->uids);
    }

    return -ENOMEM;
}

static struct opal_req_item table_next_cmd_where[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_WHERE } },
    { .type = OPAL_BYTES, .len = 0, .val = { .bytes = NULL } }, // where
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } }
};

static struct opal_req_item table_next_cmd_count[] = {
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_VALUES } },
    { .type = OPAL_U64, .len = 1, .val = { .uint = 0 } }, // count
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } }
};

static int opal_table_next(int fd, struct opal_device *dev, uint8_t *uid, uint8_t *where, uint16_t count,
    struct sed_next_uids *next_uids)
{
    struct opal_req_item table_next_cmd[8] = { 0 };
    uint8_t size = 0;

    if (where) {
        table_next_cmd_where[2].val.bytes = where;
        table_next_cmd_where[2].len = 8;
        memcpy(table_next_cmd, table_next_cmd_where, sizeof(struct opal_req_item) * 4);
        size += 4;
    }

    if (count) {
        table_next_cmd_count[2].val.uint = count;
        memcpy(table_next_cmd + size, table_next_cmd_count, sizeof(struct opal_req_item) * 4);
        size += 4;
    }

    prepare_req_buf(dev, table_next_cmd, size, uid, opal_method[OPAL_NEXT_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
    if (ret)
        goto put_tokens;

    ret = parse_next_uids(dev, next_uids);
    if (ret)
        goto put_tokens;

put_tokens:
    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

int opal_table_next_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    uint8_t *uid, uint8_t *where, uint16_t count, struct sed_next_uids *next_uids)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_table_next(dev->fd, dev->priv, uid, where, count, next_uids);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}

static struct opal_req_item authenticate_cmd[] = {
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } }, // Auth UID

    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_STARTNAME } },
    { .type = OPAL_U8, .len = 1, .val = { .byte = 0 } },
    { .type = OPAL_BYTES, .len = 1, .val = { .bytes = NULL } }, // Proof / Host Challenge
    { .type = OPAL_U8, .len = 1, .val = { .byte = OPAL_ENDNAME } },
};

int opal_authenticate_method(int fd, struct opal_device *dev, int auth, const struct sed_key *key)
{
    /* New authority UID */
    authenticate_cmd[0].val.bytes = opal_uid[auth];

    /* Proof/Host Challenge */
    authenticate_cmd[3].val.bytes = (uint8_t *)key->key;
    authenticate_cmd[3].len = key->len;

    prepare_req_buf(dev, authenticate_cmd, ARRAY_SIZE(authenticate_cmd), opal_uid[OPAL_THIS_SP_UID],
        opal_method[OPAL_AUTHENTICATE_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

int opal_authenticate_pt(struct sed_device *dev, enum SED_AUTHORITY auth, const struct sed_key *key)
{
    uint8_t auth_id;
    int ret = get_opal_auth_id(auth, &auth_id);
    if (ret)
        return ret;

    return opal_authenticate_method(dev->fd, dev->priv, auth_id, key);;
}

static struct opal_req_item get_acl_cmd[] = {
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } }, // INVOKING UID
    { .type = OPAL_BYTES, .len = 8, .val = { .bytes = NULL } }, // METHOD UID
};

int opal_get_acl(int fd, struct opal_device *dev, const uint8_t *invoking_uid, const uint8_t *method_uid,
    struct sed_next_uids *next_uids)
{
    get_acl_cmd[0].val.bytes = invoking_uid;
    get_acl_cmd[1].val.bytes = method_uid;

    prepare_req_buf(dev, get_acl_cmd, ARRAY_SIZE(get_acl_cmd), opal_uid[OPAL_ACCESS_CONTROL_UID],
        opal_method[OPAL_GETACL_METHOD_UID]);

    int ret = opal_snd_rcv_cmd_parse_chk(fd, dev, false);
    if (ret)
        return ret;

    ret = parse_next_uids(dev, next_uids);

    opal_put_all_tokens(dev->payload.tokens, &dev->payload.len);

    return ret;
}

int opal_get_acl_pt(struct sed_device *dev, const struct sed_key *key, uint8_t *sp_uid, uint8_t *auth_uid,
    const uint8_t *invoking_uid, const uint8_t *method_uid, struct sed_next_uids *next_uids)
{
    int ret = opal_start_generic_session(dev->fd, dev->priv, sp_uid, auth_uid, key);
    if (ret)
        goto end_session;

    ret = opal_get_acl(dev->fd, dev->priv, invoking_uid, method_uid, next_uids);

end_session:
    opal_end_session(dev->fd, dev->priv);

    return ret;
}
