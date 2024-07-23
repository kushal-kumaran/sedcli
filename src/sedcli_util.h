/*
 * Copyright (C) 2020, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SEDCLI_UTIL_H_
#define _SEDCLI_UTIL_H_

int get_access_type(const char *access_type_str, enum SED_ACCESS_TYPE *access_type);

int get_password(char *pwd, uint16_t *len, uint16_t max);

void *alloc_locked_buffer(size_t size);

void free_locked_buffer(void *buf, size_t buf_size);

#endif /* _SEDCLI_UTIL_H_ */
