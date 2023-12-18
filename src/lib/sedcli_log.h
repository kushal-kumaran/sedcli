/*
 * Copyright (C) 2018-2019, 2022-2023 Solidigm. All Rights Reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef SRC_SEDCLI_LOG_H_
#define SRC_SEDCLI_LOG_H_

#ifdef SEDCLI_DEBUG_LOGGING

#define SEDCLI_DEBUG_TRACE() printf("[SEDCLI] %s:%d()\n", __FILE__, __LINE__)
#define SEDCLI_DEBUG_MSG(msg) printf("[SEDCLI] %s:%d() - %s", __FILE__, __LINE__, msg)
#define SEDCLI_DEBUG_PARAM(format, ...) printf("[SEDCLI] %s:%d() - "format, __FILE__, __LINE__, ##__VA_ARGS__)
#define SEDCLI_DEBUG_SIMPLE(format, ...) printf(""format, ##__VA_ARGS__)

#else

#define SEDCLI_DEBUG_TRACE()
#define SEDCLI_DEBUG_MSG(msg)
#define SEDCLI_DEBUG_PARAM(format, ...)
#define SEDCLI_DEBUG_SIMPLE(format, ...)

#endif

#endif /* SRC_SEDCLI_LOG_H_ */
