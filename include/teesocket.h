/**
 *    Created by Anthony Lee, in project teesocket
 *    Copyright 2020 Anthony Lee
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef TEESOCKET_H
#define TEESOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
extern size_t on_teesocket_back_read_ready(int clientid, const void* buffer, const size_t length);
extern size_t on_teesocket_peers_write_ready(int clientid, void* buffer, const size_t maxlen);
extern size_t on_teesocket_peers_read_ready(int clientid, const void* buffer, const size_t length);
extern size_t on_teesocket_new_peers(void* buffer, const size_t maxlen);

extern void on_teesocket_libinit(int host_argc, char* host_argv[]);

/* For libteesocket compatibility, we copied the declaration to here */

#ifndef __HAS_LOGGER_API_DEFINED
#define __HAS_LOGGER_API_DEFINED
enum _loglvl {
	LOGLVL_DEBUG = 0,
	LOGLVL_INFO,
	LOGLVL_WARN,
	LOGLVL_ERR
};

extern void logprintf(int priority, const char* fmt, ...);
extern void logprintf_info(const char* fmt, ...);
#endif // __HAS_LOGGER_API_DEFINED


#ifdef __cplusplus
}
#endif
#endif // TEESOCKET_H
