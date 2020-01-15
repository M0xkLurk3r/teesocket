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

#ifndef TEESOCKSDK_H
#define TEESOCKSDK_H

#ifdef __cplusplus
extern "C" {
#endif

#include "teesocket.h"

extern void __real_teesocket_init(int host_argc, char* host_argv[]);

static void (*__real_teesocket_init_ptr)(int host_argc, char* host_argv[]);
#define extern_teesocket_init(host_argc, host_argv)	(*__real_teesocket_init_ptr)((host_argc), (host_argv))

static size_t (*__real_on_teesocket_back_read_ready_ptr)(int, const void*, const size_t);
#define extern_on_teesocket_back_read_ready(clientid, buffer, length) \
		(*__real_on_teesocket_back_read_ready_ptr)((clientid), (buffer), (length))

static size_t (*__real_on_teesocket_peers_write_ready_ptr)(int, const void*, const size_t);
#define extern_on_teesocket_peers_write_ready(clientid, buffer, maxlen) \
		(*__real_on_teesocket_peers_write_ready_ptr)((clientid), (buffer), (maxlen))

static size_t (*__real_on_teesocket_peers_read_ready_ptr)(int, const void*, const size_t);
#define extern_on_teesocket_peers_read_ready(clientid, buffer, length) \
		(*__real_on_teesocket_peers_read_ready_ptr)((clientid), (buffer), (length))

static size_t (*__real_on_teesocket_new_peers_ptr)(const void*, const size_t);
#define extern_on_teesocket_new_peers(buffer, maxlen) \
		(*__real_on_teesocket_new_peers_ptr)((buffer), (maxlen))

#ifdef __cplusplus
}
#endif
#endif // TEESOCKSDK_H
