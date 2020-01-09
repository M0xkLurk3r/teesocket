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

extern void __real_teesocket_init(struct config* conf, const int pipesin[], const int pipesout[]);
extern void __real_callback_peers_spawn(int peersfd);

#ifdef __cplusplus
}
#endif
#endif // TEESOCKSDK_H
