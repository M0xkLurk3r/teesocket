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

enum __tee_conntype {
	INCOMING,
	OUTGOING
};

enum __tee_socktype {
	INET,
	UNIX,
	RFILE,
	STDFD
};

struct config {
	char* income;
	char* outgo;
	char** shell_argv;
	int maxfdsize;
	int incomefd;
	enum __tee_socktype incometype;
	int outgofd;
	enum __tee_socktype outgotype;
};


extern void teesocket_init(const struct config* conf);
extern int callback_teesocket_incoming(int clientnum, const void* data, size_t length);
extern void teesocket_outgoing(const void* data, size_t length);

#ifdef __cplusplus
}
#endif
#endif // TEESOCKET_H
