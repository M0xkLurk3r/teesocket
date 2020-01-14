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

#ifndef TEESOCKET_INTERNAL_H
#define TEESOCKET_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif
	
#include <stdio.h>
	
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
	char* income0;
	char* income1;
	char* income2;
	char* income3;
	char* income4;
	char* income5;
	char* outgo;
	char** shell_argv;
	char* teesopath;
	int maxfdsize;
	int incomefd[6];
	enum __tee_socktype incometype[6];
	int outgofd;
	enum __tee_socktype outgotype;
};

#ifdef __cplusplus
}
#endif

#endif //TEESOCKET_INTERNAL_H
