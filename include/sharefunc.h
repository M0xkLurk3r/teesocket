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

#ifndef SHAREFUNC_H
#define SHAREFUNC_H

#ifdef __cplusplus
extern "C" {
#endif
	
#include <stdio.h>

struct sharefunc {
	void* (*func)(void *);
	char* funcname;
	struct sharefunc* next;
};

extern struct sharefunc* create_sharefunc_table();
extern void push_sharefunc_table(struct sharefunc* ptable, void* (*func)(void *), char* funcname);
extern void* pop_sharefunc_table(struct sharefunc* ptable, char* funcname);
extern void* enum_sharefunc_table(struct sharefunc* ptable, char* funcname);
extern void destory_sharefunc_table(struct sharefunc* ptable);


#ifdef __cplusplus
}
#endif
#endif // SHAREFUNC_H
