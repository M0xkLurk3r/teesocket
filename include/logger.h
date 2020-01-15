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

#ifndef LOGGER_H
#define LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
	
enum logtype {
	STDOUT,
	STDERR,
	LOGCAT,
	KLOG
};

#define log_extract_type(type) !strcmp((type), "stdout") ?	\
					STDOUT : (!strcmp((type), "stderr") ?	\
					STDERR : (!strcmp((type), "logcat") ?	\
					LOGCAT : (!strcmp((type), "klog") ?		\
					KLOG : STDERR)))	// default to stderr

extern void loginit(char* prefix, enum logtype type);

#ifndef __HAS_LOGGER_API_DEFINED
#define __HAS_LOGGER_API_DEFINED
extern void logprintf(const char* fmt, ...);
#endif // __HAS_LOGGER_API_DEFINED

#ifdef __cplusplus
}
#endif
#endif // TEESOCKET_H
