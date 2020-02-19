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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include "dbgwait.h"
#include "logger.h"

void wait_for_debugger() {
	logprintf(LOGLVL_INFO, "Wait for debugger.\n");
	logprintf(LOGLVL_INFO, "Hint: Attach your debugger to PID %d\n", getpid());
	
	const char* tracerpid = "TracerPid:";
	const int tracerpidlen = strlen(tracerpid);
	
	char* buf = malloc(4096);
	
	for (;;) {
		memset(buf, 0x00, 4096);
		int status_ffd = open("/proc/self/status", O_RDONLY);
		size_t readsize = read(status_ffd, buf, 4096);
		char* tracerpidptr = strstr(buf, tracerpid);
		char* tracerpidvalueptr = &tracerpidptr[tracerpidlen];
		for (;;) {
			char tpchr = *tracerpidvalueptr;
			switch (tpchr) {
				case '\0':
					goto tryagain;
				default: {
					if (isdigit(tpchr)) {
						if (tpchr > '0') {
							logprintf(LOGLVL_INFO, "Debugger presented, resuming.\n");
							goto end;
						} else {
							// continue to sleep 1 seconds for next try
							goto tryagain;
						}
					} else {
						// probably some problem ehhh....
						break;
					}
				}
			}
			tracerpidvalueptr++;
		}
		tryagain:
		close(status_ffd);
		sleep(1);
	}
	end:
	free(buf);
}
