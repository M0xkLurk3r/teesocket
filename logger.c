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

#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <syscall.h>
#include <errno.h>

static enum logtype LOGTYPE;
static char* PREFIX;
static FILE* logstream;

static int (* __ref_android_log_vprint)(int, const char*, const char *, va_list);
#define ANDROIDLOG(prio, tag, fmt, ap) (*__ref_android_log_vprint)((prio), (tag), (fmt), (ap))

static int LOGLVL;

void loginit(char* prefix, int loglvl, enum logtype type) {
	PREFIX = prefix;
	LOGTYPE = type;
	LOGLVL = loglvl;
	if (type == KLOG) {
		// Open a stream to /dev/kmsg
		logstream = fopen("/dev/kmsg", "w");
		if (! logstream) {
			// fuck, why did i always met crook environment made by crazy geeks...
			logstream = stderr;
			type = STDERR;
			int err = errno;
			logprintf(LOGLVL_WARN, "WARN: [err %d, %s], logging fallback to stderr\n", 
						err, strerror(err));
		}
	} else if (type == LOGCAT) {
		// TODO: call dlopen() and dlsym() to load android's fucking logging function
		void* liblog_handle = dlopen("liblog.so", RTLD_LAZY);
		if (! liblog_handle) {
			goto android_logcat_error;
		}
		__ref_android_log_vprint = dlsym(liblog_handle, "__android_log_vprint");
		if (! __ref_android_log_vprint) {
			goto android_logcat_error;
		}
		return;
		
		android_logcat_error:
			logstream = stderr;
			type = STDERR;
			logprintf(LOGLVL_WARN, "WARN: [%s], logging fallback to stderr\n", dlerror());
			return;
	} else {
		logstream = type == STDOUT ? stdout : stderr;
	}
}

void logprintf(int priority, const char* fmt, ...) {
	if (priority < LOGLVL) {
		return;
	}
	char fmtbuf[512] = "\0";
	va_list ap;
	va_start(ap, fmt);
	switch (LOGTYPE) {
		case LOGCAT:
			ANDROIDLOG(priority + 3, PREFIX, fmt, ap);
			break;
		case KLOG:
		case STDOUT:
		case STDERR:
			strcpy(fmtbuf, PREFIX);
			strcat(fmtbuf, ": ");
			strcat(fmtbuf, fmt);
			vfprintf(logstream, fmtbuf, ap);
	}
	va_end(ap);
}
