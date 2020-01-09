#include "logger.h"
#include <stdio.h>
#include <stdarg.h>

static enum logtype LOGTYPE;
static char* PREFIX;
static FILE* logstream;

void loginit(char* prefix, enum logtype type) {
	PREFIX = prefix;
	LOGTYPE = type;
	if (type == KLOG) {
		// Open a stream to /dev/kmsg
		logstream = fopen("/dev/kmsg", "w");
		if (! logstream) {
			// fuck, why did i always met crook environment made by crazy geeks...
			logstream = stderr;
		}
	} else if (type == LOGCAT) {
		// TODO: call dlopen() and dlsym() to load android's fucking logging function
	} else {
		logstream = type == STDOUT ? stdout : stderr;
	}
}

void logprintf(const char* fmt, ...) {
	char fmtbuf[512] = "\0";
	va_list ap;
	switch (LOGTYPE) {
		case LOGCAT:
		
		case KLOG:
		case STDOUT:
		case STDERR:
			strcpy(fmtbuf, PREFIX);
			strcat(fmtbuf, ": ");
			strcat(fmtbuf, fmt);
	}
	va_start(ap, fmt);
	vfprintf(logstream, fmtbuf, ap);
	va_end(ap);
}
