/*************************************************************************************************************
Copyright (c) 2012-2016, Harman International Industries, Incorporated
All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS LISTED "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS LISTED BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*************************************************************************************************************/

#include <gptp_log.hpp>

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

void gptpLog(const char *tag, const char *path, int line, const char *fmt, ...)
{
	char msg[1024];

	va_list args;
	va_start(args, fmt);
	vsprintf(msg, fmt, args);

	time_t tNow = time(NULL);
	struct tm tmNow;
	localtime_r(&tNow, &tmNow);

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	if (path) {
		fprintf(stderr, "%s: GPTP [%2.2d:%2.2d:%2.2d:%3.3ld] [%s:%u] %s\n",
			   tag, tmNow.tm_hour, tmNow.tm_min, tmNow.tm_sec, ts.tv_nsec / 1000000, path, line, msg);
	}
	else {
		fprintf(stderr, "%s: GPTP [%2.2d:%2.2d:%2.2d:%3.3ld] %s\n",
			   tag, tmNow.tm_hour, tmNow.tm_min, tmNow.tm_sec, ts.tv_nsec / 1000000, msg);
	}
}





