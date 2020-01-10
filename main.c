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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "teesocket.h"
#include "teesocket_internal.h"
#include "dumbsdk.h"
// #include "shbuf.h"

#include "logger.h"

#define MAXFDSIZE 64

#define _In_
#define _Out_

static int PREKILL_SOCKFD = -1;

int startswith(_In_ const char* a, _In_ const char* b) {
	return a && b && strstr(a, b) == &a[0];
}

void help(const char* argv0, const char* preprint, int exitcode) {
	if (preprint) {
		fputs(preprint, stderr);
		fputc('\n', stderr);
	}
	fputs("teesocket: Read from socket input and write to multiple socket output\n", stderr);
	fputs("Written by Anthony Lee", stderr);
	fprintf(stderr, "Usage: [%s] [args] ...\n", argv0);
	fputs("\t-i[0,6] --in=[0,6]\t\tIncoming handle, we allows 0~6 input handle\n", stderr);
	fputs("\t-o --out\tOutgoing handle\n", stderr);
	fputs("\t-m --multi\tMaximum incoming connection I could allow\n", stderr);
	fputs("\t-l --loadso\tAlternative shared object (default is ${librarypath}/libteesocket.so)\n", stderr);
	fputs("\t-h --help\tShow this help\n", stderr);
	fputc('\n', stderr);
	exit(exitcode);
}

void resolve_argv(_Out_ struct config *conf, 
				  _In_ int argc, 
				  _In_ char* argv[]) {
	// FUCK GETOPT(3), almost rape my mind
	for (int argvp = 1; argvp < argc; argvp++) {
		if ((startswith(argv[argvp], "-i0") || startswith(argv[argvp], "--in=0")) && (argvp + 1) < argc) {
			conf->income0 = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-i1") || startswith(argv[argvp], "--in=1")) && (argvp + 1) < argc) {
			conf->income1 = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-i2") || startswith(argv[argvp], "--in=2")) && (argvp + 1) < argc) {
			conf->income2 = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-i3") || startswith(argv[argvp], "--in=3")) && (argvp + 1) < argc) {
			conf->income3 = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-i4") || startswith(argv[argvp], "--in=4")) && (argvp + 1) < argc) {
			conf->income4 = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-i5") || startswith(argv[argvp], "--in=5")) && (argvp + 1) < argc) {
			conf->income5 = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-o") || startswith(argv[argvp], "--out")) && (argvp + 1) < argc) {
			conf->outgo = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-m") || startswith(argv[argvp], "--multi")) && (argvp + 1) < argc) {
			conf->maxfdsize = atoi(argv[argvp + 1]);
		}
		if ((startswith(argv[argvp], "-l") || startswith(argv[argvp], "--loadso")) && (argvp + 1) < argc) {
			conf->teesopath = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-h") || startswith(argv[argvp], "--help"))) {
			help(argv[0], NULL, 0);
		}
	}
	if (!conf->income0 || !conf->outgo) {
		// We need at least one input and valid output
		help(argv[0], "ERROR: argument expected.", 1);
	}
	if (!conf->maxfdsize) {
		conf->maxfdsize = MAXFDSIZE;
	}
}

socklen_t unwrap_protocol_to_sockaddr(_In_	const char* protostr, 
									  _Out_	struct sockaddr* saddr) {
	if (startswith(protostr, "tcp://")) { // e.g. tcp://192.168.1.1:22
		// I ensure (*saddr) has declared as type `struct sockaddr_in`
		struct sockaddr_in* saddrptr = (struct sockaddr_in *)saddr;
		saddrptr->sin_family = AF_INET;
		char buf[128] = "\0";
		// strip out the protocol prefix (we got "192.168.1.1:22")
		strcpy(buf, &protostr[6]);
		char* portpos = strstr(buf, ":");
		// Replace ':' to '\0'
		*portpos = '\0';
		saddrptr->sin_addr.s_addr = inet_addr(buf);	// we got "192.168.1.1"
		// right shift the pointer and get the port number string (got "22")
		saddrptr->sin_port = htons(atoi(&portpos[1]));
		return sizeof(struct sockaddr_in);
	} else if (startswith(protostr, "unix://")) {
		struct sockaddr_un* saddrptr = (struct sockaddr_un *)saddr;
		saddrptr->sun_family = AF_UNIX;
		strcpy(saddrptr->sun_path, &protostr[7]);
		return sizeof(saddrptr->sun_family) + strlen(saddrptr->sun_path);
	} else if (startswith(protostr, "file://")) {
		saddr->sa_data[0] = 'F';
		saddr->sa_data[1] = 'I';
		saddr->sa_data[2] = 'L';
		saddr->sa_data[3] = 'E';
		saddr->sa_data[4] = '\0';
		saddr->sa_family = 0xFF;
		return sizeof(saddr->sa_family) + 4;
	} else if (!strcmp(protostr, "-") || !strcmp(protostr, "stdin")|| !strcmp(protostr, "stdout")) {
		memset(saddr, 0xFF, sizeof(struct sockaddr));
		return 1;
	}
	return 0;
}

// WARN: Will proceed socket connect in the period
int resolve_config_to_fd(_In_	const char* protostr, 
						 _In_	enum __tee_conntype ctype,
						 _Out_	enum __tee_socktype* stype,
						 _Out_	struct sockaddr* saddr,
						 _Out_	socklen_t* socklen) {
	*socklen = unwrap_protocol_to_sockaddr(protostr, saddr);
	int sock_family = saddr->sa_family;
	if (sock_family == 0xFFFF) {
		// for stdin/stdout, don't perform any bind(2), listen(2) or connect(2)
		if (saddr->sa_data[0] == 'F'
		 && saddr->sa_data[1] == 'I'
		 && saddr->sa_data[2] == 'L'
		 && saddr->sa_data[3] == 'E') {
			*stype = RFILE;
			return open(&protostr[strlen("file://") + 1], ctype == INCOMING ? O_RDONLY : O_WRONLY);
		} else {
			*stype = STDFD;
			return ctype == INCOMING ? STDIN_FILENO : STDOUT_FILENO;
		}
	} else {
		*stype = sock_family == AF_INET ? INET : UNIX;
		int sockfd = socket(sock_family, SOCK_STREAM, 
					  sock_family == AF_INET ? IPPROTO_TCP : 0 /* 0 for UNIX protocol */);
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));
		PREKILL_SOCKFD = sockfd;
		return sockfd;
	}
}

int resolve_fd_and_perform_link_on(_In_	const char* protostr, 
								   _In_	enum __tee_conntype ctype,
								   _Out_ enum __tee_socktype* stype) {
	uint8_t buf[256];
	memset(buf, 0x00, 256);
	struct sockaddr* saddr = (struct sockaddr *)buf;	// store data on buf
	socklen_t socklen;
	int openfd = resolve_config_to_fd(protostr, ctype, stype, saddr, &socklen);
	if (openfd > 2) {
		if (ctype == INCOMING) {
			connect(openfd, saddr, socklen);
		} else if (ctype == OUTGOING) {
			bind(openfd, saddr, socklen);
			listen(openfd, 1);
		}
	}
	return openfd;
}

int largefdnum(_In_ const int fdarr[], _In_ int fdarrlen) {
	int largernum = 0;
	for (int i = 0; i < fdarrlen; i++) {
		if (fdarr[i] > largernum) {
			largernum = fdarr[i];
		}
	}
	return largernum;
}

void resolve_config_to_fds(_In_ _Out_ struct config* conf) {
	// now proceed income
	for (int i = 0; i < 6; i++) {
		conf->incomefd[i] = -1;
	}
	if (conf->income0) {
		conf->incomefd[0] = resolve_fd_and_perform_link_on(conf->income0, INCOMING, &conf->incometype[0]);
	}
	if (conf->income1) {
		conf->incomefd[1] = resolve_fd_and_perform_link_on(conf->income1, INCOMING, &conf->incometype[1]);
	}
	if (conf->income2) {
		conf->incomefd[2] = resolve_fd_and_perform_link_on(conf->income2, INCOMING, &conf->incometype[2]);
	}
	if (conf->income3) {
		conf->incomefd[3] = resolve_fd_and_perform_link_on(conf->income3, INCOMING, &conf->incometype[3]);
	}
	if (conf->income4) {
		conf->incomefd[4] = resolve_fd_and_perform_link_on(conf->income4, INCOMING, &conf->incometype[4]);
	}
	if (conf->income0) {
		conf->incomefd[5] = resolve_fd_and_perform_link_on(conf->income0, INCOMING, &conf->incometype[5]);
	}
	conf->outgofd = resolve_fd_and_perform_link_on(conf->outgo, OUTGOING, &conf->outgotype);
}

void register_default_external_library(_In_ struct config* conf,
									   _In_ const int pipefdsin[],
									   _In_ const int pipefdsout[]) {
	// TODO: We should probably implement a one-way pass function of teesocket_init()...
	__real_teesocket_init = __dumb_teesocket_init;
	extern_teesocket_init(conf, &pipefdsin[0], &pipefdsout[1]);
}	

void register_extern_library(_In_ struct config* conf, 
							 _In_ const int pipefdsin[],
							 _In_ const int pipefdsout[]) {
	char* so_path = conf->teesopath;
	if (!so_path) {
		so_path = "libteesocket.so";
	}
	void* teeso_handle = dlopen(so_path, RTLD_LAZY);
	if (teeso_handle) {
		__real_teesocket_init = dlsym(teeso_handle, "__real_teesocket_init");
		if (__real_teesocket_init) {
			extern_teesocket_init(conf, &pipefdsin[0], &pipefdsout[1]);
			return;
		}
	}
	// TODO: Pass a default `__real_teesocket_init' function (could also be implemented of us)
	// 		 to make the workflow work.
	register_default_external_library(conf, pipefdsin, pipefdsout);
}

void teesocket_event_loop(_In_ const struct config* conf, 
						  _In_ const int pipefdsin[],
						  _In_ const int pipefdsout[]) {
	int*		peersfds = (int *) malloc(sizeof(int) * conf->maxfdsize);
	int			peersfdslen = 2;
	int			internalfdlen = 0;
	int			incomefdlen = 0;
	fd_set		peersfdset;
	uint8_t*	shared_buf = (uint8_t *) malloc(sizeof(uint8_t) * 32768);
	uint8_t*	shared_buf1 = (uint8_t *) malloc(sizeof(uint8_t) * 32768);
	
	peersfds[0] = conf->incomefd[0];
	peersfds[1] = conf->outgofd;
	FD_ZERO(&peersfdset);
	FD_SET(peersfds[0], &peersfdset);
	FD_SET(peersfds[1], &peersfdset);
	
	// Add available pipe readfd to array
	peersfds[2] = pipefdsout[0];
	FD_SET(pipefdsout[0], &peersfdset);
	++peersfdslen;
	
	for (int i = 1; i < 6; i++) {
		if (conf->incomefd[i] >= 0) {
			peersfds[i + 2] = conf->incomefd[i];
			FD_SET(conf->incomefd[i], &peersfdset);
			++peersfdslen;
			++incomefdlen;
		}
	}
	
	// store current fdlen
	internalfdlen = peersfdslen;
	
	for (;;) {
		fd_set rtfdset = peersfdset;
		int select_result = select(largefdnum(peersfds, peersfdslen) + 1, 
								   &rtfdset, NULL, NULL, NULL);
		int incoming_readlen = 0;
		if (select_result > 0) {
			for (int i = 0; i < incomefdlen; i++) {
				if (FD_ISSET(conf->incomefd[i], &rtfdset)) {
					int recv_readlen = read(conf->incomefd[i], shared_buf, 32768);
					write(pipefdsin[32 + i], shared_buf, recv_readlen);
				}
			}
			if (FD_ISSET(pipefdsout[0], &rtfdset)) {
				incoming_readlen = read(pipefdsout[0], shared_buf1, 32768);
			}
			
			if (conf->outgotype == RFILE || conf->outgotype == STDFD) {
				if (FD_ISSET(conf->outgofd, &rtfdset) && incoming_readlen > 0) {
					write(conf->outgofd, shared_buf1, incoming_readlen);
				}
			} else {
				if (FD_ISSET(conf->outgofd, &rtfdset)) {
					// TODO: Perform accept()
					struct sockaddr addr;
					socklen_t len = 0;
					int peersfd = accept(conf->outgofd, &addr, &len);
					if (peersfdslen >= conf->maxfdsize) {
						// maximum connection reached, 
						// ignore further incoming connection
						close(peersfd);
					} else {
						if (peersfd > 0) {
							FD_SET(peersfd, &peersfdset);
							peersfds[peersfdslen] = peersfd;
							++peersfdslen;
						}
					}
				}
				for (int i = internalfdlen; i < peersfdslen; i++) {
					if (FD_ISSET(peersfds[i], &rtfdset)) {
						char tmpread;
						int rsize = read(peersfds[i], &tmpread, 1);
						if (rsize == 0) {
							// We should close this connection
							close(peersfds[i]);
							FD_CLR(peersfds[i], &peersfdset);
							peersfds[i] = peersfds[peersfdslen - 1];
							--peersfdslen;	// like std::vector::pop()
						}
					}
				}
				if (incoming_readlen > 0) {
					for (int i = internalfdlen; i < peersfdslen; i++) {
						write(peersfds[i], shared_buf1, incoming_readlen);
					}
				}
			}
		}
	}
}

void internal_init(_In_ struct config* conf, _Out_ int pipefdsin[], _Out_ int pipefdsout[]) {
	/* 
	 * Based on current implementation, we just have one input.
	 * So we just alloc one pipe.
	 */
	for (int i = 0; i < 64; i++) {
		// fill with -1 first
		pipefdsin[i] = -1;
	}
	for (int i = 0; conf->incomefd[i] >=0 && i < 6; i++) {
		int p[2] = {0};
		pipe(p);
		pipefdsin[i] = p[0];
		pipefdsin[i + 32] = p[1];
	}
	pipe(pipefdsout);	// Should add more in the future
}

void int_handler(int sig, void *s, void* u) {
	/* Close open socket for sane */
	close(PREKILL_SOCKFD);
	exit(0);
}

int main(int argc, char *argv[]) {
	struct config conf;
	/**
	 * Allows up to 32 peers; first 32 elements were pipe(2)'s read end,
	 * the 32th element was write end, those fds should be mapped as one-to-one.
	 */
	int pipefdsin[64] = {0};
	/**
	 * Output fds allows up to 1 peers.
	 */
	int pipefdsout[2] = {0};
	/*
	 * Capture SIGPIPE, SIGINT and SIGTERM.
	 * SIGPIPE just pay no action to it,
	 * SIGINT and SIGTERM will let us close listening socket manually
	 */
	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sa.sa_handler = int_handler;
	
	signal(SIGPIPE, SIG_IGN);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	
	memset(&conf, 0x00, sizeof(struct config));
	
	loginit(argv[0], log_extract_type("stderr"));
	logprintf("Starts TEESocket\n");
	resolve_argv(&conf, argc, argv);
	register_extern_library(&conf, pipefdsin, pipefdsout);
	resolve_config_to_fds(&conf);
	internal_init(&conf, pipefdsin, pipefdsout);
	teesocket_event_loop(&conf, pipefdsin, pipefdsout);
	return 0;
}
