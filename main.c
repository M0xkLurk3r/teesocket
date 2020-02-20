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
#include "teesocksdk.h"
#include "dbgwait.h"

#include "logger.h"

#define MAXFDSIZE 64
#define BUFSIZE 65536

#define _In_
#define _Out_

static int PREKILL_SOCKFD = -1;

int startswith(_In_ const char* a, _In_ const char* b) {
	return a && b && strstr(a, b) == &a[0];
}

const char* strip_execprefix(const char* prefix) {
	int real_start_offset = 0;
	int p = 0;
	for (;; p++) {
		switch(prefix[p]) {
			case '\0':
				return &prefix[real_start_offset];
			case '/':
			case '.':
			case '\\':
				real_start_offset = p + 1;
				break;
		}
	}
	return &prefix[real_start_offset];
}

void help(const char* argv0, const char* preprint, int exitcode) {
	if (preprint) {
		fputs(preprint, stderr);
		fputc('\n', stderr);
	}
	fputs("teesocket: Read from socket input and write to multiple socket output\n", stderr);
	fputs("Written by Anthony Lee (https://github.com/M0xkLurk3r)\n", stderr);
	fprintf(stderr, "Usage: [%s] [args] ...\n\n", argv0);
	fputs("\t-i[0,5] --in=[0,5]\tIncoming handle, we allows 0~5 input handle\n", stderr);
	fputs("\t-o --out\t\tOutgoing handle\n", stderr);
	fputs("\t-m --multi\t\tMaximum incoming connection I could allow\n", stderr);
	fputs("\t-l --loadso\t\tExternal library (default is <yourlibrarypath>/libteesocket.so)\n", stderr);
	fputs("\t-s --slave\t\tSlave mode.(connect to --out address instead of listen)\n", stderr);
	fputs("\t-qb --quit-on-break\tQuit on any link broke (except outgoing connection in master mode)\n", stderr);
	fputs("\t-d --debug\t\tWaiting for debugger and continue. (Useful to debugging external library)\n", stderr);
	fputs("\t-ll --loglevel\t\tLogging level.\n", stderr);
	fputs("\t\t\t\t0 -> All log print verbosely\n", stderr);
	fputs("\t\t\t\t1 -> Print information, warning and error\n", stderr);
	fputs("\t\t\t\t2 -> Print warning and error\n", stderr);
	fputs("\t\t\t\t3 -> only error\n", stderr);
	fputs("\t-lt --log-to\t\tWrite log to (stderr, stdout, logcat, klog; defaults to stderr)\n", stderr);
	fprintf(stderr, "\t-lp --log-prefix\tLog prefix (defaults to %s)\n", strip_execprefix(argv0));
	fputs("\t-h --help\t\tShow this help\n", stderr);
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
		if ((startswith(argv[argvp], "-ll") || startswith(argv[argvp], "--loglevel")) && (argvp + 1) < argc) {
			conf->loglevel = atoi(argv[argvp + 1]);
		}
		if ((startswith(argv[argvp], "-lt") || startswith(argv[argvp], "--log-to")) && (argvp + 1) < argc) {
			conf->logto = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-lp") || startswith(argv[argvp], "--log-prefix")) && (argvp + 1) < argc) {
			conf->logprefix = argv[argvp + 1];
		}
		if (startswith(argv[argvp], "-s") || startswith(argv[argvp], "--slave")) {
			conf->outgodirect = OUTGOING;
		}
		if (startswith(argv[argvp], "-d") || startswith(argv[argvp], "--debug")) {
			conf->waitdbg = 1;
		}
		if ((startswith(argv[argvp], "-h") || startswith(argv[argvp], "--help"))) {
			help(argv[0], NULL, 0);
		}
		if ((startswith(argv[argvp], "-qb") || startswith(argv[argvp], "--quit-on-break"))) {
			conf->quitonbreak = 1;
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
		if (ctype == OUTGOING) {
			if (connect(openfd, saddr, socklen) == -1) {
				logprintf(LOGLVL_ERR, "ERROR: connect: %s\n", strerror(errno));
				exit(1);
			}
		} else if (ctype == INCOMING) {
			if (bind(openfd, saddr, socklen) == -1) {
				logprintf(LOGLVL_ERR, "ERROR: bind: %s\n", strerror(errno));
				exit(1);
			}
			if (listen(openfd, 1)) {
				logprintf(LOGLVL_ERR, "ERROR: listen: %s\n", strerror(errno));
				exit(1);
			}
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
		conf->incomefd[0] = resolve_fd_and_perform_link_on(conf->income0, OUTGOING, &conf->incometype[0]);
	}
	if (conf->income1) {
		conf->incomefd[1] = resolve_fd_and_perform_link_on(conf->income1, OUTGOING, &conf->incometype[1]);
	}
	if (conf->income2) {
		conf->incomefd[2] = resolve_fd_and_perform_link_on(conf->income2, OUTGOING, &conf->incometype[2]);
	}
	if (conf->income3) {
		conf->incomefd[3] = resolve_fd_and_perform_link_on(conf->income3, OUTGOING, &conf->incometype[3]);
	}
	if (conf->income4) {
		conf->incomefd[4] = resolve_fd_and_perform_link_on(conf->income4, OUTGOING, &conf->incometype[4]);
	}
	if (conf->income5) {
		conf->incomefd[5] = resolve_fd_and_perform_link_on(conf->income5, OUTGOING, &conf->incometype[5]);
	}
	conf->outgofd = resolve_fd_and_perform_link_on(conf->outgo, conf->outgodirect, &conf->outgotype);
}

void register_extern_library(_In_ struct config* conf) {
	char* so_path = conf->teesopath;
	if (!so_path) {
		so_path = "libteesocket.so";
	}
	void* teeso_handle = dlopen(so_path, 
								conf->waitdbg ? RTLD_NOW : RTLD_LAZY
								/* 
								 * Probably causes bug ...
								 * using better way to re-implement this
								 */
							   );
	if (teeso_handle) {
		__real_teesocket_init_ptr = dlsym(teeso_handle, "on_teesocket_libinit");
		if (__real_teesocket_init_ptr) {
			__real_on_teesocket_new_peers_ptr = dlsym(teeso_handle, "on_teesocket_new_peers");
			__real_on_teesocket_back_read_ready_ptr = dlsym(teeso_handle, "on_teesocket_back_read_ready");
			__real_on_teesocket_peers_write_ready_ptr = dlsym(teeso_handle, "on_teesocket_peers_write_ready");
			__real_on_teesocket_peers_read_ready_ptr = dlsym(teeso_handle, "on_teesocket_peers_read_ready");
			const char* (*shname)() = dlsym(teeso_handle, "TEESOCKET_MODULE_NAME");
			const char* (*shver)() = dlsym(teeso_handle, "TEESOCKET_MODULE_VER");
			logprintf(LOGLVL_INFO, "external library %s ver %s loaded\n", (*shname)(), (*shver)());
			return;
		} else {
			logprintf(LOGLVL_ERR, "ERROR while parsing libteesocket.so: %s\n", dlerror());
			exit(1);
		}
	} else {
		logprintf(LOGLVL_ERR, "ERROR while opening libteesocket.so: %s\n", dlerror());
		exit(1);
	}
}

void init_extern_library(_In_ int argc, _In_ char* argv[]) {
	extern_teesocket_init(argc, argv);
}

int write_to_peers(_In_ _Out_ void* shared_buf, 
				   _In_ const int peersfds[], 
				   _In_ int internalfdlen, 
				   _In_ int peersfdslen) {
	size_t proceed_len = extern_on_teesocket_peers_write_ready(0, shared_buf, BUFSIZE);
	if (proceed_len > 0) {
		for (int i = internalfdlen; i < peersfdslen; i++) {
			write(peersfds[i], shared_buf, proceed_len);
		}
	}
	return (proceed_len == BUFSIZE);
}

static inline int sizevalid(size_t size) {
	return (size > 0) && (size != -1);
}

/* for socket only */
int accept_peers(_In_ int outgofd, 
				 _In_ int maxfdsize, 
				 _In_ _Out_ int* peersfdslen,
				 _In_ int peersfds[], 
				 _Out_ fd_set* peersfdset, 
				 _In_ _Out_ void* shared_buf) {
	int peersfd = accept(outgofd, NULL, NULL);
	if ((*peersfdslen) >= maxfdsize) {
		// maximum connection reached, 
		// ignore further incoming connection
		close(peersfd);
	} else {
		if (peersfd > 0) {
			FD_SET(peersfd, peersfdset);
			peersfds[(*peersfdslen)] = peersfd;
			++(*peersfdslen);
		}
		size_t proceed_len = extern_on_teesocket_new_peers(shared_buf, BUFSIZE);
		if (sizevalid(proceed_len)) {
			// Write initial data
			write(peersfd, shared_buf, proceed_len);
		}
	}
	return 0;
}

int check_and_read_or_pop_peers(_In_ int internalfdlen, 
								_In_ _Out_ int* peersfdslen, 
								_In_ int peersfds[], 
								_In_ fd_set* rtfdset, 
								_Out_ fd_set* peersfdset,
								_In_ _Out_ void* buffer) {
	for (int i = internalfdlen; i < (*peersfdslen); i++) {
		if (FD_ISSET(peersfds[i], rtfdset)) {
			char tmpread;
			int rsize = read(peersfds[i], buffer, BUFSIZE);
			if (sizevalid(rsize)) {
				// We should close this connection
				close(peersfds[i]);
				FD_CLR(peersfds[i], peersfdset);
				peersfds[i] = peersfds[(*peersfdslen) - 1];
				--(*peersfdslen);	// like std::vector::pop()
			} else {
				extern_on_teesocket_peers_read_ready(i, buffer, rsize);
			}
		}
	}
	return 0;
}

void teesocket_event_loop(_In_ const struct config* conf) {
	int*		peersfds = (int *) malloc(sizeof(int) * conf->maxfdsize);
	int			peersfdslen = 2;
	int			internalfdlen = 0;
	int			incomefdlen = 1;	// at least we have one
	fd_set		peersfdset;
	uint8_t*	shared_buf = (uint8_t *) malloc(sizeof(uint8_t) * BUFSIZE);
	
	peersfds[0] = conf->incomefd[0];
	peersfds[1] = conf->outgofd;
	FD_ZERO(&peersfdset);
	FD_SET(peersfds[0], &peersfdset);
	FD_SET(peersfds[1], &peersfdset);
	
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
	
	// If we're working in slave mode, perform new_peers routine for one shot
	if (conf->outgodirect == OUTGOING) {
		size_t oneshot_newpeers_write_len = extern_on_teesocket_new_peers(shared_buf, BUFSIZE);
		if (sizevalid(oneshot_newpeers_write_len)) {
			write(conf->outgofd, shared_buf, oneshot_newpeers_write_len);
		}
	}
	
	for (;;) {
		fd_set rtfdset = peersfdset;
		struct timeval tv_time = {
			.tv_sec = 0,
			.tv_usec = 500
		};
		struct timeval* tv = NULL;
		int select_result = select(largefdnum(peersfds, peersfdslen) + 1, 
								   &rtfdset, NULL, NULL, tv);
		if (select_result > 0) {
			for (int i = 0; i < incomefdlen; i++) {
				if (FD_ISSET(conf->incomefd[i], &rtfdset)) {
					int recv_readlen = read(conf->incomefd[i], shared_buf, BUFSIZE);
					// TODO: perform read() operation
					if (sizevalid(recv_readlen)) {
						size_t readlen = extern_on_teesocket_back_read_ready(i, shared_buf, recv_readlen);
					} else {
						logprintf(LOGLVL_WARN, "Incoming channel %d closed connection, lasterror = \"%s\"\n", i, strerror(errno));
						if (conf->quitonbreak) {
							logprintf(LOGLVL_WARN, "Quit on link break.\n");
							exit(1);
						}
					}
				}
			}
			if (conf->outgotype == RFILE || conf->outgotype == STDFD 
				// If outgodirect == OUTGOING, we only have one fd and didn't need to accept(2) any longer
				|| conf->outgodirect == OUTGOING) {
				if ((conf->outgotype == INET || conf->outgotype == UNIX)
				&&	FD_ISSET(conf->outgofd, &rtfdset)) {
					size_t recv_readlen = read(conf->outgofd, shared_buf, BUFSIZE);
					if (sizevalid(recv_readlen)) {
						size_t readlen = extern_on_teesocket_peers_read_ready(0, shared_buf, recv_readlen);
					} else {
						logprintf(LOGLVL_WARN, "Outgoing channel closed connection, lasterror = \"%s\"\n", strerror(errno));
						if (conf->quitonbreak) {
							logprintf(LOGLVL_WARN, "Quit on link break.\n");
							exit(1);
						}
					}
				}
				size_t proceed_len = extern_on_teesocket_peers_write_ready(0, shared_buf, BUFSIZE);
				if (proceed_len > 0) {
					write(conf->outgofd, shared_buf, proceed_len);
				}
			} else {
				if (FD_ISSET(conf->outgofd, &rtfdset)) {
					// TODO: Perform accept()
					accept_peers(conf->outgofd, conf->maxfdsize, &peersfdslen, 
								 peersfds, &peersfdset, shared_buf);
				}
				check_and_read_or_pop_peers(internalfdlen, &peersfdslen, 
									peersfds, &rtfdset, &peersfdset, shared_buf);
				if (write_to_peers(shared_buf, peersfds, internalfdlen, peersfdslen)) {
					tv = &tv_time;
				} else {
					tv = NULL;
				}
			}
		} else if (select_result == 0) {
			if (! write_to_peers(shared_buf, peersfds, internalfdlen, peersfdslen)) {
				tv = NULL;
			} else {
				tv = &tv_time;
			}
		}
	}
}

void internal_init(_In_ struct config* conf) {
	
}

void wait_my_debugger(_In_ struct config* conf) {
	if (conf->waitdbg) {
		wait_for_debugger();
	}
}

void int_handler(int sig, void *s, void* u) {
	/* Close open socket for sane */
	close(PREKILL_SOCKFD);
	exit(0);
}

int main(int argc, char *argv[]) {
	struct config conf;
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
	
	resolve_argv(&conf, argc, argv);
	loginit(conf.logprefix ? conf.logprefix : argv[0], 
			conf.loglevel, 
			log_extract_type(conf.logto ? conf.logto : "stderr"));
	
	logprintf(LOGLVL_INFO, "Starts TEESocket\n");
	register_extern_library(&conf);
	wait_my_debugger(&conf);
	
	init_extern_library(argc, argv);
	resolve_config_to_fds(&conf);
	internal_init(&conf);
	teesocket_event_loop(&conf);
	return 0;
}
