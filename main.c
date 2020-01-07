/**
 * Created by Anthony Lee, in project teesocket
 * Distribute under Apache License 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define MAXFDSIZE 64

#define _In_
#define _Out_

enum conntype {
	INCOMING,
	OUTGOING
};

enum socktype {
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
	enum socktype incometype;
	int outgofd;
	enum socktype outgotype;
};

static int PREKILL_SOCKFD = -1;

int startswith(_In_ const char* a, _In_ const char* b) {
	return a && b && strstr(a, b) == &a[0];
}

void help(const char* argv0, const char* preprint, int exitcode) {
	if (preprint) {
		fputs(preprint, stderr);
	}
	fputs("teesocket: Read from socket input and write to multiple socket output\n", stderr);
	fputs("Written by Anthony Lee", stderr);
	fprintf(stderr, "Usage: [%s] [args] ...\n", argv0);
	fputs("\t-i --in\t\tIncoming handle\n", stderr);
	fputs("\t-o --out\tOutgoing handle\n", stderr);
	fputs("\t-m --multi\tMaximum incoming connection I could allow\n", stderr);
	fputs("\t-h --help\tShow this help\n", stderr);
	fputc('\n', stderr);
	exit(exitcode);
}

void resolve_argv(_Out_ struct config *conf, 
				  _In_ int argc, 
				  _In_ char* argv[]) {
	// FUCK GETOPT(3), almost rape my mind
	for (int argvp = 1; argvp < argc; argvp++) {
		if ((startswith(argv[argvp], "-i") || startswith(argv[argvp], "--in")) && (argvp + 1) < argc) {
			conf->income = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-o") || startswith(argv[argvp], "--out")) && (argvp + 1) < argc) {
			conf->outgo = argv[argvp + 1];
		}
		if ((startswith(argv[argvp], "-m") || startswith(argv[argvp], "--multi")) && (argvp + 1) < argc) {
			conf->maxfdsize = atoi(argv[argvp + 1]);
		}
		if ((startswith(argv[argvp], "-h") || startswith(argv[argvp], "--help"))) {
			help(argv[0], NULL, 0);
		}
	}
	if (!conf->income || !conf->outgo) {
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
						 _In_	enum conntype ctype,
						 _Out_	enum socktype* stype,
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
		PREKILL_SOCKFD = sockfd;
		return sockfd;
	}
}

int resolve_fd_and_perform_link_on(_In_	const char* protostr, 
								   _In_	enum conntype ctype,
								   _Out_ enum socktype* stype) {
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
	conf->incomefd = resolve_fd_and_perform_link_on(conf->income, INCOMING, &conf->incometype);
	conf->outgofd = resolve_fd_and_perform_link_on(conf->outgo, OUTGOING, &conf->outgotype);
}

void teesocket_event_loop(_In_ const struct config* conf) {
	int* peersfds = (int *) malloc(sizeof(int) * conf->maxfdsize);
	int peersfdslen = 2;
	fd_set peersfdset;
	uint8_t* shared_buf = (uint8_t *) malloc(sizeof(uint8_t) * 4096);
	peersfds[0] = conf->incomefd;
	peersfds[1] = conf->outgofd;
	FD_ZERO(&peersfdset);
	FD_SET(peersfds[0], &peersfdset);
	FD_SET(peersfds[1], &peersfdset);
	for (;;) {
		fd_set rtfdset = peersfdset;
		int select_result = select(largefdnum(peersfds, peersfdslen) + 1, &rtfdset, NULL, NULL, NULL);
		int incoming_readlen = 0;
		if (select_result > 0) {
			if (FD_ISSET(peersfds[0], &rtfdset)) {
				incoming_readlen = read(peersfds[0], shared_buf, 4096);
			}
			if (conf->outgotype == RFILE || conf->outgotype == STDFD) {
				if (FD_ISSET(peersfds[1], &rtfdset)) {
					write(peersfds[1], shared_buf, incoming_readlen);
				}
			} else {
				if (FD_ISSET(peersfds[1], &rtfdset)) {
					// TODO: Perform accept()
					struct sockaddr addr;
					socklen_t len;
					int peersfd = accept(peersfds[1], &addr, &len);
					if (peersfdslen >= conf->maxfdsize) {
						// maximum connection reached, ignore further incoming connection
						close(peersfd);
					} else {
						if (peersfd > 0) {
							FD_SET(peersfd, &peersfdset);
							peersfds[peersfdslen] = peersfd;
							++peersfdslen;
						}
					}
				}
				for (int i = 2; i < peersfdslen; i++) {
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
				for (int i = 2; i < peersfdslen; i++) {
					write(peersfds[i], shared_buf, incoming_readlen);
				}
			}
		}
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
	
	resolve_argv(&conf, argc, argv);
	resolve_config_to_fds(&conf);
	teesocket_event_loop(&conf);
	return 0;
}
