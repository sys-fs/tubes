/**
 * See the LICENSE file for licensing information
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PING_TIMEOUT 240
#define VERSION "1.0.0"

static char *server = "chat.freenode.net";
static char *port = "6667";
static FILE *log;
static SSL_CTX *ctx;
static SSL *ssl;
static short use_ssl = 0;
static unsigned int last_response;

/* connect to irc server */
int dial(char *server, char *port);
/* get SSL up and running */
int sslify(int *sockfd);
/* set up the error logging file */
FILE *slog(char *file);
/* mop up so we exit cleanly */
void mop(void);

int main(int argc, char **argv)
{
	int sockfd, in, out;
	int maxfd;
	fd_set rd;
	struct timeval tv;
	char buf[512];
	int i, r;

	for (i = 1; i < argc; i++) {
		char c = argv[i][1];
		if (argv[i][0] != '-' || argv[i][2])
			c = -1;
		switch (c) {
		case 'S':
			use_ssl = 1;
			break;
		case 's':
			if (++i < argc)
				server = argv[i];
			break;
		case 'p':
			if (++i < argc)
				port = argv[i];
			break;
		case 'v':
			fprintf(stderr, "tubes-%s © 2016 Thomas Mannay\n", VERSION);
			exit(0);
		default:
			fprintf(stderr,
				"usage: tubes [-S] [-s server] [-p port] [-v]\n");
			exit(0);
		}
	}

	if ((log = slog(".tubes.err")) == NULL) {
		fprintf(stderr, "tubes: error on slog()");
		exit(-1);
	}

	if (daemon(0, 0) == -1) {
		fprintf(log, "tubes: error on daemon()\n");
		exit(-1);
	}


	if ((sockfd = dial(server, port)) == -1)
		exit(-1);

	if (use_ssl && sslify(&sockfd) == -1)
		exit(-1);

	snprintf(buf, 512, "/tmp/%s.in", server);
	unlink(buf);
	mknod(buf, S_IFIFO | 0660, 0);
	in = open(buf, O_RDWR | O_NONBLOCK);
	snprintf(buf, 512, "/tmp/%s.out", server);
	unlink(buf);
	mknod(buf, S_IFIFO | 0660, 0);
	out = open(buf, O_RDWR);

	atexit(mop);

	for (;;) {
		FD_ZERO(&rd);
		maxfd = (out >= sockfd) ? out : sockfd;
		FD_SET(out, &rd);
		FD_SET(sockfd, &rd);

		tv.tv_sec = 10;
		tv.tv_usec = 0;
		r = select(maxfd+1, &rd, 0, 0, &tv);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			fprintf(log, "tubes: error on select()\n");
			exit(-1);
		} else if (r == 0) {
			if (time(NULL) - last_response >= PING_TIMEOUT) {
				fprintf(log, "tubes: ping timeout\n");
				exit(-1);
			}
		}
		if (FD_ISSET(out, &rd))
			if ((i = read(out, buf, sizeof(buf))) > 0) {
				buf[i] = 0;
				if (use_ssl)
					SSL_write(ssl, buf, strlen(buf));
				else
					send(sockfd, buf, strlen(buf), 0);
			}
		if (FD_ISSET(sockfd, &rd)) {
			if (use_ssl) {
				int blocked;
				do {
					blocked = 0;
					i = SSL_read(ssl, buf, sizeof(buf));
					if (SSL_get_error(ssl, i)
					    == SSL_ERROR_WANT_READ)
						blocked = 1;
				} while (SSL_pending(ssl) && !blocked);
			} else
				i = recv(sockfd, buf, sizeof(buf), 0);
			if (i != -1) {
				if (i == 0) {
					fprintf(log, "tubes: connection closed\n");
					close(sockfd);
					if (use_ssl)
						SSL_CTX_free(ctx);
					exit(0);
				}
				buf[i] = 0;
				if (write(in, buf, strlen(buf)) < 0) {
					if (errno == EINTR)
						continue;
					fprintf(log, "tubes: error on write()\n");
					exit(-1);
				}
				last_response = time(NULL);
			}
		}
	}

	return 0;
}

int dial(char *server, char *port)
{
	int sockfd, err;
	struct addrinfo hints, *serv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((err = getaddrinfo(server, port, &hints, &serv)) != 0) {
		fprintf(log, "getaddrinfo: %s\n", gai_strerror(err));
		return -1;
	} else if ((sockfd = socket(serv->ai_family,  serv->ai_socktype,
				    serv->ai_protocol)) == -1) {
		fprintf(log, "tubes: error on socket()\n");
		return -1;
	} else if (connect(sockfd, serv->ai_addr, serv->ai_addrlen) == -1) {
		fprintf(log, "tubes: error on connect().\n");
		close(sockfd);
		return -1;
	}
	freeaddrinfo(serv);

	return sockfd;
}

int sslify(int *sockfd)
{
	int r;

	SSL_library_init();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
			    | SSL_OP_SINGLE_DH_USE);
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, *sockfd);
	SSL_set_connect_state(ssl);

	if ((r = SSL_connect(ssl)) < 1) {
		fprintf(log, "tubes: %s\n", strerror(SSL_get_error(ssl, r)));
		SSL_CTX_free(ctx);
		return -1;
	}

	return 0;
}

FILE *slog(char *file)
{
	const char *home = getenv("HOME");
	char path[100];
	FILE *fp;

	snprintf(path, 100, "%s/%s", home, file);
	mknod(path, 0 | 0666, 0);
	fp = fopen(path, "w");

	return fp;
}

void mop(void)
{
	char str[512];

	ERR_free_strings();
	EVP_cleanup();
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	snprintf(str, 512, "/tmp/%s.in", server);
	unlink(str);
	snprintf(str, 512, "/tmp/%s.out", server);
	unlink(str);
}