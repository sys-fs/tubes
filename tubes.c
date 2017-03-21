/* See the LICENSE file for licensing information */
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
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PING_TIMEOUT 240

static SSL_CTX *ctx;
static SSL *ssl;
static char host[128] = "chat.freenode.net";
static char port[6] = "6667";
static short use_ssl = 0;
static unsigned int last_response;

static int
tube(char *direction)
{
	int fd;
	char buf[512];

	snprintf(buf, sizeof(buf), "/tmp/%s.%s", host, direction);
	unlink(buf);
	mkfifo(buf, 0660);
	if ((fd = open(buf, O_RDWR)) < 0)
		perror("tube");

	return fd;
}

static int
dial(char *host, char *port)
{
	int sockfd, err;
	struct addrinfo hints, *serv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((err = getaddrinfo(host, port, &hints, &serv)) != 0) {
		fprintf(stderr, "dial: %s\n", gai_strerror(err));
		return -1;
	}
	if ((sockfd = socket(serv->ai_family, serv->ai_socktype,
			     serv->ai_protocol)) < 0) {
		perror("dial");
		return -1;
	}
	if (connect(sockfd, serv->ai_addr, serv->ai_addrlen) < 0) {
		perror("dial");
		close(sockfd);
		return -1;
	}
	freeaddrinfo(serv);

	return sockfd;
}

static int
sslify(int *sockfd)
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
		fprintf(stderr, "sslify: %s\n", strerror(SSL_get_error(ssl, r)));
		SSL_CTX_free(ctx);
		return -1;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int sockfd, in, out;
	int maxfd;
	fd_set rd;
	struct timeval tv;
	char buf[512];
	int i, r, status;

	while ((i = getopt(argc, argv, "Sh:p:")) != -1) {
		switch (i) {
		case 'S':
			use_ssl = 1;
			strncpy(port, "6697", sizeof(port));
			break;
		case 'h':
			strncpy(host, optarg, sizeof(host));
			break;
		case 'p':
			strncpy(port, optarg, sizeof(port));
			break;
		default:
			fprintf(stderr, "usage: tubes [-S] [-h host] [-p port]\n");
			return 1;
		}
	}

	if ((sockfd = dial(host, port)) < 0)
		return 1;
	if (use_ssl && sslify(&sockfd) < 0)
		return 1;
	if ((in = tube("in")) < 0)
		return 1;
	if ((out = tube("out")) < 0)
		return 1;
	if (daemon(0, 0) < 0) {
		perror("main");
		return 1;
	}

	openlog(argv[0], LOG_PID, LOG_DAEMON);
	for (status = 0, last_response = time(NULL);;) {
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
			syslog(LOG_ERR, strerror(errno));
			status = 1;
			break;
		} else if (r == 0 && time(NULL) - last_response >= PING_TIMEOUT) {
			syslog(LOG_ERR, "ping timeout");
			status = 1;
			break;
		}
		if (FD_ISSET(out, &rd)) {
			if ((i = read(out, buf, sizeof(buf))) < 0) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "broken pipe");
				status = 1;
				break;
			} else if (i > 0) {
				buf[i] = 0;
				if (use_ssl)
					SSL_write(ssl, buf, strlen(buf));
				else
					send(sockfd, buf, strlen(buf), 0);
			}
		}
		if (FD_ISSET(sockfd, &rd)) {
			if (use_ssl) {
				do {
					r = 0;
					i = SSL_read(ssl, buf, sizeof(buf));
					if (SSL_get_error(ssl, i)
					    == SSL_ERROR_WANT_READ)
						r = 1;
				} while (SSL_pending(ssl) && !r);
			} else
				i = recv(sockfd, buf, sizeof(buf), 0);
			if (i != -1) {
				if (i == 0) {
					syslog(LOG_NOTICE, "connection closed");
					break;
				}
				buf[i] = 0;
				if (write(in, buf, strlen(buf)) < 0) {
					if (errno == EINTR)
						continue;
					syslog(LOG_ERR, "broken pipe");
					status = 1;
					break;
				}
				last_response = time(NULL);
			}
		}
	}

	close(sockfd);
	close(in);
	close(out);
	closelog();

	if (use_ssl) {
		ERR_free_strings();
		EVP_cleanup();
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ctx);
	}

	snprintf(buf, 512, "/tmp/%s.in", host);
	unlink(buf);
	snprintf(buf, 512, "/tmp/%s.out", host);
	unlink(buf);

	return status;
}
