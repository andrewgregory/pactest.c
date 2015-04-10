/*
 * Copyright 2015 Andrew Gregory <andrew.gregory.8@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Project URL: http://github.com/andrewgregory/pactest.c
 */

#ifndef PTSERVE_C
#define PTSERVE_C

#define PTSERVE_C_VERSION 0.1

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

#include <alpm.h>

typedef struct ptserve_message_t {
	struct ptserve_t *ptserve;
	char *method;
	char *path;
	char *protocol;
	alpm_list_t *headers;
	int socket_fd;
} ptserve_message_t;

typedef void (ptserve_response_cb_t)(ptserve_message_t *request);

typedef struct ptserve_t {
	ptserve_response_cb_t *response_cb;
	uint16_t port;
	char *url;
	void *data;
	int rootfd;
	int sd_server;
	pid_t _pid;
	pthread_t _tid;
} ptserve_t;

/*****************************************************************************
 * utilities
 ****************************************************************************/

static int _vasprintf(char **strp, const char *fmt, va_list args) {
	va_list arg_cp;
	size_t len;
	va_copy(arg_cp, args);
	len = vsnprintf(NULL, 0, fmt, arg_cp);
	va_end(arg_cp);
	if((*strp = malloc(len + 2)) != NULL) { return vsprintf(*strp, fmt, args); }
	else { return -1; }
}

static int _asprintf(char **strp, const char *fmt, ...) {
	va_list args;
	int ret;
	va_start(args, fmt);
	ret = _vasprintf(strp, fmt, args);
	va_end(args);
	return ret;
}

static ssize_t _send(int socket, const void *buf, size_t len) {
	return send(socket, buf, len, MSG_NOSIGNAL);
}

static ssize_t _sendf(int socket, const char *fmt, ...) {
	ssize_t ret;
	char *buf = NULL;
	int blen = 0;
	va_list args;
	va_start(args, fmt);
	blen = _vasprintf(&buf, fmt, args);
	va_end(args);
	ret = _send(socket, buf, blen);
	free(buf);
	return ret;
}

static ssize_t _dgetdelim(int fd, char *buf, ssize_t bufsiz, char *delim) {
	char *d = delim, *b = buf;
	while(1) {
		ssize_t ret = read(fd, b, 1);
		if(ret == 0) { *b = '\0'; return b - buf; }
		if(ret == -1) { return -1; }
		if(*d && *b == *d) {
			if(*(++d) == '\0') {
				b -= strlen(delim) - 1;
				*b = '\0';
				return b - buf;
			}
		} else {
			d = delim;
		}
		if(++b - buf >= bufsiz - 1) { return -1; }
	}
}

/*****************************************************************************
 * http message
 ****************************************************************************/

#define PTSERVE_HDR_MAX 1024
ptserve_message_t *ptserve_message_new(ptserve_t *server, int socket_fd) {
	ptserve_message_t *msg = calloc(sizeof(ptserve_message_t), 1);
	char line[PTSERVE_HDR_MAX];

	_dgetdelim(socket_fd, line, PTSERVE_HDR_MAX, " ");
	msg->method = strdup(line);
	_dgetdelim(socket_fd, line, PTSERVE_HDR_MAX, " ");
	msg->path = strdup(line);
	_dgetdelim(socket_fd, line, PTSERVE_HDR_MAX, "\r\n");
	msg->protocol = strdup(line);

	while(_dgetdelim(socket_fd, line, PTSERVE_HDR_MAX, "\r\n") > 0) {
		msg->headers = alpm_list_add(msg->headers, strdup(line));
	}

	msg->ptserve = server;
	msg->socket_fd = socket_fd;

	return msg;
}

void ptserve_message_free(ptserve_message_t *msg) {
	if(msg == NULL) { return; }
	free(msg->method);
	free(msg->path);
	free(msg->protocol);
	FREELIST(msg->headers);
	if(msg->socket_fd >= 0) { close(msg->socket_fd); }
	free(msg);
}

const char *ptserve_message_get_header(ptserve_message_t *msg, const char *hdr) {
	alpm_list_t *i;
	size_t hlen = strlen(hdr);
	for(i = msg->headers; i; i = alpm_list_next(i)) {
		const char *mhdr = i->data;
		if(strncasecmp(mhdr, hdr, hlen) == 0 && strncmp(mhdr + hlen, ": ", 2) == 0) {
			return mhdr + hlen + 2;
		}
	}
	return NULL;
}

void ptserve_message_rm_header(ptserve_message_t *msg, const char *hdr) {
	alpm_list_t *i;
	size_t hlen = strlen(hdr);
	for(i = msg->headers; i; i = i->next) {
		char *oldheader = i->data;
		if(strncasecmp(i->data, hdr, hlen) == 0 && oldheader[hlen] == ':') {
			msg->headers = alpm_list_remove_item(msg->headers, i);
			free(i->data);
			free(i);
			return;
		}
	}
}

int ptserve_message_set_header(ptserve_message_t *message,
		const char *header, const char *value) {
	alpm_list_t *i;
	char *newheader;
	size_t hlen = strlen(header);

	if(_asprintf(&newheader, "%s: %s", header, value) == -1) { return 0; }

	/* look for an existing header */
	for(i = message->headers; i; i = i->next) {
		char *oldheader = i->data;
		if(strncasecmp(i->data, header, hlen) == 0 && oldheader[hlen] == ':') {
			free(i->data);
			i->data = newheader;
			return 1;
		}
	}

	message->headers = alpm_list_add(message->headers, newheader);
	return 1;
}

/*****************************************************************************
 * ptserve
 ****************************************************************************/

ptserve_t *ptserve_new() {
	ptserve_t *ptserve = calloc(sizeof(ptserve_t), 1);
	if(ptserve == NULL) { return NULL; }
	ptserve->rootfd = AT_FDCWD;
	ptserve->sd_server = -1;
	ptserve->_tid = -1;
	return ptserve;
}

void ptserve_free(ptserve_t *ptserve) {
	if(ptserve == NULL) { return; }
	/* kill(ptserve->_pid, SIGTERM); */
	/* waitpid(ptserve->_pid, NULL, 0); */
	/* if(ptserve->_tid != -1) { */
	/* 	pthread_kill(ptserve->_tid, SIGINT); */
	/* 	pthread_join(ptserve->_tid, NULL); */
	/* } */
	free(ptserve->url);
	free(ptserve);
}

void ptserve_listen(ptserve_t *ptserve) {
	struct sockaddr_in sin;
	socklen_t addrlen = sizeof(sin);

	if(ptserve->sd_server >= 0) { return; } /* already listening */

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(0);

	ptserve->sd_server = socket(PF_INET, SOCK_STREAM, 0);
	bind(ptserve->sd_server, (struct sockaddr*) &sin, sizeof(sin));
	getsockname(ptserve->sd_server, (struct sockaddr*) &sin, &addrlen);

	listen(ptserve->sd_server, SOMAXCONN);

	ptserve->port = ntohs(sin.sin_port);
	_asprintf(&(ptserve->url), "http://127.0.0.1:%d", ptserve->port);
}

int ptserve_accept(ptserve_t *ptserve) {
	return accept(ptserve->sd_server, 0, 0);
}

void *ptserve_serve(void *arg) {
	ptserve_t *ptserve = arg;
	int session_fd;
	ptserve_listen(ptserve);
	while((session_fd = ptserve_accept(ptserve)) >= 0) {
		ptserve_message_t *msg = ptserve_message_new(ptserve, session_fd);
		ptserve->response_cb(msg);
		ptserve_message_free(msg);
	}
	return NULL;
}

/*****************************************************************************
 * ptserve helpers
 ****************************************************************************/

void ptserve_send_file(int socket, int rootfd, const char *path) {
	struct stat sbuf;
	ssize_t nread;
	char buf[128];
	int fd = openat(rootfd, path, O_RDONLY);
	fstat(fd, &sbuf);
	_sendf(socket, "HTTP/1.1 200 OK\r\n");
	_sendf(socket, "Content-Length: %zd\r\n", sbuf.st_size);
	_sendf(socket, "\r\n");
	while((nread = read(fd, buf, 128)) > 0 && _send(socket, buf, nread));
	close(fd);
}

void ptserve_send_str(int socket, const char *body) {
	size_t blen = strlen(body);
	_sendf(socket, "HTTP/1.1 200 OK\r\n");
	_sendf(socket, "Content-Length: %zd\r\n", blen);
	_sendf(socket, "\r\n");
	_send(socket, body, blen);
}

void ptserve_cb_dir(ptserve_message_t *request) {
	char *c, *path = request->path;
	/* strip protocol and location if present */
	if((c = strstr(path, "://")) != NULL) {
		path = c + 3;
		if((c = strchr(path, '/')) != NULL) {
			path = c + 1;
		} else {
			path = "/";
		}
	}
	/* strip leading '/' */
	if(path[0] == '/') { path++; }
	ptserve_send_file(request->socket_fd, request->ptserve->rootfd, path);
}

ptserve_t *ptserve_serve_cbat(int fd, ptserve_response_cb_t *cb, void *data) {
	ptserve_t *ptserve = ptserve_new();
	if(ptserve == NULL) {
		free(ptserve);
		return NULL;
	}
	ptserve->rootfd = fd;
	ptserve->response_cb = cb;
	ptserve->data = data;
	ptserve_serve(ptserve);
	return ptserve;
}

ptserve_t *ptserve_serve_cb(ptserve_response_cb_t *cb, void *data) {
	return ptserve_serve_cbat(AT_FDCWD, cb, data);
}

ptserve_t *ptserve_serve_dirat(int fd, const char *path) {
	ptserve_t *ptserve = ptserve_new();
	int rootfd = openat(fd, path, O_RDONLY | O_DIRECTORY);
	if(ptserve == NULL || (ptserve->rootfd = rootfd) < 0) {
		free(ptserve);
		return NULL;
	}
	ptserve->response_cb = ptserve_cb_dir;
	ptserve_listen(ptserve);
	pthread_create(&ptserve->_tid, NULL, ptserve_serve, ptserve);
	return ptserve;
}

ptserve_t *ptserve_serve_dir(const char *path) {
	return ptserve_serve_dirat(AT_FDCWD, path);
}

/*****************************************************************************
 * tests
 ****************************************************************************/

void ptserve_set_proxy(ptserve_t *ptserve) {
	setenv("http_proxy", ptserve->url, 1);
}
#if 0
int main(int argc, char *argv[]) {
	ptserve_t *ptserve = ptserve_serve_cbat(AT_FDCWD, ptserve_cb_dir, NULL);
	ptserve_listen(ptserve);
	printf("listening on port %d\n", ptserve->port);
	ptserve_serve(ptserve);
	return 0;
}

int main_nocb(int argc, char *argv[]) {
	int fd;
	ptserve_t *ptserve = ptserve_new();
	ptserve_listen(ptserve);
	printf("listening on port %d\n", ptserve->port);
	while((fd = ptserve_accept(ptserve)) >= 0) {
		ptserve_message_t *msg = ptserve_message_new(ptserve, fd);
		ptserve_cb_dir(msg);
		ptserve_message_free(msg);
	}
	ptserve_free(ptserve);
}
#endif

#endif /* PTSERVE_C */

/* vim: set ts=2 sw=2 noet: */
