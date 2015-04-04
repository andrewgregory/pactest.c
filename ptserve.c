#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>

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
	void *data;
	int rootfd;
	pid_t _pid;
	int sd_server;
} ptserve_t;

static ssize_t _send(int socket, const void *buf, size_t len) {
	return send(socket, buf, len, MSG_NOSIGNAL);
}

static ssize_t _sendf(int socket, const char *fmt, ...) {
	ssize_t ret;
	char *buf = NULL;
	size_t blen = 0;
	FILE *fbuf = open_memstream(&buf, &blen);
	va_list args;
	va_start(args, fmt);
	vfprintf(fbuf, fmt, args);
	va_end(args);
	fclose(fbuf);
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

ptserve_message_t *ptserve_message_new(ptserve_t *server, int socket_fd) {
	ptserve_message_t *msg = calloc(sizeof(ptserve_message_t), 1);
	char line[LINE_MAX];

	_dgetdelim(socket_fd, line, LINE_MAX, " ");
	msg->method = strdup(line);
	_dgetdelim(socket_fd, line, LINE_MAX, " ");
	msg->path = strdup(line);
	_dgetdelim(socket_fd, line, LINE_MAX, "\r\n");
	msg->protocol = strdup(line);

	while(_dgetdelim(socket_fd, line, LINE_MAX, "\r\n") > 0) {
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

int ptserve_message_set_header(ptserve_message_t *message,
		const char *header, const char *value) {
	alpm_list_t *i;
	size_t hlen = strlen(header);
	char *newheader = malloc(hlen + strlen(": ") + strlen(value) + 1);

	if(newheader == NULL) { return 0; }
	sprintf("%s: %s", header, value);

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

void ptserve_serve_file(int socket, int rootfd, const char *path) {
	struct stat sbuf;
	ssize_t nread;
	char buf[128];
	int fd = openat(rootfd, path, O_RDONLY);
	fstat(fd, &sbuf);
	_sendf(socket, "HTTP/1.1 200 OK\r\n");
	_sendf(socket, "Content-Length: %zd\r\n", sbuf.st_size);
	_sendf(socket, "\r\n");
	printf("finished headers %s %zd\n", path, sbuf.st_size);
	while((nread = read(fd, buf, 128)) > 0 && send(socket, buf, nread, MSG_NOSIGNAL)) {
		printf("wrote: %zd\n", nread);
		fwrite(buf, nread, 1, stdout);
	}
	printf("finished serving %s\n", path);
	close(fd);
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
	printf("serving %s\n", path);
	ptserve_serve_file(request->socket_fd, request->ptserve->rootfd, path);
}

ptserve_t *ptserve_new_dir(int fd, const char *path) {
	ptserve_t *ptserve = calloc(sizeof(ptserve_t), 1);
	int rootfd = openat(fd, path, O_RDONLY | O_DIRECTORY);
	if(ptserve == NULL || (ptserve->rootfd = rootfd) < 0) {
		free(ptserve);
		return NULL;
	}
	ptserve->response_cb = ptserve_cb_dir;
	return ptserve;
}

ptserve_t *ptserve_new_cb(int fd, ptserve_response_cb_t *cb, void *data) {
	ptserve_t *ptserve = calloc(sizeof(ptserve_t), 1);
	if(ptserve == NULL) {
		free(ptserve);
		return NULL;
	}
	ptserve->rootfd = fd;
	ptserve->response_cb = cb;
	ptserve->data = data;
	ptserve->sd_server = -1;
	return ptserve;
}

void ptserve_free(ptserve_t *ptserve) {
	kill(ptserve->_pid, SIGTERM);
	waitpid(ptserve->_pid, NULL, 0);
	free(ptserve);
}

void ptserve_listen(ptserve_t *ptserve) {
	struct sockaddr_in sin;
	socklen_t addrlen = sizeof(sin);

	if(ptserve->sd_server >= 0) { return; }

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(0);

	ptserve->sd_server = socket(PF_INET, SOCK_STREAM, 0);
	bind(ptserve->sd_server, (struct sockaddr*) &sin, sizeof(sin));
	getsockname(ptserve->sd_server, (struct sockaddr*) &sin, &addrlen);
	ptserve->port = ntohs(sin.sin_port);

	listen(ptserve->sd_server, SOMAXCONN);
}

int ptserve_accept(ptserve_t *ptserve) {
	int session_fd = accept(ptserve->sd_server, 0, 0);
	if(session_fd >= 0) {
		ptserve_message_t *msg = ptserve_message_new(ptserve, session_fd);
		ptserve->response_cb(msg);
	}
	return session_fd;
}

void *ptserve_serve(void *ptserve) {
	while(ptserve_accept(ptserve) >= 0);
}

ptserve_t *ptserve_serve_dir(int fd, const char *path) {
	ptserve_t *ptserve = ptserve_new_dir(fd, path);
	ptserve_listen(ptserve);
	return ptserve;
}

char *ptserve_get_url(ptserve_t *ptserve) {
	int len = sprintf(NULL, 0, "http://127.0.0.1:%d", ptserve->port);
	char *buf = malloc(len + 1);
	sprintf(buf, "http://127.0.0.1:%d", ptserve->port);
	return buf;
}

void ptserve_set_proxy(ptserve_t *ptserve) {
	char *url = ptserve_get_url(ptserve);
	setenv("http_proxy", url, 1);
	free(url);
}

void testcb(ptserve_message_t *msg) {
	alpm_list_t *i;
	ptserve_cb_dir(msg);
	puts("closing socket");
	close(msg->socket_fd);
}

int main(int argc, char *argv[]) {
	ptserve_t *ptserve = ptserve_new_cb(AT_FDCWD, testcb, NULL);
	ptserve_listen(ptserve);

	printf("listening on port %d\n", ptserve->port);

	ptserve_serve(ptserve);
	return 0;
}

/* vim: set ts=2 sw=2 noet: */
