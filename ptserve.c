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
	char *url;
	void *data;
	int rootfd;
	pid_t _pid;
	int sd_server;
} ptserve_t;

static int _vasprintf(char **strp, const char *fmt, va_list args) {
	size_t len = vsnprintf(NULL, 0, fmt, args);
	*strp = malloc(len + 1);
	vsprintf(*strp, fmt, args);
}

static int _asprintf(char **strp, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	_vasprintf(strp, fmt, args);
	va_end(args);
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

void ptserve_serve_file(int socket, int rootfd, const char *path) {
	struct stat sbuf;
	ssize_t nread;
	char buf[128];
	int fd = openat(rootfd, path, O_RDONLY);
	fstat(fd, &sbuf);
	_sendf(socket, "HTTP/1.1 200 OK\r\n");
	_sendf(socket, "Content-Length: %zd\r\n", sbuf.st_size);
	_sendf(socket, "\r\n");
	while((nread = read(fd, buf, 128)) > 0 && send(socket, buf, nread, MSG_NOSIGNAL)) {
		fwrite(buf, nread, 1, stdout);
	}
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
	ptserve_serve_file(request->socket_fd, request->ptserve->rootfd, path);
}

ptserve_t *ptserve_new() {
	ptserve_t *ptserve = calloc(sizeof(ptserve_t), 1);
	if(ptserve == NULL) { return NULL; }
	ptserve->rootfd = -1;
	ptserve->sd_server = -1;
	return ptserve;
}

ptserve_t *ptserve_new_dir(int fd, const char *path) {
	ptserve_t *ptserve = ptserve_new();
	int rootfd = openat(fd, path, O_RDONLY | O_DIRECTORY);
	if(ptserve == NULL || (ptserve->rootfd = rootfd) < 0) {
		free(ptserve);
		return NULL;
	}
	ptserve->response_cb = ptserve_cb_dir;
	return ptserve;
}

ptserve_t *ptserve_new_cb(int fd, ptserve_response_cb_t *cb, void *data) {
	ptserve_t *ptserve = ptserve_new();
	if(ptserve == NULL) {
		free(ptserve);
		return NULL;
	}
	ptserve->rootfd = fd;
	ptserve->response_cb = cb;
	ptserve->data = data;
	return ptserve;
}

void ptserve_free(ptserve_t *ptserve) {
	if(ptserve == NULL) { return; }
	kill(ptserve->_pid, SIGTERM);
	waitpid(ptserve->_pid, NULL, 0);
	free(ptserve->url);
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


	_asprintf(&ptserve->url, "http://127.0.0.1:%d", ptserve->port);
}

int ptserve_accept(ptserve_t *ptserve) {
	return accept(ptserve->sd_server, 0, 0);
}

void *ptserve_serve(ptserve_t *ptserve) {
	int session_fd;
	while((session_fd = ptserve_accept(ptserve)) >= 0) {
		ptserve_message_t *msg = ptserve_message_new(ptserve, session_fd);
		ptserve->response_cb(msg);
		ptserve_message_free(msg);
	}
	return NULL;
}

ptserve_t *ptserve_serve_dir(int fd, const char *path) {
	ptserve_t *ptserve = ptserve_new_dir(fd, path);
	ptserve_listen(ptserve);
	ptserve_serve(ptserve);
	return ptserve;
}

void ptserve_set_proxy(ptserve_t *ptserve) {
	setenv("http_proxy", ptserve->url, 1);
}

int main(int argc, char *argv[]) {
	ptserve_t *ptserve = ptserve_new_cb(AT_FDCWD, ptserve_cb_dir, NULL);
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

/* vim: set ts=2 sw=2 noet: */
