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
    FILE *body;
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

ssize_t dgetdelim(int fd, char *buf, ssize_t bufsiz, char *delim) {
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

  dgetdelim(socket_fd, line, LINE_MAX, " ");
  msg->method = strdup(line);
  dgetdelim(socket_fd, line, LINE_MAX, " ");
  msg->path = strdup(line);
  dgetdelim(socket_fd, line, LINE_MAX, "\r\n");
  msg->protocol = strdup(line);

  while(dgetdelim(socket_fd, line, LINE_MAX, "\r\n") > 0) {
      msg->headers = alpm_list_add(msg->headers, strdup(line));
  }
  msg->body = fdopen(socket_fd, "r");

  msg->ptserve = server;
  msg->socket_fd = socket_fd;

  return msg;
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

void ptserve_cb_dir(ptserve_message_t *request) {
    
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
    ptserve->rootfd = dup(fd);
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

void ptserve_set_proxy(ptserve_t *ptserve) {
    char addr[100];
    snprintf(addr, 100, "%s://%s:%s", "http", "localhost", ptserve->port);
    setenv("http_proxy", addr, 1);
}

void testcb(ptserve_message_t *msg) {
    alpm_list_t *i;
    dprintf(msg->socket_fd, "%s %d %s\r\n", "HTTP/1.1", 200, "OK");
    write(msg->socket_fd, "\r\n", 2);
    dprintf(msg->socket_fd, "method: %s\n", msg->method);
    dprintf(msg->socket_fd, "path: %s\n", msg->path);
    dprintf(msg->socket_fd, "protocol: %s\n", msg->protocol);
    for(i = msg->headers; i; i = alpm_list_next(i)) {
        dprintf(msg->socket_fd, "%s\n", i->data);
    }
    close(msg->socket_fd);
}

int main(int argc, char *argv[]) {
    ptserve_t *ptserve = ptserve_new_cb(AT_FDCWD, testcb, NULL);
    ptserve_listen(ptserve);

    printf("listening on port %d\n", ptserve->port);

    ptserve_serve(ptserve);
    return 0;
}
