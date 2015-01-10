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

#ifndef PACTEST_C
#define PACTEST_C

#define PACTEST_C_VERSION 1.0

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/wait.h>

#include <alpm.h>

typedef struct pt_env_t {
    alpm_handle_t *handle;
    alpm_list_t *dbs;
    alpm_list_t *pkgs;
    char *dbpath;
    char *root;
    int dbfd;
    int rootfd;
} pt_env_t;

typedef struct pt_db_t {
    char *name;
    alpm_list_t *pkgs;
} pt_db_t;

typedef struct pt_pkg_file_t {
    char *path;
    char *contents;
} pt_pkg_file_t;

typedef struct pt_pkg_t {
    alpm_list_t *backup;
    alpm_list_t *checkdepends;
    alpm_list_t *conflicts;
    alpm_list_t *depends;
    alpm_list_t *files;
    alpm_list_t *groups;
    alpm_list_t *licenses;
    alpm_list_t *makedepends;
    alpm_list_t *optdepends;
    alpm_list_t *provides;
    alpm_list_t *replaces;
    char *arch;
    char *base;
    char *builddate;
    char *csize;
    char *desc;
    char *filename;
    char *installdate;
    char *isize;
    char *name;
    char *packager;
    char *scriptlet;
    char *version;
} pt_pkg_t;

void pt_rmrfat(int dd, const char *path) {
    if(!unlinkat(dd, path, 0)) {
        return;
    } else {
        struct dirent *de;
        DIR *d;
        int fd;

        switch(errno) {
            case ENOENT:
                return;
            case EPERM:
            case EISDIR:
                break;
            default:
                /* not a directory */
                return;
        }

        fd = openat(dd, path, O_DIRECTORY);
        d = fdopendir(fd);
        if(!d) { return; }
        for(de = readdir(d); de != NULL; de = readdir(d)) {
            if(strcmp(de->d_name, "..") != 0 && strcmp(de->d_name, ".") != 0) {
                char name[PATH_MAX];
                snprintf(name, PATH_MAX, "%s/%s", path, de->d_name);
                pt_rmrfat(dd, name);
            }
        }
        closedir(d);
        unlinkat(dd, path, AT_REMOVEDIR);
    }
}

int pt_mkdirat(int dd, int mode, const char *path) {
    char *dir = strdup(path);
    char p[PATH_MAX] = "";
    char *c;
    int ret = 0;
    if(dir[0] == '/') { strcat(p, "/"); }
    for(c = strtok(dir, "/"); c; c = strtok(NULL, "/")) {
        struct stat buf;
        strcat(p, c);
        strcat(p, "/");
        if(fstatat(dd, p, &buf, 0) == 0) { continue; }
        if((ret = mkdirat(dd, p, mode)) != 0) { break; }
    }
    free(dir);
    return ret;
}

int pt_grepat(int dd, const char *path, const char *needle) {
    int fd;
    char buf[LINE_MAX];
    FILE *f;
    if((fd = openat(dd, path, O_RDONLY)) == -1) { return 0; }
    if((f = fdopen(fd, "r")) == NULL) { return 0; }
    while(fgets(buf, sizeof(buf), f)) {
        if(strstr(buf, needle)) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

int pt_writeat(int dd, const char *path, const char *contents) {
    int fd, flags = O_CREAT | O_WRONLY | O_TRUNC;
    char *c;
    if((c = strrchr(path, '/'))) {
        char *dir = strndup(path, c - path);
        pt_mkdirat(dd, 0700, dir);
        free(dir);
    }
    if((fd = openat(dd, path, flags, 0644)) == -1) {
        return -1;
    }
    write(fd, contents, strlen(contents));
    close(fd);
    return 0;
}

pt_env_t *pt_new(const char *dbpath) {
    pt_env_t *pt;
    char root[] = "/tmp/pactest-XXXXXX";
    if(dbpath == NULL) { dbpath = "var/lib/pacman/"; }
    if(mkdtemp(root) == NULL) { return NULL; }
    if((pt = calloc(sizeof(pt_env_t), 1)) == NULL) { return NULL; }
    pt->root = strdup(root);
    pt->rootfd = open(pt->root, O_DIRECTORY);
    pt->dbpath = strdup(dbpath);
    pt_mkdirat(pt->rootfd, 0700, pt->dbpath);
    pt->dbfd = openat(pt->rootfd, pt->dbpath, O_DIRECTORY);
    pt_writeat(pt->dbfd, "local/ALPM_DB_VERSION", "9");
    return pt;
}

alpm_handle_t *pt_initialize(pt_env_t *pt, alpm_errno_t *err) {
    if(err) { *err = 0; }
    pt->handle = alpm_initialize(pt->root, pt->dbpath, err);
    return pt->handle;
}

int _pt_write_list(struct archive *a, const char *section, alpm_list_t *values) {
    alpm_list_t *i;
    archive_write_data(a, "%", 1);
    archive_write_data(a, section, strlen(section));
    archive_write_data(a, "\n", 2);
    for(i = values; i; i = i->next) {
        const char *buf = i->data;
        archive_write_data(a, buf, strlen(buf));
        archive_write_data(a, "\n", 1);
    }
    archive_write_data(a, "\n", 1);
}

int _pt_write_entry(struct archive *a, const char *section, const char *value) {
    archive_write_data(a, "%", 1);
    archive_write_data(a, section, strlen(section));
    archive_write_data(a, "%\n", 2);
    archive_write_data(a, value, strlen(value));
    archive_write_data(a, "\n", 1);
}

void _pt_path(pt_env_t *pt, char *dest, const char *path) {
    if(path[0] == '/') {
        strcpy(dest, path);
    } else {
        snprintf(dest, PATH_MAX, "%s/%s", pt->root, path);
    }
}

int pt_install_db(pt_env_t *pt, pt_db_t *db) {
    alpm_list_t *i;
    struct archive *a = archive_write_new();
    struct archive_entry *e;
    char dbpath[PATH_MAX];
    int fd;
    
    pt_mkdirat(pt->dbfd, 0700, "sync");
    sprintf(dbpath, "sync/%s.db", db->name);
    fd = openat(pt->dbfd, dbpath, O_CREAT, 0700);

    archive_write_set_format_ustar(a);
    archive_write_open_fd(a, fd);
    for(i = db->pkgs; i; i = i->next) {
        pt_pkg_t *pkg = i->data;
        char fpath[PATH_MAX];

        sprintf(fpath, "%s-%s/depends", pkg->name, pkg->version);
        e = archive_entry_new();
        archive_entry_set_pathname(e, fpath);
        archive_write_header(a, e);
        _pt_write_list(a, "DEPENDS", pkg->depends);
        _pt_write_list(a, "CONFLICTS", pkg->conflicts);
        _pt_write_list(a, "PROVIDES", pkg->provides);
        _pt_write_list(a, "OPTDEPENDS", pkg->optdepends);
        _pt_write_list(a, "MAKEDEPENDS", pkg->makedepends);
        _pt_write_list(a, "CHECKDEPENDS", pkg->checkdepends);
        archive_entry_free(e);

        sprintf(fpath, "%s-%s/desc", pkg->name, pkg->version);
        e = archive_entry_new();
        archive_entry_set_pathname(e, fpath);
        archive_write_header(a, e);
        _pt_write_entry(a, "FILENAME", pkg->filename);
        _pt_write_entry(a, "NAME", pkg->name);
        _pt_write_entry(a, "BASE", pkg->base);
        _pt_write_entry(a, "VERSION", pkg->version);
        _pt_write_entry(a, "DESC", pkg->desc);
        _pt_write_list(a, "GROUPS", pkg->groups);
        _pt_write_entry(a, "CSIZE", pkg->csize);
        _pt_write_entry(a, "ISIZE", pkg->isize);
        archive_entry_free(e);
    }
    archive_write_free(a);
    close(fd);
    return 0;
}

void pt_pkg_add_file(pt_pkg_t *pkg, const char *path, const char *contents) {
    pt_pkg_file_t *f = malloc(sizeof(pt_pkg_file_t));
    f->path = strdup(path);
    f->contents = strdup(contents);
    pkg->files = alpm_list_add(pkg->files, f);
}

int _pt_dwrite_entry(int fd, const char *section, const char *value) {
    if(value == NULL) { return 0; }
    return dprintf(fd, "%%%s%%\n%s\n\n", section, value);
}

void _pt_dwrite_list(int fd, const char *section, alpm_list_t *values) {
    dprintf(fd, "%%%s%%\n", section);
    while(values) {
        dprintf(fd, "%s\n", (char *) values->data);
        values = values->next;
    }
    write(fd, "\n", 1);
}

int pt_add_pkg_to_localdb(pt_env_t *pt, pt_pkg_t *pkg) {
    alpm_list_t *i;
    char path[PATH_MAX] = "";
    int fd;

    snprintf(path, PATH_MAX, "local/%s-%s", pkg->name, pkg->version);
    pt_mkdirat(pt->dbfd, 0700, path);

    /* TODO: write mtree file */

    snprintf(path, PATH_MAX, "local/%s-%s/files", pkg->name, pkg->version);
    fd = openat(pt->dbfd, path, O_CREAT | O_WRONLY, 0644);
    dprintf(fd, "%%%s%%\n", "FILES");
    for(i = pkg->files; i; i = i->next) {
        /* TODO: fill in parent directories? */
        pt_pkg_file_t *f = i->data;
        dprintf(fd, "%s\n", f->path);
    }
    write(fd, "\n", 1);
    dprintf(fd, "%%%s%%\n", "BACKUP");
    for(i = pkg->backup; i; i = i->next) {
        pt_pkg_file_t *f = i->data;
        dprintf(fd, "%s\n", f->path);
    }
    write(fd, "\n", 1);
    close(fd);

    snprintf(path, PATH_MAX, "local/%s-%s/desc", pkg->name, pkg->version);
    fd = openat(pt->dbfd, path, O_CREAT | O_WRONLY, 0644);
    _pt_dwrite_entry(fd, "FILENAME", pkg->filename);
    _pt_dwrite_entry(fd, "NAME", pkg->name);
    _pt_dwrite_entry(fd, "BASE", pkg->base);
    _pt_dwrite_entry(fd, "VERSION", pkg->version);
    _pt_dwrite_entry(fd, "DESC", pkg->desc);
    _pt_dwrite_entry(fd, "CSIZE", pkg->csize);
    _pt_dwrite_entry(fd, "ISIZE", pkg->isize);
    _pt_dwrite_list(fd, "GROUPS", pkg->groups);
    _pt_dwrite_list(fd, "DEPENDS", pkg->depends);
    _pt_dwrite_list(fd, "CONFLICTS", pkg->conflicts);
    _pt_dwrite_list(fd, "PROVIDES", pkg->provides);
    _pt_dwrite_list(fd, "OPTDEPENDS", pkg->optdepends);
    _pt_dwrite_list(fd, "MAKEDEPENDS", pkg->makedepends);
    _pt_dwrite_list(fd, "CHECKDEPENDS", pkg->checkdepends);
    close(fd);

    return 0;
}

int pt_install_pkg(pt_env_t *pt, pt_pkg_t *pkg) {
    alpm_list_t *i;
    pt_add_pkg_to_localdb(pt, pkg);
    for(i = pkg->files; i; i = i->next) {
        pt_pkg_file_t *f = i->data;
        pt_writeat(pt->rootfd, f->path, f->contents);
    }
    return 0;
}

void _pt_db_free(pt_db_t *db) {
    if(db != NULL) {
        alpm_list_free(db->pkgs);
        free(db->name);
        free(db);
    }
}

void _pt_pkg_free(pt_pkg_t *pkg) {
    if(pkg != NULL) {
        free(pkg->name);
        free(pkg);
    }
}

void pt_cleanup(pt_env_t *pt) {
    if(pt != NULL) { 
        close(pt->rootfd);
        pt_rmrfat(AT_FDCWD, pt->root);
        free(pt->root);
        free(pt->dbpath);
        alpm_release(pt->handle);
        alpm_list_free_inner(pt->dbs, (alpm_list_fn_free)_pt_db_free);
        alpm_list_free_inner(pt->pkgs, (alpm_list_fn_free)_pt_pkg_free);
        alpm_list_free(pt->dbs);
        alpm_list_free(pt->pkgs);
        free(pt);
    }
}

pt_db_t *pt_db_new(pt_env_t *pt, const char *dbname) {
    pt_db_t *db = calloc(sizeof(pt_db_t), 1);
    db->name = strdup(dbname);
    pt->dbs = alpm_list_add(pt->dbs, db);
    return db;
}

pt_pkg_t *pt_pkg_new(pt_env_t *pt, const char *pkgname, const char *pkgver) {
    pt_pkg_t *pkg = calloc(sizeof(pt_pkg_t), 1);
    pkg->name = strdup(pkgname);
    pkg->version = strdup(pkgname);
    pt->pkgs = alpm_list_add(pt->pkgs, pkg);
    return pkg;
}

int pt_fexecve(int fd, char *const argv[], char *const envp[],
        int cwd, FILE *out, FILE *err) {
    int opipe[2], epipe[2];
    pid_t pid;
    if( pipe(opipe) || pipe(epipe) ) { return -1; }

#define _PT_CLOSE(fd) while(close(fd) == -1 && errno == EINTR)
#define _PT_DUP(oldfd, newfd) while(dup2(oldfd, newfd) == -1 && errno == EINTR)

    if((pid = fork()) == -1) {
        return -1;
    } else if(pid == 0) {
        /* child */
        _PT_DUP(opipe[1], STDOUT_FILENO);
        _PT_DUP(epipe[1], STDERR_FILENO);
        _PT_CLOSE(opipe[0]);
        _PT_CLOSE(opipe[1]);
        _PT_CLOSE(epipe[0]);
        _PT_CLOSE(epipe[1]);

        if(cwd >= 0 && fchdir(cwd) != 0) { return 0; }

        fexecve(fd, argv, envp);

        return -1;
    } else {
        /* parent */
        int status, nfds = (opipe[0] > epipe[0] ? opipe[0] : epipe[0]) + 1;
        fd_set readfds;
        _PT_CLOSE(opipe[1]);
        _PT_CLOSE(epipe[1]);

        FD_ZERO(&readfds);
        FD_SET(opipe[0], &readfds);
        FD_SET(epipe[0], &readfds);

        while(select(nfds, &readfds, NULL, NULL, NULL) > 0) {
            size_t r;
            char buf[LINE_MAX];

            if(FD_ISSET(opipe[0], &readfds)) {
                r = read(opipe[0], buf, LINE_MAX - 1);
                if(out) { buf[r] = '\0'; fputs(buf, out); };
            }
            if(FD_ISSET(epipe[0], &readfds)) {
                r = read(epipe[0], buf, LINE_MAX - 1);
                if(out) { buf[r] = '\0'; fputs(buf, err); };
            }

            FD_SET(opipe[0], &readfds);
            FD_SET(epipe[0], &readfds);

            if(waitpid(pid, &status, WNOHANG) != 0) {
                /* slurp any remaining input and break */
                if(out) {
                    while((r = read(opipe[0], buf, LINE_MAX - 1)) > 0) {
                        buf[r] = '\0';
                        fputs(buf, out);
                    }
                }
                if(err) {
                    while((r = read(epipe[0], buf, LINE_MAX - 1)) > 0) {
                        buf[r] = '\0';
                        fputs(buf, err);
                    }
                }
                break;
            }
        }

        _PT_CLOSE(opipe[0]);
        _PT_CLOSE(epipe[0]);

        return WEXITSTATUS(status);
    }

#undef _PT_CLOSE
#undef _PT_DUP
}

#endif /* PACTEST_C */
