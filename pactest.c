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
        if(stat(p, &buf) == 0) { continue; }
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
    if((fd = openat(dd, path, flags, 0700)) == -1) {
        return 0;
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
    pt->dbpath = strdup(dbpath);
    pt->rootfd = open(pt->root, O_DIRECTORY);
    pt->dbfd = openat(pt->rootfd, pt->dbpath, O_DIRECTORY);
    return pt;
}

alpm_handle_t *pt_initialize(pt_env_t *pt, alpm_errno_t *err) {
    pt_mkdirat(pt->rootfd, 0700, pt->dbpath);
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

int pt_cache_pkg(pt_env_t *pt, pt_pkg_t *p) {
    struct archive *a;
    a = archive_write_new();
    alpm_list_t *i;
    return 0;
}

int pt_install_pkg(pt_env_t *pt, pt_pkg_t *pkg) {
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

#endif /* PACTEST_C */
