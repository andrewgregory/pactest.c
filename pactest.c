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

#define PACTEST_C_VERSION "0.1"

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

enum pt_ftype {
    PT_FTYPE_FILE,
    PT_FTYPE_SYMLINK,
    PT_FTYPE_DIRECTORY
};

typedef struct pt_pkg_file_t {
    enum pt_ftype type;
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
    char *url;
    char *version;
} pt_pkg_t;

void _pt_pkg_file_free(pt_pkg_file_t *f) {
    if(f == NULL) { return; }
    free(f->path);
    free(f->contents);
    free(f);
}

void _pt_db_free(pt_db_t *db) {
    if(db == NULL) { return; }
    alpm_list_free(db->pkgs);
    free(db->name);
    free(db);
}

void _pt_pkg_free(pt_pkg_t *pkg) {
    if(pkg == NULL) { return; }
    alpm_list_free_inner(pkg->files, (alpm_list_fn_free) _pt_pkg_file_free);
    alpm_list_free(pkg->files);
    FREELIST(pkg->backup);
    FREELIST(pkg->checkdepends);
    FREELIST(pkg->conflicts);
    FREELIST(pkg->depends);
    FREELIST(pkg->groups);
    FREELIST(pkg->licenses);
    FREELIST(pkg->makedepends);
    FREELIST(pkg->optdepends);
    FREELIST(pkg->provides);
    FREELIST(pkg->replaces);
    free(pkg->arch);
    free(pkg->base);
    free(pkg->builddate);
    free(pkg->csize);
    free(pkg->desc);
    free(pkg->filename);
    free(pkg->installdate);
    free(pkg->isize);
    free(pkg->name);
    free(pkg->packager);
    free(pkg->scriptlet);
    free(pkg->version);
    free(pkg);
}

/******************************************
 * file system utilities
 ******************************************/

static char *pt_vasprintf(const char *fmt, va_list args) {
    va_list arg_cp;
    size_t len;
    char *ret;
    va_copy(arg_cp, args);
    len = vsnprintf(NULL, 0, fmt, arg_cp);
    va_end(arg_cp);
    if((ret = malloc(len + 2)) != NULL) { vsprintf(ret, fmt, args); }
    return ret;
}

static char *pt_asprintf(const char *fmt, ...) {
    va_list args;
    char *ret;
    va_start(args, fmt);
    ret = pt_vasprintf(fmt, args);
    va_end(args);
    return ret;
}

char *pt_apath(pt_env_t *pt, const char *path) {
    return *path == '/' ? strdup(path) : pt_asprintf("%s/%s", pt->root, path);
}

char *pt_path(pt_env_t *pt, const char *path) {
    static char fullpath[PATH_MAX];
    if(path[0] == '/') {
        strcpy(fullpath, path);
    } else {
        snprintf(fullpath, PATH_MAX, "%s/%s", pt->root, path);
    }
    return fullpath;
}

int pt_rmrfat(int dd, const char *path) {
    if(!unlinkat(dd, path, 0)) {
        return 0;
    } else {
        struct dirent *de;
        DIR *d;
        int fd;

        switch(errno) {
            case ENOENT:
                return 0;
            case EPERM:
            case EISDIR:
                break;
            default:
                /* not a directory */
                return 0;
        }

        fd = openat(dd, path, O_DIRECTORY);
        d = fdopendir(fd);
        if(!d) { return 0; }
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
    return 0;
}

/* TODO: cleanup pt_mkdirat */
int pt_mkdirat(int dd, int mode, const char *path) {
    char dir[PATH_MAX], *c = dir;
    size_t plen = strlen(path);
    if(plen > PATH_MAX) { errno = ENAMETOOLONG; return -1; }
    strcpy(dir, path);
    while(dir[plen - 1] == '/') { dir[--plen] = '\0'; }
    while((c = strchr(c + 1, '/'))) {
        *c = '\0';
        if(mkdirat(dd, dir, mode) != 0 && errno != EEXIST) { return -1; }
        *c = '/';
    }
    if(mkdirat(dd, path, mode) != 0 && errno != EEXIST) { return -1; }
    return 0;
}

int pt_mkpdirat(int dd, int mode, const char *path) {
    char *c;
    if((c = strrchr(path, '/'))) {
        char dir[PATH_MAX] = "";
        if(c - path + 1 > PATH_MAX) { errno = ENAMETOOLONG; return -1; }
        strncat(dir, path, c - path + 1);
        return pt_mkdirat(dd, mode, dir);
    }
    return 0;
}

int pt_symlinkat(int dd, const char *path, const char *target) {
    pt_mkpdirat(dd, 0700, path);
    return symlinkat(target, dd, path);
}

int pt_writeat(int dd, const char *path, const char *contents) {
    int fd, flags = O_CREAT | O_WRONLY | O_TRUNC;
    ssize_t ret;
    if(pt_mkpdirat(dd, 0700, path) != 0) { return 0; }
    if((fd = openat(dd, path, flags, 0644)) == -1) { return 0; }
    ret = write(fd, contents, strlen(contents));
    close(fd);
    return ret == strlen(contents);
}

FILE *pt_fopenat(int dirfd, const char *path, const char *mode) {
    int fd, flags = 0, rwflag = 0;
    FILE *stream;
    switch(*(mode++)) {
        case 'r': rwflag = O_RDONLY; break;
        case 'w': rwflag = O_WRONLY; flags |= O_CREAT | O_TRUNC; break;
        case 'a': rwflag = O_WRONLY; flags |= O_CREAT | O_APPEND; break;
        default: errno = EINVAL; return NULL;
    }
    if(mode[1] == 'b') { mode++; }
    if(mode[1] == '+') { mode++; rwflag = O_RDWR; }
    while(*mode) {
        switch(*(mode++)) {
            case 'e': flags |= O_CLOEXEC; break;
            case 'x': flags |= O_EXCL; break;
        }
    }
    if((fd = openat(dirfd, path, flags | rwflag, 0666)) < 0) { return NULL; }
    if((stream = fdopen(fd, mode)) == NULL) { close(fd); return NULL; }
    return stream;
}

/******************************************
 * environment creation
 ******************************************/

void pt_cleanup(pt_env_t *pt) {
    if(pt == NULL) { return; }
    close(pt->rootfd);
    if(!getenv("PT_KEEP_ROOT")) { pt_rmrfat(AT_FDCWD, pt->root); }
    else { fprintf(stderr, "root: %s\n", pt->root); }
    free(pt->root);
    free(pt->dbpath);
    alpm_release(pt->handle);
    alpm_list_free_inner(pt->dbs, (alpm_list_fn_free)_pt_db_free);
    alpm_list_free_inner(pt->pkgs, (alpm_list_fn_free)_pt_pkg_free);
    alpm_list_free(pt->dbs);
    alpm_list_free(pt->pkgs);
    free(pt);
}

static int _pt_mktmproot(pt_env_t *pt, const char *path) {
    char *root = strdup(path);
    if(root == NULL) { return -1; }
    if(mkdtemp(root) == NULL) { free(root); return -1; }
    free(pt->root);
    pt->root = root;
    return 0;
}

pt_env_t *pt_new(const char *dbpath) {
    pt_env_t *pt = NULL;
    if(dbpath == NULL) { dbpath = "var/lib/pacman"; }
#define _PT_ASSERT(x) if(!(x)) { pt_cleanup(pt); return NULL; }
    _PT_ASSERT(pt = calloc(sizeof(pt_env_t), 1));
    _PT_ASSERT(_pt_mktmproot(pt, "/tmp/pactest-XXXXXX") == 0);
    _PT_ASSERT((pt->rootfd = open(pt->root, O_DIRECTORY)) >= 0);
    _PT_ASSERT(pt->dbpath = pt_apath(pt, dbpath));
    _PT_ASSERT(pt_mkdirat(pt->rootfd, 0777, pt->dbpath) == 0);
    _PT_ASSERT((pt->dbfd = openat(pt->rootfd, pt->dbpath, O_DIRECTORY)) >= 0);
    _PT_ASSERT(pt_writeat(pt->dbfd, "local/ALPM_DB_VERSION", "9") > 0);
#undef _PT_ASSERT
    return pt;
}

void pt_log_cb(alpm_loglevel_t level, const char *fmt, va_list args) {
    switch(level) {
        case ALPM_LOG_DEBUG: fputs("alpm (debug): ", stderr); break;
        case ALPM_LOG_ERROR: fputs("alpm (error): ", stderr); break;
        case ALPM_LOG_FUNCTION: fputs("alpm (function): ", stderr); break;
        case ALPM_LOG_WARNING: fputs("alpm (warning): ", stderr); break;
    }
    vfprintf(stderr, fmt, args);
}

alpm_handle_t *pt_initialize(pt_env_t *pt, alpm_errno_t *err) {
    if(err) { *err = 0; }
    if((pt->handle = alpm_initialize(pt->root, pt->dbpath, err)) == NULL) { return NULL; }
    alpm_option_add_cachedir(pt->handle, pt_path(pt, "var/cache/pacman/pkg"));
    if(getenv("PT_DEBUG")) { alpm_option_set_logcb(pt->handle, pt_log_cb); }
    return pt->handle;
}

void _pt_fwrite_pkgentry(FILE *f, const char *section, const char *value) {
    if(value) { fprintf(f, "%s = %s\n", section, value); }
}

void _pt_fwrite_pkglist(FILE *f, const char *section, alpm_list_t *values) {
    while(values) {
        _pt_fwrite_pkgentry(f, section, values->data);
        values = values->next;
    }
}

int _pt_pkg_write_archive(pt_pkg_t *pkg, struct archive *a) {
    alpm_list_t *i;
    FILE *contents;
    struct archive_entry *e;
    char *buf;
    size_t buflen;

    contents = open_memstream(&buf, &buflen);
    _pt_fwrite_pkgentry(contents, "pkgname", pkg->name);
    _pt_fwrite_pkgentry(contents, "pkgver", pkg->version);
    _pt_fwrite_pkgentry(contents, "pkgdesc", pkg->desc);
    _pt_fwrite_pkgentry(contents, "url", pkg->url);
    _pt_fwrite_pkgentry(contents, "builddate", pkg->builddate);
    _pt_fwrite_pkgentry(contents, "packager", pkg->packager);
    _pt_fwrite_pkgentry(contents, "arch", pkg->arch);
    _pt_fwrite_pkgentry(contents, "size", pkg->isize);
    _pt_fwrite_pkglist(contents, "group", pkg->groups);
    _pt_fwrite_pkglist(contents, "license", pkg->licenses);
    _pt_fwrite_pkglist(contents, "depend", pkg->depends);
    _pt_fwrite_pkglist(contents, "optdepend", pkg->optdepends);
    _pt_fwrite_pkglist(contents, "conflict", pkg->conflicts);
    _pt_fwrite_pkglist(contents, "replaces", pkg->replaces);
    _pt_fwrite_pkglist(contents, "provides", pkg->provides);
    _pt_fwrite_pkglist(contents, "backup", pkg->backup);
    /* _pt_fwrite_pkgentry(f, "pkgbase", pkg->pkgbase); */
    /* _pt_fwrite_pkgentry(f, "basever", pkg->basever); */
    /* _pt_fwrite_pkgentry(f, "makedepend", pkg->makedepends); */
    /* _pt_fwrite_pkgentry(f, "checkdepend", pkg->checkdepends); */
    /* _pt_fwrite_pkgentry(f, "makepkgopt", pkg->makepkgopts); */
    fclose(contents);

    e = archive_entry_new();
    archive_entry_set_pathname(e, ".PKGINFO");
    archive_entry_set_perm(e, 0644);
    archive_entry_set_filetype(e, AE_IFREG);
    archive_entry_set_size(e, buflen);
    archive_write_header(a, e);
    archive_write_data(a, buf, buflen);
    free(buf);

    for(i = pkg->files; i; i = i->next) {
        pt_pkg_file_t *f = i->data;
        size_t len = f->contents ? strlen(f->contents) : 0;
        archive_entry_clear(e);
        archive_entry_set_pathname(e, f->path);
        switch(f->type) {
            case PT_FTYPE_FILE:
                archive_entry_set_filetype(e, AE_IFREG);
                archive_entry_set_perm(e, 0644);
                break;
            case PT_FTYPE_SYMLINK:
                archive_entry_set_filetype(e, AE_IFLNK);
                archive_entry_set_perm(e, 0644);
                break;
            case PT_FTYPE_DIRECTORY:
                archive_entry_set_filetype(e, AE_IFDIR);
                archive_entry_set_perm(e, 0755);
                break;
        }
        archive_entry_set_size(e, len);
        archive_write_header(a, e);
        archive_write_data(a, f->contents, len);
    }

    archive_entry_free(e);
    return 1;
}

int pt_pkg_writeat(int dd, const char *path, pt_pkg_t *pkg) {
    struct archive *a = archive_write_new();
    char *c;
    int fd;
    struct stat sbuf;

    pt_mkpdirat(dd, 0700, path);
    fd = openat(dd, path, O_CREAT | O_WRONLY, 0644);

    if((c = strrchr(pkg->filename, '.'))) {
        if(strcmp(c, ".bz2") == 0) {
            archive_write_add_filter_bzip2(a);
        } else if(strcmp(c, ".gz") == 0) {
            archive_write_add_filter_gzip(a);
        } else if(strcmp(c, ".xz") == 0) {
            archive_write_add_filter_xz(a);
        } else if(strcmp(c, ".lz") == 0) {
            archive_write_add_filter_lzip(a);
        } else if(strcmp(c, ".Z") == 0) {
            archive_write_add_filter_compress(a);
        }
    }

    archive_write_set_format_ustar(a);
    archive_write_open_fd(a, fd);
    _pt_pkg_write_archive(pkg, a);
    archive_write_free(a);
    if(pkg->csize == NULL && fstat(fd, &sbuf) == 0) {
        pkg->csize = pt_asprintf("%zd", sbuf.st_size);
    }
    close(fd);
    return 0;
}

int pt_db_add_pkg(pt_db_t *db, pt_pkg_t *pkg) {
    db->pkgs = alpm_list_add(db->pkgs, pkg);
    return 1;
}

int _pt_fwrite_dbheader(FILE *f, const char *header) {
    return fprintf(f, "%%" "%s" "%%" "\n", header);
}

void _pt_fwrite_dbentry(FILE *f, const char *section, const char *value) {
    if(value == NULL) { return; }
    _pt_fwrite_dbheader(f, section);
    fprintf(f, "%s\n\n", value);
}

void _pt_fwrite_dblist(FILE *f, const char *section, alpm_list_t *values) {
    _pt_fwrite_dbheader(f, section);
    while(values) {
        fprintf(f, "%s\n", (char *) values->data);
        values = values->next;
    }
    fputc('\n', f);
}

int pt_db_writeat(int dd, const char *path, pt_db_t *db) {
    alpm_list_t *i;
    struct archive *a = archive_write_new();
    struct archive_entry *e = archive_entry_new();
    int fd = openat(dd, path, O_CREAT | O_WRONLY, 0644);

    archive_write_set_format_ustar(a);
    archive_write_open_fd(a, fd);
    for(i = db->pkgs; i; i = i->next) {
        pt_pkg_t *pkg = i->data;
        size_t buflen = 0;
        char *buf, ppath[PATH_MAX];
        FILE *f;

        sprintf(ppath, "%s-%s/", pkg->name, pkg->version);
        archive_entry_clear(e);
        archive_entry_set_pathname(e, ppath);
        archive_entry_set_filetype(e, AE_IFDIR);
        archive_entry_set_perm(e, 0755);
        archive_write_header(a, e);

        f = open_memstream(&buf, &buflen);
        _pt_fwrite_dblist(f, "DEPENDS", pkg->depends);
        _pt_fwrite_dblist(f, "CONFLICTS", pkg->conflicts);
        _pt_fwrite_dblist(f, "PROVIDES", pkg->provides);
        _pt_fwrite_dblist(f, "OPTDEPENDS", pkg->optdepends);
        _pt_fwrite_dblist(f, "MAKEDEPENDS", pkg->makedepends);
        _pt_fwrite_dblist(f, "CHECKDEPENDS", pkg->checkdepends);
        fclose(f);

        sprintf(ppath, "%s-%s/depends", pkg->name, pkg->version);
        archive_entry_clear(e);
        archive_entry_set_pathname(e, ppath);
        archive_entry_set_filetype(e, AE_IFREG);
        archive_entry_set_perm(e, 0644);
        archive_entry_set_size(e, buflen);
        archive_write_header(a, e);
        archive_write_data(a, buf, buflen);
        free(buf);

        f = open_memstream(&buf, &buflen);
        _pt_fwrite_dbentry(f, "FILENAME", pkg->filename);
        _pt_fwrite_dbentry(f, "NAME", pkg->name);
        _pt_fwrite_dbentry(f, "ARCH", pkg->arch);
        _pt_fwrite_dbentry(f, "BASE", pkg->base);
        _pt_fwrite_dbentry(f, "VERSION", pkg->version);
        _pt_fwrite_dbentry(f, "DESC", pkg->desc);
        _pt_fwrite_dbentry(f, "CSIZE", pkg->csize);
        _pt_fwrite_dbentry(f, "ISIZE", pkg->isize);
        _pt_fwrite_dblist(f, "GROUPS", pkg->groups);
        fclose(f);

        sprintf(ppath, "%s-%s/desc", pkg->name, pkg->version);
        archive_entry_clear(e);
        archive_entry_set_pathname(e, ppath);
        archive_entry_set_filetype(e, AE_IFREG);
        archive_entry_set_perm(e, 0644);
        archive_entry_set_size(e, buflen);
        archive_write_header(a, e);
        archive_write_data(a, buf, buflen);
        free(buf);
    }

    archive_entry_free(e);
    archive_write_free(a);
    close(fd);
    return 0;
}

int pt_install_db(pt_env_t *pt, pt_db_t *db) {
    char path[PATH_MAX];
    pt_mkdirat(pt->dbfd, 0755, "sync");
    sprintf(path, "sync/%s.db", db->name);
    return pt_db_writeat(pt->dbfd, path, db);
}

int pt_add_pkg_to_localdb(pt_env_t *pt, pt_pkg_t *pkg) {
    alpm_list_t *i;
    char path[PATH_MAX] = "";
    int fd;
    FILE *f;

    snprintf(path, PATH_MAX, "local/%s-%s", pkg->name, pkg->version);
    pt_mkdirat(pt->dbfd, 0700, path);

    /* TODO: write mtree file */

    snprintf(path, PATH_MAX, "local/%s-%s/files", pkg->name, pkg->version);
    fd = openat(pt->dbfd, path, O_CREAT | O_WRONLY, 0644);
    f = fdopen(fd, "w");
    _pt_fwrite_dbheader(f, "FILES");
    for(i = pkg->files; i; i = i->next) {
        /* TODO: fill in parent directories? */
        pt_pkg_file_t *file = i->data;
        fprintf(f, "%s\n", file->path);
    }
    fputc('\n', f);

    _pt_fwrite_dbheader(f, "BACKUP");
    for(i = pkg->backup; i; i = i->next) {
        pt_pkg_file_t *file = i->data;
        fprintf(f, "%s\n", file->path);
    }
    fputc('\n', f);
    fclose(f);

    snprintf(path, PATH_MAX, "local/%s-%s/desc", pkg->name, pkg->version);
    fd = openat(pt->dbfd, path, O_CREAT | O_WRONLY, 0644);
    f = fdopen(fd, "w");
    _pt_fwrite_dbentry(f, "FILENAME", pkg->filename);
    _pt_fwrite_dbentry(f, "NAME", pkg->name);
    _pt_fwrite_dbentry(f, "BASE", pkg->base);
    _pt_fwrite_dbentry(f, "VERSION", pkg->version);
    _pt_fwrite_dbentry(f, "DESC", pkg->desc);
    _pt_fwrite_dbentry(f, "CSIZE", pkg->csize);
    _pt_fwrite_dbentry(f, "ISIZE", pkg->isize);
    _pt_fwrite_dblist(f, "GROUPS", pkg->groups);
    _pt_fwrite_dblist(f, "DEPENDS", pkg->depends);
    _pt_fwrite_dblist(f, "CONFLICTS", pkg->conflicts);
    _pt_fwrite_dblist(f, "PROVIDES", pkg->provides);
    _pt_fwrite_dblist(f, "OPTDEPENDS", pkg->optdepends);
    _pt_fwrite_dblist(f, "MAKEDEPENDS", pkg->makedepends);
    _pt_fwrite_dblist(f, "CHECKDEPENDS", pkg->checkdepends);
    fclose(f);

    if(pkg->scriptlet) {
        snprintf(path, PATH_MAX, "local/%s-%s/install", pkg->name, pkg->version);
        fd = openat(pt->dbfd, path, O_CREAT | O_WRONLY, 0644);
        write(fd, pkg->scriptlet, strlen(pkg->scriptlet));
    }

    return 0;
}

pt_pkg_file_t *pt_pkg_add_file(pt_pkg_t *pkg, const char *path, const char *contents) {
    pt_pkg_file_t *f;
    if((f = calloc(sizeof(pt_pkg_file_t), 1)) == NULL) { return NULL; }
    if((f->path = strdup(path)) == NULL) { _pt_pkg_file_free(f); return NULL; }
    if((f->contents = strdup(contents)) == NULL) { _pt_pkg_file_free(f); return NULL; }
    pkg->files = alpm_list_add(pkg->files, f);
    return f;
}

pt_pkg_file_t *pt_pkg_add_symlink(pt_pkg_t *pkg, const char *path, const char *dest) {
    pt_pkg_file_t *f;
    if((f = calloc(sizeof(pt_pkg_file_t), 1)) == NULL) { return NULL; }
    if((f->path = strdup(path)) == NULL) { _pt_pkg_file_free(f); return NULL; }
    if((f->contents = strdup(dest)) == NULL) { _pt_pkg_file_free(f); return NULL; }
    f->type = PT_FTYPE_SYMLINK;
    pkg->files = alpm_list_add(pkg->files, f);
    return f;
}

pt_pkg_file_t *pt_pkg_add_dir(pt_pkg_t *pkg, const char *path) {
    pt_pkg_file_t *f;
    if((f = calloc(sizeof(pt_pkg_file_t), 1)) == NULL) { return NULL; }
    if((f->path = strdup(path)) == NULL) { _pt_pkg_file_free(f); return NULL; }
    f->type = PT_FTYPE_DIRECTORY;
    pkg->files = alpm_list_add(pkg->files, f);
    return f;
}

int pt_install_pkg(pt_env_t *pt, pt_pkg_t *pkg) {
    alpm_list_t *i;
    pt_add_pkg_to_localdb(pt, pkg);
    for(i = pkg->files; i; i = i->next) {
        pt_pkg_file_t *f = i->data;
        switch(f->type) {
            case PT_FTYPE_FILE:
                pt_writeat(pt->rootfd, f->path, f->contents);
                break;
            case PT_FTYPE_SYMLINK:
                pt_symlinkat(pt->rootfd, f->path, f->contents);
                break;
            case PT_FTYPE_DIRECTORY:
                pt_mkdirat(pt->rootfd, 0755, f->path);
                break;
        }
    }
    return 0;
}

pt_db_t *pt_db_new(pt_env_t *pt, const char *dbname) {
    pt_db_t *db = NULL;
#define _PT_ASSERT(x) if(!(x)) { _pt_db_free(db); return NULL; }
    _PT_ASSERT(db = calloc(sizeof(pt_db_t), 1));
    _PT_ASSERT(db->name = strdup(dbname));
    _PT_ASSERT(pt->dbs = alpm_list_add(pt->dbs, db));
#undef _PT_ASSERT
    return db;
}

pt_pkg_t *pt_pkg_new(pt_env_t *pt, const char *pkgname, const char *pkgver) {
    pt_pkg_t *pkg = NULL;
#define _PT_ASSERT(x) if(!(x)) { _pt_pkg_free(pkg); return NULL; }
    _PT_ASSERT(pkg = calloc(sizeof(pt_pkg_t), 1));
    _PT_ASSERT(pkg->name = strdup(pkgname));
    _PT_ASSERT(pkg->version = strdup(pkgver));
    _PT_ASSERT(pkg->arch = strdup("any"));
    _PT_ASSERT(pkg->filename = pt_asprintf("%s-%s.pkg.tar", pkgname, pkgver));
    _PT_ASSERT(pt->pkgs = alpm_list_add(pt->pkgs, pkg));
#undef _PT_ASSERT
    return pkg;
}

void pt_sarray_cat(const char **sarray, ...) {
    size_t idx = 0;
    va_list ap;
    va_start(ap, sarray);
    while(sarray[idx] != NULL) { idx++; }
    while((sarray[idx++] = va_arg(ap, const char *)) != NULL);
    va_end(ap);
}

void pt_sarray_cpy(const char **sarray, size_t idx, ...) {
    va_list ap;
    va_start(ap, idx);
    while((sarray[idx++] = va_arg(ap, const char *)) != NULL);
    va_end(ap);
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
                if(out && r > 0 && fwrite(buf, 1, r, out) < r) { out = NULL; };
            }
            if(FD_ISSET(epipe[0], &readfds)) {
                r = read(epipe[0], buf, LINE_MAX - 1);
                if(err && r > 0 && fwrite(buf, 1, r, err) < r) { err = NULL; };
            }

            FD_SET(opipe[0], &readfds);
            FD_SET(epipe[0], &readfds);

            if(waitpid(pid, &status, WNOHANG) != 0) {
                /* slurp any remaining input and break */
                while(out && (r = read(epipe[0], buf, LINE_MAX)) > 0) {
                    if(fwrite(buf, 1, r, out) == 0) { out = NULL; }
                }
                while(err && (r = read(epipe[0], buf, LINE_MAX)) > 0) {
                    if(fwrite(buf, 1, r, err) == 0) { err = NULL; }
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

/*****************************************
 * ALPM helpers
 *****************************************/

int pt_alpm_set_cachedir(alpm_handle_t *h, const char *path) {
    alpm_list_t *l = alpm_list_add(NULL, (void*) path);
    int ret = l != NULL && alpm_option_set_cachedirs(h, l) == 0 ? 0 : -1;
    alpm_list_free(l);
    return ret;
}

alpm_db_t *pt_alpm_get_db(alpm_handle_t *h, const char *dbname) {
    alpm_list_t *i;
    for(i = alpm_get_syncdbs(h); i; i = i->next) {
        if(strcmp(alpm_db_get_name(i->data), dbname) == 0) { return i->data; }
    }
    return NULL;
}

alpm_pkg_t *pt_alpm_get_pkg(alpm_handle_t *h, const char *pkgname) {
    char *c = strchr(pkgname, '/');
    if(c && strncmp(pkgname, "local", c - pkgname) == 0) {
        alpm_db_t *db = alpm_get_localdb(h);
        return alpm_db_get_pkg(db, c + 1);
    } else if(c) {
        alpm_list_t *i;
        for(i = alpm_get_syncdbs(h); i; i = i->next) {
            if(strncmp(alpm_db_get_name(i->data), pkgname, c - pkgname) == 0) {
                return alpm_db_get_pkg(i->data, c + 1);
            }
        }
    } else {
        alpm_list_t *i;
        for(i = alpm_get_syncdbs(h); i; i = i->next) {
            alpm_pkg_t *p = alpm_db_get_pkg(i->data, pkgname);
            if(p) { return p; }
        }
    }
    return NULL;
}

/*****************************************
 * Tests
 *****************************************/

int pt_grep(int dd, const char *path, const char *needle) {
    int fd;
    char buf[LINE_MAX];
    FILE *f;
    if((fd = openat(dd, path, O_RDONLY)) == -1) { return 0; }
    if((f = fdopen(fd, "r")) == NULL) { close(fd); return 0; }
    while(fgets(buf, sizeof(buf), f)) {
        if(strstr(buf, needle)) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

int pt_not_grep(int dd, const char *path, const char *needle) {
    int fd;
    char buf[LINE_MAX];
    FILE *f;
    if((fd = openat(dd, path, O_RDONLY)) == -1) { return 0; }
    if((f = fdopen(fd, "r")) == NULL) { close(fd); return 0; }
    while(fgets(buf, sizeof(buf), f)) {
        if(strstr(buf, needle)) { fclose(f); return 0; }
    }
    fclose(f);
    return 1;
}

char *pt_installed_pkg_version(pt_env_t *pt, const char *pkgname) {
    static char version[NAME_MAX];
    int dd = openat(pt->dbfd, "local", O_DIRECTORY);
    DIR *dirp = fdopendir(dd);
    struct dirent entry, *result;

    version[0] = '\0';

    while(readdir_r(dirp, &entry, &result) == 0 && result) {
        char *c, *dname = entry.d_name;
        for(c = dname + strlen(dname); c > dname && *c != '-'; c--);
        for(c--; c > dname && *c != '-'; c--);
        if(c > dname && strncmp(dname, pkgname, c - dname) == 0) {
            strcpy(version, c + 1);
            break;
        }
    }

    closedir(dirp);
    return version[0] == '\0' ? NULL : version;
}

#endif /* PACTEST_C */
