/*
 * Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <security/pam_appl.h>

#define BUFSIZE 1024
#define PK_LEN 130 // Public key
#define KH_LEN 86  // Key handle
#define RD_LEN 40  // Rounding
#define POST_TIMEOUT 20
#define DEVSIZE (((PK_LEN) + (KH_LEN) + (RD_LEN)))
#define DEFAULT_AUTHFILE_DIR_VAR "XDG_CONFIG_HOME"
#define DEFAULT_AUTHFILE "/pam-u2f-http/u2f_keys"
#define DEFAULT_ORIGIN_PREFIX "pam://"
#define DEBUG_STR "debug(pam_u2f): %s:%d (%s): "

#if defined(DEBUG_PAM)
#define D(file, ...)  _debug(file, __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define D(file, ...)
#endif /* DEBUG_PAM */

struct PostWrite {
    const char *readptr;
    size_t sizeleft;
};
struct PostRead {
    char *memory;
    size_t size;
};

typedef struct {
    int debug;
    int nouserok;
    int openasuser;
    const char *auth_file;
    const char *origin;
    const char *appid;
    const char *url;
    FILE *debug_file;
} cfg_t;

int get_user_mapping(const char *authfile, const char *username, int verbose, FILE *debug_file,
                     char **keyHandle, unsigned char **publicKey);
int do_request(const char *data, const char *url, FILE *debug_file, char **output);
int do_authentication(const cfg_t *cfg, const char* keyHandle, const unsigned char* publicKey);
static size_t read_callback(void *dest, size_t size, size_t nmemb, void *userp);
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
void _debug(FILE *, const char *, int, const char *, const char *, ...);
#endif /* UTIL_H */