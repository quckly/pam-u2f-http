/*
 * Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

#include "util.h"

#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <syslog.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <jansson.h>
#include <curl/curl.h>
#include <u2f-server/u2f-server.h>

unsigned char *dump_from_hex(const char *str) {
    if (strlen(str) % 2 != 0) {
        return NULL;
    }

    int str_len = strlen(str) / 2;
    unsigned char *res = malloc(sizeof(unsigned char) * str_len);

    for (int i = 0; i < str_len; i++) {
        unsigned int x;
        if (sscanf(&str[2 * i], "%2x", &x) != 1) {
            free(res);
            return NULL;
        }
        res[i] = (unsigned char) x;
    }

    return res;
}

int get_user_mapping(const char *authfile, const char *username, int verbose, FILE *debug_file,
                     char **keyHandle, unsigned char **publicKey) {
    int retval = -1;
    struct stat st;
    struct passwd *pw = NULL, pw_s;
    char buffer[BUFSIZE];
    int fd;

    fd = open(authfile, O_RDONLY, 0);
    if (fd < 0) {
        if (verbose)
                D(debug_file, "Cannot open file: %s (%s)", authfile, strerror(errno));
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        if (verbose)
                D(debug_file, "Cannot stat file: %s (%s)", authfile, strerror(errno));
        goto done;
    }

    if (!S_ISREG(st.st_mode)) {
        if (verbose)
                D(debug_file, "%s is not a regular file", authfile);
        goto done;
    }

    if (st.st_size == 0) {
        if (verbose)
                D(debug_file, "File %s is empty", authfile);
        goto done;
    }

    int gpu_ret = getpwuid_r(st.st_uid, &pw_s, buffer, sizeof(buffer), &pw);
    if (gpu_ret != 0 || pw == NULL) {
        D(debug_file, "Unable to retrieve credentials for uid %u, (%s)", st.st_uid,
          strerror(errno));
        goto done;
    }

    if (strcmp(pw->pw_name, username) != 0 && strcmp(pw->pw_name, "root") != 0) {
        if (strcmp(username, "root") != 0) {
            D(debug_file, "The owner of the authentication file is neither %s nor root",
              username);
        } else {
            D(debug_file, "The owner of the authentication file is not root");
        }
        goto done;
    }

    json_t *json = json_loadfd(fd, 0, NULL);
    if (!json) {
        D(debug_file, "Unable to load JSON with user mapping");
        goto done;
    }

    json_t *user_mapping = json_object_get(json, username);
    if (!user_mapping) {
        D(debug_file, "Username %s is not present in mapping file", username);
        goto err;
    }

    char *kh, *pk;
    if (!json_unpack(user_mapping, "{s:s, s:s}", "keyHandle", &kh, "publicKey", &pk)) {
        unsigned char *public_key = dump_from_hex(pk);
        if (public_key == NULL)
                D(debug_file, "Can't decode from hex.");
        else {
            if ((*keyHandle = strdup(kh)) == NULL)
                    D(debug_file, "Not enough memory to copy with strdup");
            else {
                *publicKey = public_key;
                retval = 0;
            }
        }
    }

    json_decref(user_mapping);

    err:
    json_decref(json);

    done:
    close(fd);

    return retval;
}

int do_request(const char *data, const char *url, FILE *debug_file, char **output) {
    int retval = -1;
    CURLcode res;

    struct PostWrite pw;
    struct PostRead pr;

    pw.readptr = data;
    pw.sizeleft = strlen(data);

    pr.memory = malloc(1);  /* will be grown as needed by the realloc above */
    pr.size = 0;    /* no data at this point */

    res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (res != CURLE_OK) {
        return retval;
    }

    CURL *curl = curl_easy_init();
    if (curl) {
        struct curl_slist *chunk = NULL;
        chunk = curl_slist_append(chunk, "Content-Type: application/json");
        chunk = curl_slist_append(chunk, "User-Agent: pam-u2f-http/0.1");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) POST_TIMEOUT);
        // post data to server
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &pw);
        // read post result from server
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &pr);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (long) pw.sizeleft);
        res = curl_easy_perform(curl);
        curl_slist_free_all(chunk);
        if (res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            if (response_code != 0 && response_code == 200) {
                if ((*output = strdup(pr.memory)) == NULL)
                        D(debug_file, "Cannot copy with strdup");
                else
                    retval = 0;
            } else {
                D(debug_file, "Non 200 response from server");
            }
        } else
                D(debug_file, "Cannot perform request");
        curl_easy_cleanup(curl);
    }

    free(pr.memory);
    curl_global_cleanup();

    return retval;
}

// From https://curl.haxx.se/libcurl/c/getinmemory.html
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct PostRead *mem = (struct PostRead *) userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// From https://curl.haxx.se/libcurl/c/post-callback.html
static size_t read_callback(void *dest, size_t size, size_t nmemb, void *userp) {
    struct PostWrite *wt = (struct PostWrite *) userp;
    size_t buffer_size = size * nmemb;

    if (wt->sizeleft) {
        /* copy as much as possible from the source to the destination */
        size_t copy_this_much = wt->sizeleft;
        if (copy_this_much > buffer_size)
            copy_this_much = buffer_size;
        memcpy(dest, wt->readptr, copy_this_much);

        wt->readptr += copy_this_much;
        wt->sizeleft -= copy_this_much;
        return copy_this_much; /* we copied this many bytes */
    }

    return 0; /* no more data left to deliver */
}

int do_authentication(const cfg_t *cfg, const char *keyHandle, const unsigned char *publicKey) {
    u2fs_ctx_t *ctx;
    u2fs_auth_res_t *auth_result;
    u2fs_rc s_rc;
    char *buf, *challenge;
    int retval = -2;

    s_rc = u2fs_global_init(cfg->debug ? U2FS_DEBUG : 0);
    if (s_rc != U2FS_OK) {
        D(cfg->debug_file, "Unable to initialize libu2f-server: %s", u2fs_strerror(s_rc));
        return retval;
    }

    s_rc = u2fs_init(&ctx);
    if (s_rc != U2FS_OK) {
        D(cfg->debug_file, "Unable to initialize libu2f-server context: %s", u2fs_strerror(s_rc));
        return retval;
    }

    if ((s_rc = u2fs_set_origin(ctx, cfg->origin)) != U2FS_OK) {
        if (cfg->debug)
                D(cfg->debug_file, "Unable to set origin: %s", u2fs_strerror(s_rc));
        return retval;
    }

    if ((s_rc = u2fs_set_appid(ctx, cfg->appid)) != U2FS_OK) {
        if (cfg->debug)
                D(cfg->debug_file, "Unable to set appid: %s", u2fs_strerror(s_rc));
        return retval;
    }


    if ((s_rc = u2fs_set_keyHandle(ctx, keyHandle)) != U2FS_OK) {
        if (cfg->debug)
                D(cfg->debug_file, "Unable to set keyHandle: %s", u2fs_strerror(s_rc));
        return retval;
    }


    if ((s_rc = u2fs_set_publicKey(ctx, publicKey)) != U2FS_OK) {
        if (cfg->debug)
                D(cfg->debug_file, "Unable to set publicKey %s", u2fs_strerror(s_rc));
        return retval;
    }


    if ((s_rc = u2fs_authentication_challenge(ctx, &buf)) != U2FS_OK) {
        if (cfg->debug)
                D(cfg->debug_file, "Unable to produce authentication challenge: %s",
                  u2fs_strerror(s_rc));
        free(buf);
        buf = NULL;
        return retval;
    }

    if (cfg->debug)
            D(cfg->debug_file, "Challenge: %s", buf);

    // send challenge
    if (do_request(buf, cfg->url, cfg->debug_file, &challenge)) {
        free(buf);
        buf = NULL;
        return retval;
    }

    if (cfg->debug)
            D(cfg->debug_file, "Response: %s", challenge);

    retval = -1;
    s_rc = u2fs_authentication_verify(ctx, challenge, &auth_result);
    u2fs_free_auth_res(auth_result);
    free(challenge);
    challenge = NULL;

    if (s_rc == U2FS_OK) {
        retval = 1;
    } else {
        if (cfg->debug)
                D(cfg->debug_file, "Unable to authenticate user, %s", u2fs_strerror(s_rc));
    }

    free(buf);
    buf = NULL;
    u2fs_done(ctx);
    u2fs_global_done();

    return retval;
}

#if defined(PAM_DEBUG)
void _debug(FILE *debug_file, const char *file, int line, const char *func, const char *fmt, ...) {
  va_list ap;
#ifdef __linux__
  unsigned int size;
  char buffer[BUFSIZE];
  char *out;

  size = (unsigned int)snprintf(NULL, 0, DEBUG_STR, file, line, func);
  va_start(ap, fmt);
  size += (unsigned int)vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  va_start(ap, fmt);
  if (size < (BUFSIZE - 1)) {
    out = buffer;
  }
  else {
    out = malloc(size);
  }

  size = (unsigned int)sprintf(out, DEBUG_STR, file, line, func);
  vsprintf(&out[size], fmt, ap);
  va_end(ap);

  if (debug_file == (FILE *)-1) {
    syslog(LOG_AUTHPRIV | LOG_DEBUG, "%s", out);
  }
  else {
    fprintf(debug_file, "%s\n", out);
  }

  if (out != buffer) {
    free(out);
  }
#else /* Windows, MAC */
  va_start(ap, fmt);
  fprintf(debug_file, DEBUG_STR, file, line, func );
  vfprintf(debug_file, fmt, ap);
  fprintf(debug_file, "\n");
  va_end(ap);
#endif /* __linux__ */
}
#endif /* PAM_DEBUG */
