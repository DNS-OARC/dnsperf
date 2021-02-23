/*
 * Copyright 2019-2021 OARC, Inc.
 * Copyright 2017-2018 Akamai Technologies
 * Copyright 2006-2016 Nominum, Inc.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include "datafile.h"

#include "log.h"
#include "os.h"
#include "util.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

perf_datafile_t* perf_datafile_open(const char* filename)
{
    perf_datafile_t* dfile;
    struct stat      buf;

    dfile = calloc(1, sizeof(perf_datafile_t));
    if (!dfile) {
        perf_log_fatal("out of memory");
        return 0; // fix clang scan-build
    }

    PERF_MUTEX_INIT(&dfile->lock);
    dfile->pipe_fd  = -1;
    dfile->is_file  = false;
    dfile->size     = 0;
    dfile->cached   = false;
    dfile->maxruns  = 1;
    dfile->nruns    = 0;
    dfile->read_any = false;
    if (!filename) {
        dfile->fd = STDIN_FILENO;
    } else {
        dfile->fd = open(filename, O_RDONLY);
        if (dfile->fd < 0)
            perf_log_fatal("unable to open file: %s", filename);
        if (fstat(dfile->fd, &buf) == 0 && S_ISREG(buf.st_mode)) {
            dfile->is_file = true;
            dfile->size    = buf.st_size;
        }
    }

    return dfile;
}

void perf_datafile_close(perf_datafile_t** dfilep)
{
    perf_datafile_t* dfile;

    assert(dfilep);
    assert(*dfilep);

    dfile   = *dfilep;
    *dfilep = 0;

    if (dfile->fd >= 0 && dfile->fd != STDIN_FILENO) {
        close(dfile->fd);
    }
    PERF_MUTEX_DESTROY(&dfile->lock);
    free(dfile);
}

void perf_datafile_setpipefd(perf_datafile_t* dfile, int pipe_fd)
{
    dfile->pipe_fd = pipe_fd;
}

void perf_datafile_setmaxruns(perf_datafile_t* dfile, unsigned int maxruns)
{
    dfile->maxruns = maxruns;
}

static void reopen_file(perf_datafile_t* dfile)
{
    if (dfile->cached) {
        dfile->at = 0;
    } else {
        if (lseek(dfile->fd, 0L, SEEK_SET) < 0) {
            perf_log_fatal("cannot reread input");
        }
        dfile->at         = 0;
        dfile->have       = 0;
        dfile->databuf[0] = 0;
    }
}

static perf_result_t read_more(perf_datafile_t* dfile)
{
    ssize_t                n;
    perf_result_t          result;
    struct perf_net_socket sock = { .mode = sock_file, .fd = dfile->fd };

    if (!dfile->is_file && dfile->pipe_fd >= 0) {
        result = perf_os_waituntilreadable(&sock, dfile->pipe_fd, -1);
        if (result != PERF_R_SUCCESS)
            return (result);
    }

    if (dfile->at && dfile->at < dfile->have) {
        memmove(dfile->databuf, &dfile->databuf[dfile->at], dfile->have - dfile->at);
        dfile->have -= dfile->at;
        dfile->at = 0;
    } else if (dfile->at == dfile->have) {
        dfile->have = 0;
        dfile->at   = 0;
    }

    n = read(dfile->fd, &dfile->databuf[dfile->have], sizeof(dfile->databuf) - dfile->have - 1);
    if (n < 0) {
        return (PERF_R_FAILURE);
    }

    dfile->have += n;
    dfile->databuf[dfile->have] = 0;

    if (dfile->is_file && dfile->have == dfile->size) {
        dfile->cached = true;
    }

    return (PERF_R_SUCCESS);
}

static perf_result_t read_one_line(perf_datafile_t* dfile, perf_buffer_t* lines)
{
    const char*   cur;
    size_t        length, curlen, nrem;
    perf_result_t result;

    while (true) {
        /* Get the current line */
        cur    = &dfile->databuf[dfile->at];
        curlen = strcspn(cur, "\n");

        /*
         * If the current line contains the rest of the buffer,
         * we need to read more (unless the full file is cached).
         */
        nrem = dfile->have - dfile->at;
        if (curlen == nrem) {
            if (!dfile->cached) {
                result = read_more(dfile);
                if (result != PERF_R_SUCCESS)
                    return (result);
            }
            if (dfile->have - dfile->at == 0) {
                dfile->nruns++;
                return (PERF_R_EOF);
            }
            if (dfile->have - dfile->at > nrem)
                continue;
        }

        /* We now have a line.  Advance the buffer past it. */
        dfile->at += curlen;
        if (dfile->have - dfile->at > 0) {
            dfile->at += 1;
        }

        /* If the line is empty or a comment, we need to try again. */
        if (curlen > 0 && cur[0] != ';')
            break;
    }

    length = perf_buffer_availablelength(lines);
    if (curlen > length - 1)
        curlen = length - 1;
    perf_buffer_putmem(lines, (unsigned char*)cur, curlen);
    perf_buffer_putuint8(lines, 0);

    return (PERF_R_SUCCESS);
}

perf_result_t perf_datafile_next(perf_datafile_t* dfile, perf_buffer_t* lines, bool is_update)
{
    const char*   current;
    perf_result_t result;

    PERF_LOCK(&dfile->lock);

    if (dfile->maxruns > 0 && dfile->maxruns == dfile->nruns) {
        result = PERF_R_EOF;
        goto done;
    }

    result = read_one_line(dfile, lines);
    if (result == PERF_R_EOF) {
        if (!dfile->read_any) {
            result = PERF_R_INVALIDFILE;
            goto done;
        }
        if (dfile->maxruns != dfile->nruns) {
            reopen_file(dfile);
            result = read_one_line(dfile, lines);
        }
    }
    if (result != PERF_R_SUCCESS) {
        goto done;
    }
    dfile->read_any = true;

    if (is_update) {
        while (true) {
            current = perf_buffer_used(lines);
            result  = read_one_line(dfile, lines);
            if (result == PERF_R_EOF && dfile->maxruns != dfile->nruns) {
                reopen_file(dfile);
            }
            if (result != PERF_R_SUCCESS || strcasecmp(current, "send") == 0)
                break;
        }
    }

    result = PERF_R_SUCCESS;
done:
    PERF_UNLOCK(&dfile->lock);
    return (result);
}

unsigned int perf_datafile_nruns(const perf_datafile_t* dfile)
{
    return dfile->nruns;
}
