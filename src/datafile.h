/*
 * Copyright 2019-2024 OARC, Inc.
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

#include "result.h"
#include "buffer.h"

#ifndef PERF_DATAFILE_H
#define PERF_DATAFILE_H 1

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    input_format_text_query,
    input_format_text_update,
    input_format_tcp_wire_format
} perf_input_format_t;

typedef struct perf_datafile perf_datafile_t;
struct perf_datafile {
    pthread_mutex_t lock;
    int             pipe_fd;
    int             fd;
    bool            is_file;
    size_t          size, at, have;
    bool            cached;
    char            databuf[(64 * 1024) + sizeof(uint16_t)]; /* pad for null-terminated string or TCP wire length */
    unsigned int    maxruns;
    unsigned int    nruns;
    bool            read_any;

    perf_input_format_t format;
    perf_result_t (*readfunc)(perf_datafile_t* dfile, perf_buffer_t* lines);
};

perf_datafile_t* perf_datafile_open(const char* filename, perf_input_format_t format);

void perf_datafile_close(perf_datafile_t** dfilep);
void perf_datafile_setmaxruns(perf_datafile_t* dfile, unsigned int maxruns);
void perf_datafile_setpipefd(perf_datafile_t* dfile, int pipe_fd);

perf_result_t perf_datafile_next(perf_datafile_t* dfile, perf_buffer_t* lines);

unsigned int perf_datafile_nruns(const perf_datafile_t* dfile);

#endif
