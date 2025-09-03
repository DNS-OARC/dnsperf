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

/***
 ***	DNS Performance Testing Tool
 ***/

#include "config.h"

#include "net.h"
#include "datafile.h"
#include "dns.h"
#include "log.h"
#include "opt.h"
#include "os.h"
#include "util.h"
#include "list.h"
#include "buffer.h"
#if HAVE_STDATOMIC_H
#include "ext/hg64.h"
#define USE_HISTOGRAMS
#endif

#include <inttypes.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#define HISTOGRAM_SIGBITS 5 /* about 3 % latency precision */

#define DEFAULT_SERVER_NAME "127.0.0.1"
#define DEFAULT_SERVER_PORT 53
#define DEFAULT_SERVER_DOT_PORT 853
#define DEFAULT_SERVER_DOH_PORT 443
#define DEFAULT_SERVER_PORTS "udp/tcp 53, DoT 853 or DoH 443"
#define DEFAULT_LOCAL_PORT 0
#define DEFAULT_MAX_OUTSTANDING 100
#define DEFAULT_TIMEOUT 5

#define TIMEOUT_CHECK_TIME 100000

#define MAX_INPUT_DATA (64 * 1024) + 2

#define MAX_SOCKETS 256

#define RECV_BATCH_SIZE 16

typedef struct {
    int                 argc;
    char**              argv;
    int                 family;
    uint32_t            clients;
    uint32_t            threads;
    uint32_t            maxruns;
    uint64_t            timelimit;
    perf_sockaddr_t     server_addr;
    perf_sockaddr_t     local_addr;
    uint64_t            timeout;
    uint32_t            bufsize;
    bool                edns;
    bool                dnssec;
    const char*         tsigkey;
    perf_ednsoption_t*  edns_option;
    uint32_t            max_outstanding;
    uint32_t            max_qps;
    uint64_t            stats_interval;
    bool                verbose_interval_stats;
    bool                updates;
    bool                binary_input;
    perf_input_format_t input_format;
    bool                verbose;
    enum perf_net_mode  mode;
    perf_suppress_t     suppress;
    size_t              num_queries_per_conn;
#ifdef USE_HISTOGRAMS
    bool latency_histogram;
#endif
    int qps_threshold_wait;
} config_t;

typedef struct {
    uint64_t        start_time;
    uint64_t        end_time;
    uint64_t        stop_time;
    struct timespec stop_time_ns;
} times_t;

#define DNSPERF_STATS_RCODECOUNTS 16
typedef struct {
    uint64_t rcodecounts[DNSPERF_STATS_RCODECOUNTS];

    uint64_t num_sent;
    uint64_t num_interrupted;
    uint64_t num_timedout;
    uint64_t num_completed;
    uint64_t num_unexpected;

    uint64_t total_request_size;
    uint64_t total_response_size;

    uint64_t latency_sum;
    uint64_t latency_sum_squares;
    uint64_t latency_min;
    uint64_t latency_max;

    uint64_t num_conn_attempts;
    uint64_t num_conn_completed;

    uint64_t conn_latency_sum;
    uint64_t conn_latency_sum_squares;
    uint64_t conn_latency_min;
    uint64_t conn_latency_max;

#ifdef USE_HISTOGRAMS
    hg64* latency;
    hg64* conn_latency;
#endif
} stats_t;

typedef perf_list(struct query_info) query_list;

typedef struct query_info {
    uint64_t                timestamp;
    query_list*             list;
    char*                   desc;
    struct perf_net_socket* sock;
    /*
     * This link links the query into the list of outstanding
     * queries or the list of available query IDs.
     */
    perf_link(struct query_info);
} query_info;

#define NQIDS 65536

typedef struct {
    query_info queries[NQIDS];
    query_list outstanding_queries;
    query_list unused_queries;

    pthread_t sender;
    pthread_t receiver;

    pthread_mutex_t lock;
    pthread_cond_t  cond;

    unsigned int             nsocks;
    int                      current_sock;
    struct perf_net_socket** socks;

    bool     done_sending;
    uint64_t done_send_time;

    const config_t* config;
    const times_t*  times;
    stats_t         stats;

    uint32_t max_outstanding;
    uint32_t max_qps;

    uint64_t last_recv;
} threadinfo_t;

static threadinfo_t* threads;

static pthread_mutex_t start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  start_cond = PTHREAD_COND_INITIALIZER;
static bool            started;

static bool interrupted = false;

static int threadpipe[2];
static int mainpipe[2];
static int intrpipe[2];

static perf_datafile_t* input;

const char* progname = "dnsperf";

static void
handle_sigint(int sig)
{
    (void)sig;
    if (write(intrpipe[1], "", 1)) { // lgtm [cpp/empty-block]
    }
}

static void
print_initial_status(const config_t* config)
{
    time_t now;
    char   buf[255], ct[32];
    int    i;

    printf("[Status] Command line: %s", progname);
    for (i = 1; i < config->argc; i++)
        printf(" %s", config->argv[i]);
    printf("\n");

    perf_sockaddr_format(&config->server_addr, buf, sizeof(buf));
    if (perf_sockaddr_isinet6(&config->server_addr)) {
        printf("[Status] Sending %s (to [%s]:%d)\n",
            config->updates ? "updates" : "queries", buf, perf_sockaddr_port(&config->server_addr));
    } else {
        printf("[Status] Sending %s (to %s:%d)\n",
            config->updates ? "updates" : "queries", buf, perf_sockaddr_port(&config->server_addr));
    }

    now = time(NULL);
    printf("[Status] Started at: %s", ctime_r(&now, ct));

    printf("[Status] Stopping after ");
    if (config->timelimit)
        printf("%u.%06u seconds",
            (unsigned int)(config->timelimit / MILLION),
            (unsigned int)(config->timelimit % MILLION));
    if (config->timelimit && config->maxruns)
        printf(" or ");
    if (config->maxruns)
        printf("%u run%s through file", config->maxruns,
            config->maxruns == 1 ? "" : "s");
    printf("\n");
}

static void
print_final_status(const config_t* config)
{
    const char* reason;

    if (interrupted)
        reason = "interruption";
    else if (config->maxruns > 0 && perf_datafile_nruns(input) == config->maxruns)
        reason = "end of file";
    else
        reason = "time limit";

    printf("[Status] Testing complete (%s)\n", reason);
    printf("\n");
}

static double
stddev(uint64_t sum_of_squares, uint64_t sum, uint64_t total)
{
    double squared;

    squared = (double)sum * (double)sum;
    return sqrt((sum_of_squares - (squared / total)) / (total - 1));
}

static void
diff_stats(const config_t* config, stats_t* last, stats_t* now, stats_t* diff)
{
    int i = 0;
    for (; i < DNSPERF_STATS_RCODECOUNTS; i++) {
        diff->rcodecounts[i] = now->rcodecounts[i] - last->rcodecounts[i];
    }

    diff->num_sent        = now->num_sent - last->num_sent;
    diff->num_interrupted = now->num_interrupted - last->num_interrupted;
    diff->num_timedout    = now->num_timedout - last->num_timedout;
    diff->num_completed   = now->num_completed - last->num_completed;
    diff->num_unexpected  = now->num_unexpected - last->num_unexpected;

    diff->total_request_size  = now->total_request_size - last->total_request_size;
    diff->total_response_size = now->total_response_size - last->total_response_size;

    diff->latency_sum         = now->latency_sum - last->latency_sum;
    diff->latency_sum_squares = now->latency_sum_squares - last->latency_sum_squares;
    diff->latency_min         = 0; /* not enough data */
    diff->latency_max         = 0;

    diff->num_conn_attempts  = now->num_conn_attempts - last->num_conn_attempts;
    diff->num_conn_completed = now->num_conn_completed - last->num_conn_completed;

    diff->conn_latency_sum         = now->conn_latency_sum - last->conn_latency_sum;
    diff->conn_latency_sum_squares = now->conn_latency_sum_squares - last->conn_latency_sum_squares;
    diff->conn_latency_min         = 0;
    diff->conn_latency_max         = 0;

#ifdef USE_HISTOGRAMS
    if (config->latency_histogram) {
        free(diff->latency);
        diff->latency = hg64_create(HISTOGRAM_SIGBITS);
        if (last->latency) {
            hg64_diff(now->latency, last->latency, diff->latency);
        } else { /* first sample */
            hg64_merge(diff->latency, now->latency);
        }
        hg64_get(diff->latency, hg64_min_key(diff->latency), &diff->latency_min, NULL, NULL);
        hg64_get(diff->latency, hg64_max_key(diff->latency), NULL, &diff->latency_max, NULL);

        free(diff->conn_latency);
        diff->conn_latency = hg64_create(HISTOGRAM_SIGBITS);
        if (last->conn_latency) {
            hg64_diff(now->conn_latency, last->conn_latency, diff->conn_latency);
        } else { /* first sample */
            hg64_merge(diff->conn_latency, now->conn_latency);
        }
        hg64_get(diff->conn_latency, hg64_min_key(diff->conn_latency), &diff->conn_latency_min, NULL, NULL);
        hg64_get(diff->conn_latency, hg64_max_key(diff->conn_latency), NULL, &diff->conn_latency_max, NULL);
    }
#endif
}

#ifdef USE_HISTOGRAMS
static void
print_histogram(hg64* histogram, const char* const desc)
{
    printf("  Latency bucket (s):   %s\n", desc);
    uint64_t pmin, pmax, pcount;
    for (unsigned key = 0;
         hg64_get(histogram, key, &pmin, &pmax, &pcount) == true;
         key = hg64_next(histogram, key)) {
        if (pcount == 0)
            continue;
        printf("  %" PRIu64 ".%06" PRIu64 " - %" PRIu64 ".%06" PRIu64 ":  %" PRIu64 "\n",
            pmin / MILLION,
            pmin % MILLION,
            pmax / MILLION,
            pmax % MILLION,
            pcount);
    };
}
#endif

/*
 * now != 0 is call to print stats in the middle of test run.
 * min-max values are not available on per-interval basis, so skip them.
 */
static void
print_statistics(const config_t* config, const times_t* times, stats_t* stats, uint64_t now, uint64_t interval_time)
{
    const char*  units;
    uint64_t     run_time;
    bool         first_rcode;
    uint64_t     latency_avg;
    unsigned int i;

    units = config->updates ? "Updates" : "Queries";

    if (now)
        run_time = now - times->start_time;
    else
        run_time = times->end_time - times->start_time;

    printf("%sStatistics:\n\n", now ? "Interval " : "");

    printf("  %s sent:         %" PRIu64 "\n",
        units, stats->num_sent);
    printf("  %s completed:    %" PRIu64 " (%.2lf%%)\n",
        units, stats->num_completed,
        PERF_SAFE_DIV(100.0 * stats->num_completed, stats->num_sent));
    printf("  %s lost:         %" PRIu64 " (%.2lf%%)\n",
        units, stats->num_timedout,
        PERF_SAFE_DIV(100.0 * stats->num_timedout, stats->num_sent));
    if (stats->num_interrupted > 0)
        printf("  %s interrupted:  %" PRIu64 " (%.2lf%%)\n",
            units, stats->num_interrupted,
            PERF_SAFE_DIV(100.0 * stats->num_interrupted, stats->num_sent));
    if (stats->num_unexpected > 0)
        printf("  Unexpected IDs:       %" PRIu64 " (%.2lf%%)\n",
            stats->num_unexpected,
            PERF_SAFE_DIV(100.0 * stats->num_unexpected, stats->num_sent));

    printf("\n");

    printf("  Response codes:       ");
    first_rcode = true;
    for (i = 0; i < DNSPERF_STATS_RCODECOUNTS; i++) {
        if (stats->rcodecounts[i] == 0)
            continue;
        if (first_rcode)
            first_rcode = false;
        else
            printf(", ");
        printf("%s %" PRIu64 " (%.2lf%%)",
            perf_dns_rcode_strings[i], stats->rcodecounts[i],
            (stats->rcodecounts[i] * 100.0) / stats->num_completed);
    }
    printf("\n");

    printf("  Average packet size:  request %u, response %u\n",
        (unsigned int)PERF_SAFE_DIV(stats->total_request_size, stats->num_sent),
        (unsigned int)PERF_SAFE_DIV(stats->total_response_size,
            stats->num_completed));
    printf("  Run time (s):         %u.%06u\n",
        (unsigned int)(run_time / MILLION),
        (unsigned int)(run_time % MILLION));
    printf("  %s per second:   %.6lf\n", units,
        PERF_SAFE_DIV(stats->num_completed, (((double)(now ? interval_time : run_time) / MILLION))));

    printf("\n");

    latency_avg = PERF_SAFE_DIV(stats->latency_sum, stats->num_completed);
    printf("  Average Latency (s):  %u.%06u",
        (unsigned int)(latency_avg / MILLION),
        (unsigned int)(latency_avg % MILLION));
    if (!now) {
        printf(" (min %u.%06u, max %u.%06u)\n",
            (unsigned int)(stats->latency_min / MILLION),
            (unsigned int)(stats->latency_min % MILLION),
            (unsigned int)(stats->latency_max / MILLION),
            (unsigned int)(stats->latency_max % MILLION));
    } else {
        printf("\n");
    }

    if (stats->num_completed > 1) {
        printf("  Latency StdDev (s):   %f\n",
            stddev(stats->latency_sum_squares, stats->latency_sum,
                stats->num_completed)
                / MILLION);
#ifdef USE_HISTOGRAMS
        if (config->latency_histogram)
            print_histogram(stats->latency, "answer count");
#endif
    }

    printf("\n");

    if (!stats->num_conn_completed && !stats->num_conn_attempts) {
        fflush(stdout);
        return;
    }

    printf("Connection Statistics:\n\n");
    printf("  Connection attempts:  %" PRIu64 " (%" PRIu64 " successful, %.2lf%%)\n\n",
        stats->num_conn_attempts,
        stats->num_conn_completed,
        PERF_SAFE_DIV(100.0 * stats->num_conn_completed, stats->num_conn_attempts));
    latency_avg = PERF_SAFE_DIV(stats->conn_latency_sum, stats->num_conn_completed);
    printf("  Average Latency (s):  %u.%06u",
        (unsigned int)(latency_avg / MILLION),
        (unsigned int)(latency_avg % MILLION));
    if (!now) {
        printf(" (min %u.%06u, max %u.%06u)\n",
            (unsigned int)(stats->conn_latency_min / MILLION),
            (unsigned int)(stats->conn_latency_min % MILLION),
            (unsigned int)(stats->conn_latency_max / MILLION),
            (unsigned int)(stats->conn_latency_max % MILLION));
    } else {
        printf("\n");
    }
    if (stats->num_conn_completed > 1) {
        printf("  Latency StdDev (s):   %f\n",
            stddev(stats->conn_latency_sum_squares, stats->conn_latency_sum, stats->num_conn_completed) / MILLION);
#ifdef USE_HISTOGRAMS
        if (config->latency_histogram)
            print_histogram(stats->latency, "connection count");
#endif
    }

    printf("\n");
    fflush(stdout);
}

/*
 * Caller must free() stats->latency and stats->conn_latency.
 */
static void
sum_stats(const config_t* config, stats_t* total)
{
    unsigned int i, j;

    memset(total, 0, sizeof(*total));
#ifdef USE_HISTOGRAMS
    if (config->latency_histogram) {
        total->latency      = hg64_create(HISTOGRAM_SIGBITS);
        total->conn_latency = hg64_create(HISTOGRAM_SIGBITS);
    }
#endif

    for (i = 0; i < config->threads; i++) {
        stats_t* stats = &threads[i].stats;
#ifdef USE_HISTOGRAMS
        if (config->latency_histogram) {
            hg64_merge(total->latency, stats->latency);
            hg64_merge(total->conn_latency, stats->conn_latency);
        }
#endif

        for (j = 0; j < DNSPERF_STATS_RCODECOUNTS; j++)
            total->rcodecounts[j] += stats->rcodecounts[j];

        total->num_sent += stats->num_sent;
        total->num_interrupted += stats->num_interrupted;
        total->num_timedout += stats->num_timedout;
        total->num_completed += stats->num_completed;
        total->num_unexpected += stats->num_unexpected;

        total->total_request_size += stats->total_request_size;
        total->total_response_size += stats->total_response_size;

        total->latency_sum += stats->latency_sum;
        total->latency_sum_squares += stats->latency_sum_squares;
        if (stats->latency_min < total->latency_min || i == 0)
            total->latency_min = stats->latency_min;
        if (stats->latency_max > total->latency_max)
            total->latency_max = stats->latency_max;

        total->num_conn_completed += stats->num_conn_completed;
        total->num_conn_attempts += stats->num_conn_attempts;

        total->conn_latency_sum += stats->conn_latency_sum;
        total->conn_latency_sum_squares += stats->conn_latency_sum_squares;
        if (stats->conn_latency_min < total->conn_latency_min || i == 0)
            total->conn_latency_min = stats->conn_latency_min;
        if (stats->conn_latency_max > total->conn_latency_max)
            total->conn_latency_max = stats->conn_latency_max;
    }
}

static char*
stringify(unsigned int value)
{
    static char buf[20];

    snprintf(buf, sizeof(buf), "%u", value);
    return buf;
}

static int
measure_nanosleep(config_t* config)
{
    struct timespec start, stop, wait = { 0, 0 };
    int             err;

    int i = 100;
    if ((err = clock_gettime(CLOCK_REALTIME, &start))) {
        return err;
    }
    for (; i; i--) {
        if ((err = nanosleep(&wait, NULL))) {
            return err;
        }
    }
    if ((err = clock_gettime(CLOCK_REALTIME, &stop))) {
        return err;
    }

    // Total time for 100 nanosleep() + 2 clock_gettime()
    config->qps_threshold_wait = ((stop.tv_sec - start.tv_sec) * 1000000000 + stop.tv_nsec - start.tv_nsec)
                                 // divided by 100 runs
                                 / 100
                                 // add fudge
                                 * 3
                                 // converted to microseconds
                                 / 1000;
    if (config->qps_threshold_wait < 0) {
        config->qps_threshold_wait = 0;
    }

    return 0;
}

static void
setup(int argc, char** argv, config_t* config)
{
    const char* family         = NULL;
    const char* server_name    = DEFAULT_SERVER_NAME;
    in_port_t   server_port    = 0;
    const char* local_name     = NULL;
    in_port_t   local_port     = DEFAULT_LOCAL_PORT;
    const char* filename       = NULL;
    const char* edns_option    = NULL;
    const char* mode           = 0;
    const char* doh_uri        = DEFAULT_DOH_URI;
    const char* doh_method     = DEFAULT_DOH_METHOD;
    const char* local_suppress = 0;
    const char* tls_sni        = 0;

    memset(config, 0, sizeof(*config));
    config->argc = argc;
    config->argv = argv;

    config->family          = AF_UNSPEC;
    config->clients         = 1;
    config->threads         = 1;
    config->timeout         = DEFAULT_TIMEOUT * MILLION;
    config->max_outstanding = DEFAULT_MAX_OUTSTANDING;
    config->mode            = sock_udp;

    config->qps_threshold_wait = -1;

    perf_opt_add('f', perf_opt_string, "family",
        "address family of DNS transport, inet or inet6", "any",
        &family);
    perf_opt_add('m', perf_opt_string, "mode", "set transport mode: udp, tcp, dot or doh", "udp", &mode);
    perf_opt_add('s', perf_opt_string, "server_addr",
        "the server to query", DEFAULT_SERVER_NAME, &server_name);
    perf_opt_add('p', perf_opt_port, "port",
        "the port on which to query the server",
        DEFAULT_SERVER_PORTS, &server_port);
    perf_opt_add('a', perf_opt_string, "local_addr",
        "the local address from which to send queries", NULL,
        &local_name);
    perf_opt_add('x', perf_opt_port, "local_port",
        "the local port from which to send queries",
        stringify(DEFAULT_LOCAL_PORT), &local_port);
    perf_opt_add('d', perf_opt_string, "datafile",
        "the input data file", "stdin", &filename);
    perf_opt_add('c', perf_opt_uint, "clients",
        "the number of clients to act as", NULL,
        &config->clients);
    perf_opt_add('T', perf_opt_uint, "threads",
        "the number of threads to run", NULL,
        &config->threads);
    perf_opt_add('n', perf_opt_uint, "maxruns",
        "run through input at most N times", NULL,
        &config->maxruns);
    perf_opt_add('l', perf_opt_timeval, "timelimit",
        "run for at most this many seconds", NULL,
        &config->timelimit);
    perf_opt_add('b', perf_opt_uint, "buffer_size",
        "socket send/receive buffer size in kilobytes", NULL,
        &config->bufsize);
    perf_opt_add('t', perf_opt_timeval, "timeout",
        "the timeout for query completion in seconds",
        stringify(DEFAULT_TIMEOUT), &config->timeout);
    perf_opt_add('e', perf_opt_boolean, NULL,
        "enable EDNS 0", NULL, &config->edns);
    perf_opt_add('E', perf_opt_string, "code:value",
        "send EDNS option", NULL, &edns_option);
    perf_opt_add('D', perf_opt_boolean, NULL,
        "set the DNSSEC OK bit (implies EDNS)", NULL,
        &config->dnssec);
    perf_opt_add('y', perf_opt_string, "[alg:]name:secret",
        "the TSIG algorithm, name and secret (base64)", NULL,
        &config->tsigkey);
    perf_opt_add('q', perf_opt_uint, "num_queries",
        "the maximum number of queries outstanding",
        stringify(DEFAULT_MAX_OUTSTANDING),
        &config->max_outstanding);
    perf_opt_add('Q', perf_opt_uint, "max_qps",
        "limit the number of queries per second", NULL,
        &config->max_qps);
    perf_opt_add('S', perf_opt_timeval, "stats_interval",
        "print qps statistics every N seconds",
        NULL, &config->stats_interval);
    perf_opt_add('u', perf_opt_boolean, NULL,
        "send dynamic updates instead of queries",
        NULL, &config->updates);
    perf_opt_add('B', perf_opt_boolean, NULL,
        "read input file as TCP-stream binary format",
        NULL, &config->binary_input);
    perf_opt_add('v', perf_opt_boolean, NULL,
        "verbose: report each query and additional information to stdout",
        NULL, &config->verbose);
    perf_long_opt_add("doh-uri", perf_opt_string, "doh_uri",
        "the URI to use for DNS-over-HTTPS", DEFAULT_DOH_URI, &doh_uri);
    perf_long_opt_add("doh-method", perf_opt_string, "doh_method",
        "the HTTP method to use for DNS-over-HTTPS: GET or POST", DEFAULT_DOH_METHOD, &doh_method);
    perf_long_opt_add("suppress", perf_opt_string, "message[,message,...]",
        "suppress messages/warnings, see man-page for list of message types", NULL, &local_suppress);
    perf_long_opt_add("num-queries-per-conn", perf_opt_uint, "queries",
        "Number of queries to send per connection", NULL, &config->num_queries_per_conn);
    perf_long_opt_add("verbose-interval-stats", perf_opt_boolean, NULL,
        "print detailed statistics for each stats_interval", NULL, &config->verbose_interval_stats);
#ifdef USE_HISTOGRAMS
    perf_long_opt_add("latency-histogram", perf_opt_boolean, NULL,
        "collect and print detailed latency histograms", NULL, &config->latency_histogram);
#endif
    perf_long_opt_add("qps-threshold-wait", perf_opt_zpint, "microseconds",
        "minimum threshold for enabling wait in rate limiting", stringify(config->qps_threshold_wait), &config->qps_threshold_wait);
    perf_long_opt_add("tls-sni", perf_opt_string, "tls_sni",
        "the TLS SNI to use for TLS connections", NULL, &tls_sni);

    bool log_stdout = false;
    perf_opt_add('W', perf_opt_boolean, NULL, "log warnings and errors to stdout instead of stderr", NULL, &log_stdout);

    perf_opt_parse(argc, argv);

    if (log_stdout) {
        perf_log_tostdout();
    }

    config->suppress = perf_opt_parse_suppress(local_suppress);

    if (mode != 0)
        config->mode = perf_net_parsemode(mode);

    if (!server_port) {
        switch (config->mode) {
        case sock_doh:
            server_port = DEFAULT_SERVER_DOH_PORT;
            break;
        case sock_dot:
            server_port = DEFAULT_SERVER_DOT_PORT;
            break;
        default:
            server_port = DEFAULT_SERVER_PORT;
            break;
        }
    }

    if (tls_sni) {
        perf_net_tls_sni = tls_sni;
    }

    if (doh_uri) {
        perf_net_doh_parse_uri(doh_uri);
    }
    if (doh_method) {
        perf_net_doh_parse_method(doh_method);
    }
    perf_net_doh_set_max_concurrent_streams(config->max_outstanding);

    if (family != NULL)
        config->family = perf_net_parsefamily(family);
    perf_net_parseserver(config->family, server_name, server_port,
        &config->server_addr);
    perf_net_parselocal(config->server_addr.sa.sa.sa_family,
        local_name, local_port, &config->local_addr);

    if (config->binary_input
        && (config->edns || config->edns_option || config->dnssec
            || config->tsigkey || config->updates)) {
        fprintf(stderr, "-B is mutually exclusive with -D, -e, -E, -u, -y\n");
        exit(1);
    }
    if (config->updates)
        config->input_format = input_format_text_update;
    else if (config->binary_input)
        config->input_format = input_format_tcp_wire_format;
    else
        config->input_format = input_format_text_query;
    input = perf_datafile_open(filename, config->input_format);

    if (config->maxruns == 0 && config->timelimit == 0)
        config->maxruns = 1;
    perf_datafile_setmaxruns(input, config->maxruns);

    if (config->dnssec || edns_option != NULL)
        config->edns = true;

    if (config->tsigkey) {
        // check TSIG key to die earlier than in threads
        perf_tsigkey_t* k = perf_tsig_parsekey(config->tsigkey);
        perf_tsig_destroykey(&k);
    }

    if (edns_option != NULL)
        config->edns_option = perf_edns_parseoption(edns_option);

    /*
     * If we run more threads than max-qps, some threads will have
     * ->max_qps set to 0, and be unlimited.
     */
    if (config->max_qps > 0 && config->threads > config->max_qps) {
        perf_log_warning("requested max QPS limit (-Q %u) is lower than number of threads (-T %u), lowering number of threads", config->max_qps, config->threads);
        config->threads = config->max_qps;
    }

    /*
     * We also can't run more threads than clients.
     */
    if (config->threads > config->clients) {
        perf_log_warning("requested number of threads (-T %u) exceeds number of clients (-c %u), lowering number of threads\n", config->threads, config->clients);
        config->threads = config->clients;
    }

#ifndef HAVE_LDNS
    if (config->updates) {
        perf_log_fatal("Unable to dynamic update, support not built in");
    }
#endif

    if (config->qps_threshold_wait < 0) {
        int err = measure_nanosleep(config);
        if (err) {
            char __s[256];
            perf_log_fatal("Unable to measure nanosleep(): %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
    }
}

static void
cleanup(config_t* config)
{
    unsigned int i;

    perf_datafile_close(&input);
    for (i = 0; i < 2; i++) {
        close(threadpipe[i]);
        close(mainpipe[i]);
        close(intrpipe[i]);
    }
    if (config->edns_option != NULL)
        perf_edns_destroyoption(&config->edns_option);
}

typedef enum {
    prepend_unused,
    append_unused,
    prepend_outstanding,
} query_move_op;

static inline void
query_move(threadinfo_t* tinfo, query_info* q, query_move_op op)
{
    perf_list_unlink(*q->list, q);
    switch (op) {
    case prepend_unused:
        q->list = &tinfo->unused_queries;
        perf_list_prepend(tinfo->unused_queries, q);
        break;
    case append_unused:
        q->list = &tinfo->unused_queries;
        perf_list_append(tinfo->unused_queries, q);
        break;
    case prepend_outstanding:
        q->list = &tinfo->outstanding_queries;
        perf_list_prepend(tinfo->outstanding_queries, q);
        break;
    }
}

static inline uint64_t
num_outstanding(const stats_t* stats)
{
    /* make sure negative values aren't returned */
    if (stats->num_completed + stats->num_timedout > stats->num_sent) {
        return 0;
    }
    return stats->num_sent - stats->num_completed - stats->num_timedout;
}

static void
wait_for_start(void)
{
    PERF_LOCK(&start_lock);
    while (!started)
        PERF_WAIT(&start_cond, &start_lock);
    PERF_UNLOCK(&start_lock);
}

static inline void
bit_set(unsigned char* bits, unsigned int bit)
{
    unsigned int shift, mask;

    shift = 7 - (bit % 8);
    mask  = 1 << shift;

    bits[bit / 8] |= mask;
}

static inline void
bit_clear(unsigned char* bits, unsigned int bit)
{
    unsigned int shift, mask;

    shift = 7 - (bit % 8);
    mask  = 1 << shift;

    bits[bit / 8] &= ~mask;
}

static inline bool
bit_check(unsigned char* bits, unsigned int bit)
{
    unsigned int shift;

    shift = 7 - (bit % 8);

    if ((bits[bit / 8] >> shift) & 0x01)
        return true;
    return false;
}

static void*
do_send(void* arg)
{
    threadinfo_t*   tinfo;
    const config_t* config;
    const times_t*  times;
    stats_t*        stats;
    unsigned int    max_packet_size;
    perf_buffer_t   msg;
    uint64_t        now, req_time, wait_us, q_sent = 0, q_step = 0, q_slice;
    char            input_data[MAX_INPUT_DATA];
    perf_buffer_t   lines;
    perf_region_t   used;
    query_info*     q;
    int             qid;
    unsigned char   packet_buffer[MAX_EDNS_PACKET];
    unsigned char*  base;
    unsigned int    length;
    int             n, i, any_inprogress = 0, sock = 0;
    perf_result_t   result;
    bool            all_fail;
    unsigned char   socketbits[(MAX_SOCKETS / 8) + 1] = {};
    perf_tsigkey_t* tsigkey                           = 0;

    tinfo           = (threadinfo_t*)arg;
    config          = tinfo->config;
    times           = tinfo->times;
    stats           = &tinfo->stats;
    max_packet_size = config->edns ? MAX_EDNS_PACKET : MAX_UDP_PACKET;
    perf_buffer_init(&msg, packet_buffer, max_packet_size);
    perf_buffer_init(&lines, input_data, sizeof(input_data));
    if (config->tsigkey) {
        tsigkey = perf_tsig_parsekey(config->tsigkey);
    }

    if (tinfo->max_qps > 0) {
        q_step = MILLION / tinfo->max_qps;
    }
    wait_for_start();
    now      = perf_get_time();
    req_time = now;
    q_slice  = now + MILLION;
    while (!interrupted && now < times->stop_time) {
        /* Avoid flooding the network too quickly. */
        if (stats->num_sent < tinfo->max_outstanding && stats->num_sent % 2 == 1) {
            if (stats->num_completed == 0)
                usleep(1000);
            else
                sleep(0);
            now = perf_get_time();
        }

        /* Some sock might still be sending, try flush all of them */
        if (any_inprogress) {
            any_inprogress = 0;
            for (i = 0; i < tinfo->nsocks; i++) {
                if (!bit_check(socketbits, i)) {
                    continue;
                }
                if (!perf_net_sockready(tinfo->socks[i], threadpipe[0], TIMEOUT_CHECK_TIME)) {
                    any_inprogress = 1;
                } else {
                    bit_clear(socketbits, i);
                }
            }
        }

        /* Rate limiting */
        if (tinfo->max_qps > 0) {
            /* the 1 second time slice where q_sent is calculated over */
            if (q_slice <= now) {
                q_slice += MILLION;
                q_sent   = 0;
                req_time = now; // reset stepping, in case of clock sliding
            }
            /* limit QPS over the 1 second slice */
            if (q_sent >= tinfo->max_qps) {
                if (!any_inprogress) { // only if nothing is in-progress
                    wait_us = q_slice - now;
                    if (config->qps_threshold_wait && wait_us > config->qps_threshold_wait) {
                        wait_us -= config->qps_threshold_wait;
                        struct timespec ts = { 0, 0 };
                        if (wait_us >= MILLION) {
                            ts.tv_sec  = wait_us / MILLION;
                            ts.tv_nsec = (wait_us % MILLION) * 1000;
                        } else {
                            ts.tv_sec  = 0;
                            ts.tv_nsec = wait_us * 1000;
                        }
                        nanosleep(&ts, NULL);
                    }
                }
                now = perf_get_time();
                continue;
            }
            /* handle stepping to the next window to send a query on */
            if (req_time > now) {
                if (!any_inprogress) { // only if nothing is in-progress
                    wait_us = req_time - now;
                    if (config->qps_threshold_wait && wait_us > config->qps_threshold_wait) {
                        wait_us -= config->qps_threshold_wait;
                        struct timespec ts = { 0, 0 };
                        if (wait_us >= MILLION) {
                            ts.tv_sec  = wait_us / MILLION;
                            ts.tv_nsec = (wait_us % MILLION) * 1000;
                        } else {
                            ts.tv_sec  = 0;
                            ts.tv_nsec = wait_us * 1000;
                        }
                        nanosleep(&ts, NULL);
                    }
                }
                now = perf_get_time();
                continue;
            }
            req_time += q_step;
        }

        PERF_LOCK(&tinfo->lock);

        /* Limit in-flight queries */
        if (num_outstanding(stats) >= tinfo->max_outstanding) {
            if (!any_inprogress) { // only if nothing is in-progress
                PERF_TIMEDWAIT(&tinfo->cond, &tinfo->lock, &times->stop_time_ns, NULL);
            }
            PERF_UNLOCK(&tinfo->lock);
            now = perf_get_time();
            continue;
        }

        q = perf_list_head(tinfo->unused_queries);
        query_move(tinfo, q, prepend_outstanding);
        q->timestamp = UINT64_MAX;

        i        = tinfo->nsocks * 2;
        all_fail = true;
        while (i--) {
            sock    = tinfo->current_sock++ % tinfo->nsocks;
            q->sock = tinfo->socks[sock];
            switch (perf_net_sockready(q->sock, threadpipe[0], TIMEOUT_CHECK_TIME)) {
            case 0:
                if (config->verbose && !config->suppress.sockready) {
                    perf_log_warning("socket %p not ready", q->sock);
                }
                q->sock  = 0;
                all_fail = false;
                continue;
            case -1:
                if (config->verbose && !config->suppress.sockready) {
                    perf_log_warning("socket %p readiness check timed out", q->sock);
                }
                q->sock = 0;
                continue;
            default:
                break;
            }
            all_fail = false;
            break;
        };

        if (all_fail) {
            perf_log_fatal("all sockets reported failure, can not continue");
        }

        if (!q->sock) {
            query_move(tinfo, q, prepend_unused);
            PERF_UNLOCK(&tinfo->lock);
            now = perf_get_time();
            continue;
        }
        PERF_UNLOCK(&tinfo->lock);

        perf_buffer_clear(&lines);
        result = perf_datafile_next(input, &lines);
        if (result != PERF_R_SUCCESS) {
            if (result == PERF_R_INVALIDFILE)
                perf_log_fatal("input file contains no data");
            break;
        }

        perf_buffer_t* send = &msg;
        qid                 = q - tinfo->queries;
        switch (config->input_format) {
        case input_format_text_query:
        case input_format_text_update:
            perf_buffer_clear(&msg);
            perf_buffer_usedregion(&lines, &used);
            result = perf_dns_buildrequest(&used, qid,
                config->edns, config->dnssec, config->input_format == input_format_text_update,
                tsigkey, config->edns_option,
                &msg);
            break;

        case input_format_tcp_wire_format:
            send = &lines;
            if (perf_buffer_usedlength(send) > 1) {
                ((uint8_t*)perf_buffer_base(send))[0] = qid >> 8;
                ((uint8_t*)perf_buffer_base(send))[1] = qid;
            }
            result = PERF_R_SUCCESS;
            break;
        }
        if (result != PERF_R_SUCCESS) {
            PERF_LOCK(&tinfo->lock);
            query_move(tinfo, q, prepend_unused);
            PERF_UNLOCK(&tinfo->lock);
            now = perf_get_time();
            continue;
        }

        base   = perf_buffer_base(send);
        length = perf_buffer_usedlength(send);

        now = perf_get_time();
        if (config->verbose) {
            free(q->desc);
            if (config->input_format == input_format_tcp_wire_format) {
                q->desc = strdup("binary input");
            } else {
                q->desc = strdup(lines.base);
            }
            if (q->desc == NULL)
                perf_log_fatal("out of memory");
        }
        q->timestamp = now;

        n = perf_net_sendto(q->sock, qid, base, length, 0, &config->server_addr.sa.sa,
            config->server_addr.length);
        if (n < 0) {
            if (errno == EINPROGRESS) {
                if (config->verbose && !config->suppress.congestion) {
                    perf_log_warning("network congested, packet sending in progress");
                }
                any_inprogress = 1;
                bit_set(socketbits, sock);
            } else {
                if (config->verbose && !config->suppress.sendfailed) {
                    char __s[256];
                    perf_log_warning("failed to send packet: %s", perf_strerror_r(errno, __s, sizeof(__s)));
                }
                PERF_LOCK(&tinfo->lock);
                query_move(tinfo, q, prepend_unused);
                PERF_UNLOCK(&tinfo->lock);
                continue;
            }
        } else if ((unsigned int)n != length) {
            if (!config->suppress.sendfailed) {
                perf_log_warning("failed to send full packet: only sent %d of %u", n, length);
            }
            PERF_LOCK(&tinfo->lock);
            query_move(tinfo, q, prepend_unused);
            PERF_UNLOCK(&tinfo->lock);
            continue;
        }
        stats->num_sent++;
        q_sent++;

        stats->total_request_size += length;
    }

    while (any_inprogress) {
        any_inprogress = 0;
        for (i = 0; i < tinfo->nsocks; i++) {
            if (!perf_net_sockready(tinfo->socks[i], threadpipe[0], TIMEOUT_CHECK_TIME)) {
                any_inprogress = 1;
            }
        }
    }

    tinfo->done_send_time = perf_get_time();
    tinfo->done_sending   = true;
    if (write(mainpipe[1], "", 1)) { // lgtm [cpp/empty-block]
    }

    if (tsigkey) {
        perf_tsig_destroykey(&tsigkey);
    }
    return NULL;
}

static void
process_timeouts(threadinfo_t* tinfo, uint64_t now)
{
    struct query_info* q;
    const config_t*    config;

    config = tinfo->config;

    /* Avoid locking unless we need to. */
    q = perf_list_tail(tinfo->outstanding_queries);
    if (q == NULL || q->timestamp > now || now - q->timestamp < config->timeout)
        return;

    PERF_LOCK(&tinfo->lock);

    do {
        query_move(tinfo, q, append_unused);

        tinfo->stats.num_timedout++;

        if (!config->suppress.timeouts) {
            if (q->desc != NULL) {
                perf_log_printf("> T %s", q->desc);
            } else {
                perf_log_printf("[Timeout] %s timed out: msg id %u",
                    config->updates ? "Update" : "Query",
                    (unsigned int)(q - tinfo->queries));
            }
        }
        q = perf_list_tail(tinfo->outstanding_queries);
    } while (q != NULL && q->timestamp < now && now - q->timestamp >= config->timeout);

    PERF_UNLOCK(&tinfo->lock);
}

typedef struct {
    struct perf_net_socket* sock;
    uint16_t                qid;
    uint16_t                rcode;
    unsigned int            size;
    uint64_t                when;
    uint64_t                sent;
    bool                    unexpected;
    bool                    short_response;
    char*                   desc;
} received_query_t;

static bool
recv_one(threadinfo_t* tinfo, int which_sock,
    unsigned char* packet_buffer, unsigned int packet_size,
    received_query_t* recvd, int* saved_errnop)
{
    uint16_t* packet_header;
    uint64_t  now;
    int       n;

    packet_header = (uint16_t*)packet_buffer;

    n   = perf_net_recv(tinfo->socks[which_sock], packet_buffer, packet_size, 0);
    now = perf_get_time();
    if (n < 0) {
        *saved_errnop = errno;
        return false;
    }
    if (!n) {
        // Treat connection closed like try again until reconnection features are in
        if (!*saved_errnop) {
            // only set this if there was no error before to allow above error check to overwrite EAGAIN
            *saved_errnop = EAGAIN;
        }
        return false;
    }
    recvd->sock           = tinfo->socks[which_sock];
    recvd->qid            = ntohs(packet_header[0]);
    recvd->rcode          = ntohs(packet_header[1]) & 0xF;
    recvd->size           = n;
    recvd->when           = now;
    recvd->sent           = 0;
    recvd->unexpected     = false;
    recvd->short_response = (n < 4);
    recvd->desc           = NULL;
    return true;
}

static void*
do_recv(void* arg)
{
    threadinfo_t*    tinfo;
    stats_t*         stats;
    unsigned char    packet_buffer[MAX_EDNS_PACKET];
    received_query_t recvd[RECV_BATCH_SIZE] = { { 0, 0, 0, 0, 0, 0, false, false, 0 } };
    unsigned int     nrecvd;
    int              saved_errno;
    unsigned char    socketbits[(MAX_SOCKETS / 8) + 1];
    uint64_t         now, latency;
    query_info*      q;
    unsigned int     current_socket, last_socket;
    unsigned int     i, j;

    tinfo = (threadinfo_t*)arg;
    stats = &tinfo->stats;

    wait_for_start();
    now         = perf_get_time();
    last_socket = 0;
    while (!interrupted) {
        process_timeouts(tinfo, now);

        /*
         * If we're done sending and either all responses have been
         * received, stop.
         */
        if (tinfo->done_sending && num_outstanding(stats) == 0)
            break;

        /*
         * Try to receive a few packets, so that we can process them
         * atomically.
         */
        saved_errno = 0;
        memset(socketbits, 0, sizeof(socketbits));
        for (i = 0; i < RECV_BATCH_SIZE; i++) {
            for (j = 0; j < tinfo->nsocks; j++) {
                current_socket = (j + last_socket) % tinfo->nsocks;
                if (bit_check(socketbits, current_socket))
                    continue;
                if (recv_one(tinfo, current_socket, packet_buffer,
                        sizeof(packet_buffer), &recvd[i], &saved_errno)) {
                    last_socket = (current_socket + 1);
                    break;
                }
                bit_set(socketbits, current_socket);
            }
            if (j == tinfo->nsocks)
                break;
        }
        nrecvd = i;

        /* Do all of the processing that requires the lock */
        PERF_LOCK(&tinfo->lock);
        for (i = 0; i < nrecvd; i++) {
            if (recvd[i].short_response)
                continue;

            q = &tinfo->queries[recvd[i].qid];
            if (q->list != &tinfo->outstanding_queries || q->timestamp == UINT64_MAX || !perf_net_sockeq(q->sock, recvd[i].sock)) {
                recvd[i].unexpected = true;
                continue;
            }
            query_move(tinfo, q, append_unused);
            recvd[i].sent = q->timestamp;
            recvd[i].desc = q->desc;
            q->desc       = NULL;
        }
        PERF_SIGNAL(&tinfo->cond);
        PERF_UNLOCK(&tinfo->lock);

        /* Now do the rest of the processing unlocked */
        for (i = 0; i < nrecvd; i++) {
            if (recvd[i].short_response) {
                perf_log_warning("received short response");
                continue;
            }
            if (recvd[i].unexpected) {
                if (!tinfo->config->suppress.unexpected) {
                    perf_log_warning("received a response with an "
                                     "unexpected (maybe timed out) "
                                     "id: %u",
                        recvd[i].qid);
                }
                stats->num_unexpected++;
                continue;
            }
            latency = recvd[i].when - recvd[i].sent;
            if (recvd[i].desc != NULL) {
                perf_log_printf(
                    "> %s %s %u.%06u",
                    perf_dns_rcode_strings[recvd[i].rcode],
                    recvd[i].desc,
                    (unsigned int)(latency / MILLION),
                    (unsigned int)(latency % MILLION));
                free(recvd[i].desc);
            }

            stats->num_completed++;
            stats->total_response_size += recvd[i].size;
            stats->rcodecounts[recvd[i].rcode]++;
            stats->latency_sum += latency;
#ifdef USE_HISTOGRAMS
            if (stats->latency) {
                hg64_inc(stats->latency, latency);
            }
#endif
            stats->latency_sum_squares += (latency * latency);
            if (latency < stats->latency_min || stats->num_completed == 1)
                stats->latency_min = latency;
            if (latency > stats->latency_max)
                stats->latency_max = latency;
        }

        if (nrecvd > 0)
            tinfo->last_recv = recvd[nrecvd - 1].when;

        /*
         * If there was an error, handle it (by either ignoring it,
         * blocking, or exiting).
         */
        if (nrecvd < RECV_BATCH_SIZE) {
            if (saved_errno == EINTR) {
                continue;
            } else if (saved_errno == EAGAIN) {
                perf_os_waituntilanyreadable(tinfo->socks, tinfo->nsocks,
                    threadpipe[0], TIMEOUT_CHECK_TIME);
                now = perf_get_time();
                continue;
            } else {
                char __s[256];
                perf_log_fatal("failed to receive packet: %s", perf_strerror_r(saved_errno, __s, sizeof(__s)));
            }
        }
    }

    return NULL;
}

static void*
do_interval_stats(void* arg)
{
    threadinfo_t*          tinfo;
    stats_t                total = {};
    stats_t                last  = {};
    stats_t                diff  = {};
    uint64_t               now;
    uint64_t               last_interval_time;
    uint64_t               interval_time;
    double                 qps;
    struct perf_net_socket sock = { .mode = sock_pipe, .fd = threadpipe[0] };

    tinfo              = arg;
    last_interval_time = tinfo->times->start_time;

    wait_for_start();
    while (perf_os_waituntilreadable(&sock, threadpipe[0],
               tinfo->config->stats_interval)
           == PERF_R_TIMEDOUT) {
        now = perf_get_time();
        sum_stats(tinfo->config, &total);
        interval_time = now - last_interval_time;

        if (tinfo->config->verbose_interval_stats) {
            diff_stats(tinfo->config, &last, &total, &diff);
            print_statistics(tinfo->config, tinfo->times, &diff, now, interval_time);
        } else {
            qps = (total.num_completed - last.num_completed) / (((double)interval_time) / MILLION);
            perf_log_printf("%u.%06u: %.6lf",
                (unsigned int)(now / MILLION),
                (unsigned int)(now % MILLION), qps);
        }

        last_interval_time = now;
#ifdef USE_HISTOGRAMS
        free(last.latency);
        free(last.conn_latency);
#endif
        last = total;
    }

    return NULL;
}

static void
cancel_queries(threadinfo_t* tinfo)
{
    struct query_info* q;

    while (true) {
        q = perf_list_tail(tinfo->outstanding_queries);
        if (q == NULL)
            break;
        query_move(tinfo, q, append_unused);

        if (q->timestamp == UINT64_MAX)
            continue;

        tinfo->stats.num_interrupted++;
        if (q->desc != NULL) {
            perf_log_printf("> I %s", q->desc);
            free(q->desc);
            q->desc = NULL;
        }
    }
}

static uint32_t
per_thread(uint32_t total, uint32_t nthreads, unsigned int offset)
{
    uint32_t value, temp_total;

    value = total / nthreads;

    /*
     * work out if there's a shortfall and adjust if necessary
     */
    temp_total = value * nthreads;
    if (temp_total < total && offset < total - temp_total)
        value++;

    return value;
}

static void perf__net_sent(struct perf_net_socket* sock, uint16_t qid)
{
    threadinfo_t* tinfo = (threadinfo_t*)sock->data;
    query_info*   q;

    q = &tinfo->queries[qid];
    if (q->timestamp != UINT64_MAX) {
        q->timestamp = perf_get_time();
    }
}

static void perf__net_event(struct perf_net_socket* sock, perf_socket_event_t event, uint64_t elapsed_time)
{
    stats_t* stats = &((threadinfo_t*)sock->data)->stats;

    switch (event) {
    case perf_socket_event_reconnected:
    case perf_socket_event_connected:
        stats->num_conn_completed++;

#ifdef USE_HISTOGRAMS
        if (stats->conn_latency) {
            hg64_inc(stats->conn_latency, elapsed_time);
        }
#endif
        stats->conn_latency_sum += elapsed_time;
        stats->conn_latency_sum_squares += (elapsed_time * elapsed_time);
        if (elapsed_time < stats->conn_latency_min || stats->num_conn_completed == 1)
            stats->conn_latency_min = elapsed_time;
        if (elapsed_time > stats->conn_latency_max)
            stats->conn_latency_max = elapsed_time;
        break;

    case perf_socket_event_reconnecting:
    case perf_socket_event_connecting:
        stats->num_conn_attempts++;
        break;

    default:
        break;
    }
}

static void
threadinfo_init(threadinfo_t* tinfo, const config_t* config,
    const times_t* times, int idx)
{
    unsigned int offset, socket_offset, i;

    memset(tinfo, 0, sizeof(*tinfo));
    PERF_MUTEX_INIT(&tinfo->lock);
    PERF_COND_INIT(&tinfo->cond);

    perf_list_init(tinfo->outstanding_queries);
    perf_list_init(tinfo->unused_queries);
#ifdef USE_HISTOGRAMS
    if (config->latency_histogram) {
        tinfo->stats.latency      = hg64_create(HISTOGRAM_SIGBITS);
        tinfo->stats.conn_latency = hg64_create(HISTOGRAM_SIGBITS);
    }
#endif
    for (i = 0; i < NQIDS; i++) {
        perf_link_init(&tinfo->queries[i]);
        perf_list_append(tinfo->unused_queries, &tinfo->queries[i]);
        tinfo->queries[i].list = &tinfo->unused_queries;
    }

    offset = tinfo - threads;

    tinfo->config = config;
    tinfo->times  = times;

    /*
     * Compute per-thread limits based on global values.
     */
    tinfo->max_outstanding = per_thread(config->max_outstanding,
        config->threads, offset);
    tinfo->max_qps         = per_thread(config->max_qps, config->threads, offset);
    tinfo->nsocks          = per_thread(config->clients, config->threads, offset);

    /*
     * We can't have more than 64k outstanding queries per thread.
     */
    if (tinfo->max_outstanding > NQIDS) {
        perf_log_warning("requested number of outstanding queries (-q %u) per single thread (-T) exceeds built-in maximum %u, adjusting\n", tinfo->max_outstanding, NQIDS);
        tinfo->max_outstanding = NQIDS;
    }

    if (tinfo->nsocks > MAX_SOCKETS) {
        perf_log_warning("requested number of clients (-c %u) per thread (-T) exceeds built-in maximum %u, adjusting\n", tinfo->nsocks, MAX_SOCKETS);
        tinfo->nsocks = MAX_SOCKETS;
    }

    if (!(tinfo->socks = calloc(tinfo->nsocks, sizeof(*tinfo->socks)))) {
        perf_log_fatal("out of memory");
    }
    socket_offset = 0;
    for (i = 0; i < offset; i++)
        socket_offset += threads[i].nsocks;
    for (i = 0; i < tinfo->nsocks; i++) {
        tinfo->socks[i] = perf_net_opensocket(config->mode, &config->server_addr,
            &config->local_addr,
            socket_offset++,
            config->bufsize,
            tinfo, perf__net_sent, perf__net_event);
        if (!tinfo->socks[i]) {
            perf_log_fatal("perf_net_opensocket(): no socket returned, out of memory?");
        }
        if (config->num_queries_per_conn && tinfo->socks[i]->num_queries_per_conn) {
            tinfo->socks[i]->num_queries_per_conn(tinfo->socks[i], config->num_queries_per_conn, config->timeout);
        }
    }
    tinfo->current_sock = 0;

    char name[16]; // glibc is limited to 16 characters
    PERF_THREAD(&tinfo->receiver, do_recv, tinfo);
    snprintf(name, sizeof(name), "perf-recv-%04d", idx);
    perf_os_thread_setname(tinfo->receiver, name);
    PERF_THREAD(&tinfo->sender, do_send, tinfo);
    snprintf(name, sizeof(name), "perf-send-%04d", idx);
    perf_os_thread_setname(tinfo->sender, name);
}

static void
threadinfo_stop(threadinfo_t* tinfo)
{
    PERF_SIGNAL(&tinfo->cond);
    PERF_JOIN(tinfo->sender, NULL);
    PERF_JOIN(tinfo->receiver, NULL);
}

static void
threadinfo_cleanup(config_t* config, threadinfo_t* tinfo, times_t* times)
{
    unsigned int i;

    if (interrupted)
        cancel_queries(tinfo);
    for (i = 0; i < tinfo->nsocks; i++) {
        perf_net_stats_compile(config->mode, tinfo->socks[i]);
        perf_net_close(tinfo->socks[i]);
    }
    if (tinfo->last_recv > times->end_time)
        times->end_time = tinfo->last_recv;
}

int main(int argc, char** argv)
{
    config_t               config;
    times_t                times;
    stats_t                total_stats;
    threadinfo_t           stats_thread;
    unsigned int           i;
    perf_result_t          result;
    struct perf_net_socket sock = { .mode = sock_pipe };

    printf("DNS Performance Testing Tool\n"
           "Version " PACKAGE_VERSION "\n\n");

    (void)SSL_library_init();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_load_error_strings();
    OPENSSL_config(0);
#endif

    setup(argc, argv, &config);

    if (pipe(threadpipe) < 0 || pipe(mainpipe) < 0 || pipe(intrpipe) < 0)
        perf_log_fatal("creating pipe");

    perf_datafile_setpipefd(input, threadpipe[0]);

    perf_os_blocksignal(SIGINT, true);
    switch (config.mode) {
    case sock_tcp:
    case sock_dot:
    case sock_doh:
        // block SIGPIPE for TCP/DOT mode, if connection is closed it will generate a signal
        perf_os_blocksignal(SIGPIPE, true);
        break;
    default:
        break;
    }

    print_initial_status(&config);

    if (!(threads = calloc(config.threads, sizeof(threadinfo_t)))) {
        perf_log_fatal("out of memory");
    }
    for (i = 0; i < config.threads; i++)
        threadinfo_init(&threads[i], &config, &times, i);
    if (config.stats_interval > 0) {
        stats_thread.config = &config;
        stats_thread.times  = &times;
        PERF_THREAD(&stats_thread.sender, do_interval_stats, &stats_thread);
    }

    times.start_time = perf_get_time();
    if (config.timelimit > 0)
        times.stop_time = times.start_time + config.timelimit;
    else
        times.stop_time = UINT64_MAX;
    times.stop_time_ns.tv_sec  = times.stop_time / MILLION;
    times.stop_time_ns.tv_nsec = (times.stop_time % MILLION) * 1000;

    PERF_LOCK(&start_lock);
    started = true;
    PERF_BROADCAST(&start_cond);
    PERF_UNLOCK(&start_lock);

    perf_os_handlesignal(SIGINT, handle_sigint);
    perf_os_blocksignal(SIGINT, false);
    sock.fd = mainpipe[0];
    result  = perf_os_waituntilreadable(&sock, intrpipe[0], times.stop_time - times.start_time);
    if (result == PERF_R_CANCELED)
        interrupted = true;

    times.end_time = perf_get_time();

    if (write(threadpipe[1], "", 1)) { // lgtm [cpp/empty-block]
    }
    for (i = 0; i < config.threads; i++)
        threadinfo_stop(&threads[i]);
    if (config.stats_interval > 0)
        PERF_JOIN(stats_thread.sender, NULL);

    perf_net_stats_init(config.mode);

    for (i = 0; i < config.threads; i++)
        threadinfo_cleanup(&config, &threads[i], &times);

    print_final_status(&config);

    sum_stats(&config, &total_stats);
    print_statistics(&config, &times, &total_stats, 0, 0);
    perf_net_stats_print(config.mode);

    cleanup(&config);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_free_strings();
#endif

    return (0);
}
