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
 ***	DNS Resolution Performance Testing Tool
 ***/

#include "config.h"

#include "datafile.h"
#include "dns.h"
#include "log.h"
#include "net.h"
#include "opt.h"
#include "util.h"
#include "os.h"
#include "list.h"
#include "result.h"
#include "buffer.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <signal.h>

/*
 * Global stuff
 */

#define DEFAULT_SERVER_NAME "127.0.0.1"
#define DEFAULT_SERVER_PORT 53
#define DEFAULT_SERVER_DOT_PORT 853
#define DEFAULT_SERVER_DOH_PORT 443
#define DEFAULT_SERVER_PORTS "udp/tcp 53, DoT 853 or DoH 443"
#define DEFAULT_LOCAL_PORT 0
#define DEFAULT_SOCKET_BUFFER 32
#define DEFAULT_TIMEOUT 45
#define DEFAULT_MAX_OUTSTANDING (64 * 1024)
#define DEFAULT_MAX_FALL_BEHIND 1000

#define MAX_INPUT_DATA (64 * 1024) + 2

#define TIMEOUT_CHECK_TIME 5000000

#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_NXDOMAIN 3

struct query_info;

typedef perf_list(struct query_info) query_list;

typedef struct query_info {
    uint64_t sent_timestamp;
    bool     is_inprogress;

    /*
     * This link links the query into the list of outstanding
     * queries or the list of available query IDs.
     */
    perf_link(struct query_info);
    /*
     * The list this query is on.
     */
    query_list* list;
} query_info;

static query_list outstanding_list;
static query_list instanding_list;

static query_info* queries;

static perf_sockaddr_t          server_addr;
static perf_sockaddr_t          local_addr;
static unsigned int             nsocks;
static struct perf_net_socket** socks;
static enum perf_net_mode       mode;

static int dummypipe[2];

static uint64_t query_timeout;
static bool     edns;
static bool     dnssec;

static perf_ednsoption_t* edns_option = 0;

static perf_datafile_t* input;

/* The target traffic level at the end of the ramp-up */
double max_qps = 100000.0;

/* The time period over which we ramp up traffic */
#define DEFAULT_RAMP_TIME 60
static uint64_t ramp_time;

/* How long to send constant traffic after the initial ramp-up */
#define DEFAULT_SUSTAIN_TIME 0
static uint64_t sustain_time;

/* How long to wait for responses after sending traffic */
static uint64_t wait_time = 40 * MILLION;

/* Total duration of the traffic-sending part of the test */
static uint64_t traffic_time;

/* Total duration of the test */
static uint64_t end_time;

/* Interval between plot data points, in microseconds */
#define DEFAULT_BUCKET_INTERVAL 0.5
static uint64_t bucket_interval;

/* The number of plot data points */
static int n_buckets;

/* The plot data file */
static const char* plotfile = "resperf.gnuplot";

/* The largest acceptable query loss when reporting max throughput */
static double max_loss_percent = 100.0;

/* The maximum number of outstanding queries */
static unsigned int max_outstanding;

static uint64_t num_queries_sent;
static uint64_t num_queries_outstanding;
static uint64_t num_responses_received;
static uint64_t num_queries_timed_out;
static uint64_t rcodecounts[16];
static uint64_t num_conn_completed;
static uint64_t num_conn_attempts;
static uint64_t num_response_unexpected;

static uint64_t time_now;
static uint64_t time_of_program_start;
static uint64_t time_of_end_of_run;

/*
 * The last plot data point containing actual data; this can
 * be less than than (n_buckets - 1) if the traffic sending
 * phase is cut short
 */
static int last_bucket_used;

/*
 * The statistics for queries sent during one bucket_interval
 * of the traffic sending phase.
 */
typedef struct {
    int    queries;
    int    responses;
    int    failures;
    double latency_sum;

    int    connections;
    double conn_latency_sum;
} ramp_bucket;

/* Pointer to array of n_buckets ramp_bucket structures */
static ramp_bucket* buckets;

enum phase {
    /*
     * The ramp-up phase: we are steadily increasing traffic.
     */
    PHASE_RAMP,
    /*
     * The sustain phase: we are sending traffic at a constant
     * rate.
     */
    PHASE_SUSTAIN,
    /*
     * The wait phase: we have stopped sending queries and are
     * just waiting for any remaining responses.
     */
    PHASE_WAIT
};
static enum phase phase = PHASE_RAMP;

/* The time when the sustain/wait phase began */
static uint64_t sustain_phase_began, wait_phase_began;

static perf_tsigkey_t* tsigkey;

static bool         verbose;
static unsigned int max_fall_behind;

static perf_suppress_t suppress;

const char* progname = "resperf";

static char*
stringify(double value, int precision)
{
    static char buf[20];

    snprintf(buf, sizeof(buf), "%.*f", precision, value);
    return buf;
}

static void perf__net_event(struct perf_net_socket* sock, perf_socket_event_t event, uint64_t elapsed_time);
static void perf__net_sent(struct perf_net_socket* sock, uint16_t qid);

static ramp_bucket* init_buckets(int n)
{
    ramp_bucket* p;
    int          i;

    if (!(p = calloc(n, sizeof(*p)))) {
        perf_log_fatal("out of memory");
        return 0; // fix clang scan-build
    }
    for (i = 0; i < n; i++) {
        p[i].queries = p[i].responses = p[i].failures = 0;
        p[i].latency_sum                              = 0.0;
    }
    return p;
}

static void setup(int argc, char** argv)
{
    const char*  family      = NULL;
    const char*  server_name = DEFAULT_SERVER_NAME;
    in_port_t    server_port = 0;
    const char*  local_name  = NULL;
    in_port_t    local_port  = DEFAULT_LOCAL_PORT;
    const char*  filename    = NULL;
    const char*  tsigkey_str = NULL;
    int          sock_family;
    unsigned int bufsize;
    unsigned int i;
    const char*  _mode           = 0;
    const char*  edns_option_str = NULL;
    const char*  doh_uri         = DEFAULT_DOH_URI;
    const char*  doh_method      = DEFAULT_DOH_METHOD;
    const char*  tls_sni         = 0;
    const char*  local_suppress  = 0;

    size_t num_queries_per_conn = 0;

    sock_family     = AF_UNSPEC;
    server_port     = 0;
    local_port      = DEFAULT_LOCAL_PORT;
    bufsize         = DEFAULT_SOCKET_BUFFER;
    query_timeout   = DEFAULT_TIMEOUT * MILLION;
    ramp_time       = DEFAULT_RAMP_TIME * MILLION;
    sustain_time    = DEFAULT_SUSTAIN_TIME * MILLION;
    bucket_interval = DEFAULT_BUCKET_INTERVAL * MILLION;
    max_outstanding = DEFAULT_MAX_OUTSTANDING;
    nsocks          = 1;
    mode            = sock_udp;
    verbose         = false;
    max_fall_behind = DEFAULT_MAX_FALL_BEHIND;

    perf_opt_add('f', perf_opt_string, "family",
        "address family of DNS transport, inet or inet6", "any",
        &family);
    perf_opt_add('M', perf_opt_string, "mode", "set transport mode: udp, tcp, dot or doh", "udp", &_mode);
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
        stringify(DEFAULT_LOCAL_PORT, 0), &local_port);
    perf_opt_add('d', perf_opt_string, "datafile",
        "the input data file", "stdin", &filename);
    perf_opt_add('t', perf_opt_timeval, "timeout",
        "the timeout for query completion in seconds",
        stringify(DEFAULT_TIMEOUT, 0), &query_timeout);
    perf_opt_add('b', perf_opt_uint, "buffer_size",
        "socket send/receive buffer size in kilobytes", NULL,
        &bufsize);
    perf_opt_add('e', perf_opt_boolean, NULL,
        "enable EDNS 0", NULL, &edns);
    perf_opt_add('E', perf_opt_string, "code:value",
        "send EDNS option", NULL, &edns_option_str);
    perf_opt_add('D', perf_opt_boolean, NULL,
        "set the DNSSEC OK bit (implies EDNS)", NULL, &dnssec);
    perf_opt_add('y', perf_opt_string, "[alg:]name:secret",
        "the TSIG algorithm, name and secret", NULL, &tsigkey_str);
    perf_opt_add('i', perf_opt_timeval, "plot_interval",
        "the time interval between plot data points, in seconds",
        stringify(DEFAULT_BUCKET_INTERVAL, 1), &bucket_interval);
    perf_opt_add('m', perf_opt_double, "max_qps",
        "the maximum number of queries per second",
        stringify(max_qps, 0), &max_qps);
    perf_opt_add('P', perf_opt_string, "plotfile",
        "the name of the plot data file", plotfile, &plotfile);
    perf_opt_add('r', perf_opt_timeval, "ramp_time",
        "the ramp-up time in seconds",
        stringify(DEFAULT_RAMP_TIME, 0), &ramp_time);
    perf_opt_add('c', perf_opt_timeval, "constant_traffic_time",
        "how long to send constant traffic, in seconds",
        stringify(DEFAULT_SUSTAIN_TIME, 0), &sustain_time);
    perf_opt_add('L', perf_opt_double, "max_query_loss",
        "the maximum acceptable query loss, in percent",
        stringify(max_loss_percent, 0), &max_loss_percent);
    perf_opt_add('C', perf_opt_uint, "clients",
        "the number of clients to act as", stringify(1, 0), &nsocks);
    perf_opt_add('q', perf_opt_uint, "num_outstanding",
        "the maximum number of queries outstanding",
        stringify(DEFAULT_MAX_OUTSTANDING, 0), &max_outstanding);
    perf_opt_add('v', perf_opt_boolean, NULL,
        "verbose: report additional information to stdout",
        NULL, &verbose);
    bool log_stdout = false;
    perf_opt_add('W', perf_opt_boolean, NULL, "log warnings and errors to stdout instead of stderr", NULL, &log_stdout);
    bool reopen_datafile = false;
    perf_opt_add('R', perf_opt_boolean, NULL, "reopen datafile on end, allow for infinit use of it", NULL, &reopen_datafile);
    perf_opt_add('F', perf_opt_zpint, "fall_behind", "the maximum number of queries that is allowed to fall behind, zero to disable",
        stringify(DEFAULT_MAX_FALL_BEHIND, 0), &max_fall_behind);
    perf_long_opt_add("doh-uri", perf_opt_string, "doh_uri",
        "the URI to use for DNS-over-HTTPS", DEFAULT_DOH_URI, &doh_uri);
    perf_long_opt_add("doh-method", perf_opt_string, "doh_method",
        "the HTTP method to use for DNS-over-HTTPS: GET or POST", DEFAULT_DOH_METHOD, &doh_method);
    perf_long_opt_add("tls-sni", perf_opt_string, "tls_sni",
        "the TLS SNI to use for TLS connections", NULL, &tls_sni);
    perf_long_opt_add("suppress", perf_opt_string, "message[,message,...]",
        "suppress messages/warnings, see dnsperf(1) man-page for list of message types", NULL, &local_suppress);
    perf_long_opt_add("num-queries-per-conn", perf_opt_uint, "queries",
        "Number of queries to send per connection", NULL, &num_queries_per_conn);

    perf_opt_parse(argc, argv);

    if (log_stdout) {
        perf_log_tostdout();
    }

    suppress = perf_opt_parse_suppress(local_suppress);

    if (_mode != 0)
        mode = perf_net_parsemode(_mode);

    if (!server_port) {
        switch (mode) {
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
    perf_net_doh_set_max_concurrent_streams(max_outstanding);

    if (max_outstanding > nsocks * DEFAULT_MAX_OUTSTANDING)
        perf_log_fatal("number of outstanding packets (%u) must not "
                       "be more than 64K per client",
            max_outstanding);

    if (ramp_time + sustain_time == 0)
        perf_log_fatal("rampup_time and constant_traffic_time must not "
                       "both be 0");

    perf_list_init(outstanding_list);
    perf_list_init(instanding_list);
    if (!(queries = calloc(max_outstanding, sizeof(query_info)))) {
        perf_log_fatal("out of memory");
    }
    for (i = 0; i < max_outstanding; i++) {
        perf_link_init(&queries[i]);
        perf_list_append(instanding_list, &queries[i]);
        queries[i].list = &instanding_list;
    }

    if (family != NULL)
        sock_family = perf_net_parsefamily(family);
    perf_net_parseserver(sock_family, server_name, server_port, &server_addr);
    perf_net_parselocal(server_addr.sa.sa.sa_family, local_name,
        local_port, &local_addr);

    input = perf_datafile_open(filename, input_format_text_query);
    if (reopen_datafile) {
        perf_datafile_setmaxruns(input, -1);
    }

    if (dnssec || edns_option_str)
        edns = true;

    if (tsigkey_str != NULL)
        tsigkey = perf_tsig_parsekey(tsigkey_str);

    if (edns_option_str != NULL)
        edns_option = perf_edns_parseoption(edns_option_str);

    traffic_time = ramp_time + sustain_time;
    end_time     = traffic_time + wait_time;

    n_buckets = (traffic_time + bucket_interval - 1) / bucket_interval;
    buckets   = init_buckets(n_buckets);

    time_now              = perf_get_time();
    time_of_program_start = time_now;

    if (!(socks = calloc(nsocks, sizeof(*socks)))) {
        perf_log_fatal("out of memory");
    }
    for (i = 0; i < nsocks; i++) {
        socks[i] = perf_net_opensocket(mode, &server_addr, &local_addr, i, bufsize, (void*)(intptr_t)i, perf__net_sent, perf__net_event);
        if (!socks[i]) {
            perf_log_fatal("perf_net_opensocket(): no socket returned, out of memory?");
        }
        if (num_queries_per_conn && socks[i]->num_queries_per_conn) {
            socks[i]->num_queries_per_conn(socks[i], num_queries_per_conn, query_timeout);
        }
    }
}

static void
cleanup(void)
{
    unsigned int i;

    perf_datafile_close(&input);
    for (i = 0; i < nsocks; i++) {
        perf_net_stats_compile(mode, socks[i]);
        (void)perf_net_close(socks[i]);
    }
    close(dummypipe[0]);
    close(dummypipe[1]);

    if (edns_option)
        perf_edns_destroyoption(&edns_option);
}

/* Find the ramp_bucket for queries sent at time "when" */

static ramp_bucket*
find_bucket(uint64_t when)
{
    uint64_t sent_at = when - time_of_program_start;
    int      i       = (int)((n_buckets * sent_at) / traffic_time);
    /*
     * Guard against array bounds violations due to roundoff
     * errors or scheduling jitter
     */
    if (i < 0)
        i = 0;
    if (i > n_buckets - 1)
        i = n_buckets - 1;
    return &buckets[i];
}

static void perf__net_event(struct perf_net_socket* sock, perf_socket_event_t event, uint64_t elapsed_time)
{
    ramp_bucket* b = find_bucket(time_now);

    switch (event) {
    case perf_socket_event_reconnected:
    case perf_socket_event_connected:
        b->connections++;
        b->conn_latency_sum += elapsed_time / (double)MILLION;
        num_conn_completed++;
        break;

    case perf_socket_event_reconnecting:
    case perf_socket_event_connecting:
        num_conn_attempts++;
        break;

    default:
        break;
    }
}

static void perf__net_sent(struct perf_net_socket* sock, uint16_t qid)
{
    ramp_bucket* b = find_bucket(time_now);

    b->queries++;

    size_t idx = (size_t)qid * nsocks + (intptr_t)sock->data;
    assert(idx < max_outstanding);
    queries[idx].sent_timestamp = time_now;
}

/*
 * print_statistics:
 *   Print out statistics based on the results of the test
 */
static void
print_statistics(void)
{
    int      i;
    double   max_throughput;
    double   loss_at_max_throughput;
    bool     first_rcode;
    uint64_t run_time = time_of_end_of_run - time_of_program_start;

    printf("\nStatistics:\n\n");

    printf("  Queries sent:         %" PRIu64 "\n",
        num_queries_sent);
    printf("  Queries completed:    %" PRIu64 "\n",
        num_responses_received);
    printf("  Queries lost:         %" PRIu64 "\n",
        num_queries_sent - num_responses_received);
    if (num_response_unexpected > 0)
        printf("  Unexpected IDs:       %" PRIu64 "\n",
            num_response_unexpected);
    printf("  Response codes:       ");
    first_rcode = true;
    for (i = 0; i < 16; i++) {
        if (rcodecounts[i] == 0)
            continue;
        if (first_rcode)
            first_rcode = false;
        else
            printf(", ");
        printf("%s %" PRIu64 " (%.2lf%%)",
            perf_dns_rcode_strings[i], rcodecounts[i],
            (rcodecounts[i] * 100.0) / num_responses_received);
    }
    printf("\n\n");
    printf("  Run time (s):         %u.%06u\n",
        (unsigned int)(run_time / MILLION),
        (unsigned int)(run_time % MILLION));

    /* Find the maximum throughput, subject to the -L option */
    max_throughput         = 0.0;
    loss_at_max_throughput = 0.0;
    for (i = 0; i <= last_bucket_used; i++) {
        ramp_bucket* b                 = &buckets[i];
        double       responses_per_sec = b->responses / (bucket_interval / (double)MILLION);
        double       loss              = b->queries ? (b->queries - b->responses) / (double)b->queries : 0.0;
        double       loss_percent      = loss * 100.0;
        if (loss_percent > max_loss_percent)
            break;
        if (responses_per_sec > max_throughput) {
            max_throughput         = responses_per_sec;
            loss_at_max_throughput = loss_percent;
        }
    }
    printf("  Maximum throughput:   %.6lf qps\n", max_throughput);
    printf("  Lost at that point:   %.2f%%\n", loss_at_max_throughput);
    printf("\n");
    printf("  Connection attempts:  %" PRIu64 " (%" PRIu64 " successful, %.2lf%%)\n\n",
        num_conn_attempts,
        num_conn_completed,
        PERF_SAFE_DIV(100.0 * num_conn_completed, num_conn_attempts));
}

/*
 * Send a query based on a line of input.
 * Return PERF_R_NOMORE if we ran out of query IDs.
 */
static perf_result_t
do_one_line(perf_buffer_t* lines, perf_buffer_t* msg)
{
    query_info*    q;
    unsigned int   qid;
    unsigned int   sock;
    perf_region_t  used;
    unsigned char* base;
    unsigned int   length;
    perf_result_t  result;

    q = perf_list_head(instanding_list);
    if (!q)
        return (PERF_R_NOMORE);
    qid  = (q - queries) / nsocks;
    sock = (q - queries) % nsocks;

    while (q->is_inprogress) {
        if (perf_net_sockready(socks[sock], dummypipe[0], TIMEOUT_CHECK_TIME) == -1) {
            if (errno == EINPROGRESS) {
                if (verbose && !suppress.congestion) {
                    perf_log_warning("network congested, packet sending in progress");
                }
            } else {
                if (verbose && !suppress.sockready) {
                    char __s[256];
                    perf_log_warning("failed to check socket readiness: %s", perf_strerror_r(errno, __s, sizeof(__s)));
                }
            }
            return (PERF_R_FAILURE);
        }

        q->is_inprogress = false;
        perf_list_unlink(instanding_list, q);
        perf_list_prepend(outstanding_list, q);
        q->list = &outstanding_list;

        num_queries_sent++;
        num_queries_outstanding++;

        q = perf_list_head(instanding_list);
        if (!q)
            return (PERF_R_NOMORE);
        qid  = (q - queries) / nsocks;
        sock = (q - queries) % nsocks;
    }

    switch (perf_net_sockready(socks[sock], dummypipe[0], TIMEOUT_CHECK_TIME)) {
    case 0:
        if (verbose && !suppress.sockready) {
            perf_log_warning("failed to send packet: socket %d not ready", sock);
        }
        return (PERF_R_FAILURE);
    case -1:
        if (errno == EINPROGRESS) {
            if (verbose && !suppress.congestion) {
                perf_log_warning("network congested, packet sending in progress");
            }
        } else if (!suppress.sockready) {
            perf_log_warning("failed to send packet: socket %d not ready", sock);
        }
        return (PERF_R_FAILURE);
    default:
        break;
    }

    perf_buffer_clear(lines);
    result = perf_datafile_next(input, lines);
    if (result != PERF_R_SUCCESS)
        perf_log_fatal("ran out of query data");
    perf_buffer_usedregion(lines, &used);

    perf_buffer_clear(msg);
    result = perf_dns_buildrequest(&used, qid,
        edns, dnssec, false,
        tsigkey, edns_option,
        msg);
    if (result != PERF_R_SUCCESS)
        return (result);

    q->sent_timestamp = time_now;

    base   = perf_buffer_base(msg);
    length = perf_buffer_usedlength(msg);
    if (perf_net_sendto(socks[sock], qid, base, length, 0,
            &server_addr.sa.sa, server_addr.length)
        < 1) {
        if (errno == EINPROGRESS) {
            if (verbose && !suppress.congestion) {
                perf_log_warning("network congested, packet sending in progress");
            }
            q->is_inprogress = true;
        } else {
            if (verbose && !suppress.sendfailed) {
                char __s[256];
                perf_log_warning("failed to send packet: %s", perf_strerror_r(errno, __s, sizeof(__s)));
            }
        }
        return (PERF_R_FAILURE);
    }

    perf_list_unlink(instanding_list, q);
    perf_list_prepend(outstanding_list, q);
    q->list = &outstanding_list;

    num_queries_sent++;
    num_queries_outstanding++;

    return PERF_R_SUCCESS;
}

static void
enter_sustain_phase(void)
{
    phase = PHASE_SUSTAIN;
    if (sustain_time != 0.0)
        printf("[Status] Ramp-up done, sending constant traffic\n");
    sustain_phase_began = time_now;
}

static void
enter_wait_phase(void)
{
    phase = PHASE_WAIT;
    printf("[Status] Waiting for more responses\n");
    wait_phase_began = time_now;
}

/*
 * try_process_response:
 *
 *   Receive from the given socket & process an individual response packet.
 *   Remove it from the list of open queries (status[]) and decrement the
 *   number of outstanding queries if it matches an open query.
 */
static void
try_process_response(unsigned int sockindex)
{
    unsigned char packet_buffer[MAX_EDNS_PACKET];
    uint16_t*     packet_header;
    uint16_t      qid, rcode;
    query_info*   q;
    double        latency;
    ramp_bucket*  b;
    int           n;

    if (perf_net_sockready(socks[sockindex], dummypipe[0], TIMEOUT_CHECK_TIME) == -1) {
        if (errno != EINPROGRESS) {
            if (verbose && !suppress.sockready) {
                char __s[256];
                perf_log_warning("failed to check socket readiness: %s", perf_strerror_r(errno, __s, sizeof(__s)));
            }
        }
    }

    packet_header = (uint16_t*)packet_buffer;
    n             = perf_net_recv(socks[sockindex], packet_buffer, sizeof(packet_buffer), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return;
        } else {
            char __s[256];
            perf_log_fatal("failed to receive packet: %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
    } else if (!n) {
        // Treat connection closed like try again until reconnection features are in
        return;
    } else if (n < 4) {
        perf_log_warning("received short response");
        return;
    }

    qid   = ntohs(packet_header[0]);
    rcode = ntohs(packet_header[1]) & 0xF;

    size_t idx = qid * nsocks + sockindex;
    if (idx >= max_outstanding || queries[idx].list != &outstanding_list) {
        if (!suppress.unexpected) {
            perf_log_warning("received a response with an unexpected id: %u", qid);
        }
        num_response_unexpected++;
        return;
    }
    q = &queries[idx];

    perf_list_unlink(outstanding_list, q);
    perf_list_append(instanding_list, q);
    q->list = &instanding_list;

    num_queries_outstanding--;

    latency = (time_now - q->sent_timestamp) / (double)MILLION;
    b       = find_bucket(q->sent_timestamp);
    b->responses++;
    if (!(rcode == DNS_RCODE_NOERROR || rcode == DNS_RCODE_NXDOMAIN))
        b->failures++;
    b->latency_sum += latency;
    num_responses_received++;
    rcodecounts[rcode]++;
}

static void
retire_old_queries(void)
{
    query_info* q;

    while (true) {
        q = perf_list_tail(outstanding_list);
        if (q == NULL || (time_now - q->sent_timestamp) < query_timeout)
            break;
        perf_list_unlink(outstanding_list, q);
        perf_list_append(instanding_list, q);
        q->list = &instanding_list;

        num_queries_outstanding--;
        num_queries_timed_out++;
    }
}

static inline int
num_scheduled(uint64_t time_since_start)
{
    if (phase == PHASE_RAMP) {
        return 0.5 * max_qps * (double)time_since_start * time_since_start / (ramp_time * MILLION);
    } else { /* PHASE_SUSTAIN */
        return 0.5 * max_qps * (ramp_time / (double)MILLION) + max_qps * (time_since_start - ramp_time) / (double)MILLION;
    }
}

int main(int argc, char** argv)
{
    int           i;
    FILE*         plotf;
    perf_buffer_t lines, msg;
    char          input_data[MAX_INPUT_DATA];
    unsigned char outpacket_buffer[MAX_EDNS_PACKET];
    unsigned int  max_packet_size;
    unsigned int  current_sock;
    perf_result_t result;

    printf("DNS Resolution Performance Testing Tool\n"
           "Version " PACKAGE_VERSION "\n\n");

    (void)SSL_library_init();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_load_error_strings();
    OPENSSL_config(0);
#endif

    setup(argc, argv);

    if (pipe(dummypipe) < 0)
        perf_log_fatal("creating pipe");

    switch (mode) {
    case sock_tcp:
    case sock_dot:
    case sock_doh:
        // block SIGPIPE for TCP/DOT mode, if connection is closed it will generate a signal
        perf_os_blocksignal(SIGPIPE, true);
        break;
    default:
        break;
    }

    perf_buffer_init(&lines, input_data, sizeof(input_data));

    max_packet_size = edns ? MAX_EDNS_PACKET : MAX_UDP_PACKET;
    perf_buffer_init(&msg, outpacket_buffer, max_packet_size);

    printf("[Status] Command line: %s", progname);
    for (i = 1; i < argc; i++) {
        printf(" %s", argv[i]);
    }
    printf("\n");

    printf("[Status] Sending\n");

    int try_responses = (max_qps / max_outstanding) + 1;
    current_sock      = 0;
    for (;;) {
        int      should_send;
        uint64_t time_since_start = time_now - time_of_program_start;
        switch (phase) {
        case PHASE_RAMP:
            if (time_since_start >= ramp_time)
                enter_sustain_phase();
            break;
        case PHASE_SUSTAIN:
            if (time_since_start >= traffic_time)
                enter_wait_phase();
            break;
        case PHASE_WAIT:
            if (time_since_start >= end_time || perf_list_empty(outstanding_list))
                goto end_loop;
            break;
        }
        if (phase != PHASE_WAIT) {
            should_send = num_scheduled(time_since_start) - num_queries_sent;
            if (max_fall_behind && should_send >= max_fall_behind) {
                printf("[Status] Fell behind by %d queries, "
                       "ending test at %.0f qps\n",
                    should_send, (max_qps * time_since_start) / ramp_time);
                enter_wait_phase();
            }
            if (should_send > 0) {
                result = do_one_line(&lines, &msg);
                if (result == PERF_R_SUCCESS)
                    find_bucket(time_now)->queries++;
                if (result == PERF_R_NOMORE) {
                    printf("[Status] Reached %u outstanding queries\n",
                        max_outstanding);
                    enter_wait_phase();
                }
            }
        }
        for (i = try_responses; i--;) {
            try_process_response(current_sock++);
            if (current_sock >= nsocks)
                current_sock = 0;
        }
        retire_old_queries();
        time_now = perf_get_time();
    }
end_loop:
    time_now           = perf_get_time();
    time_of_end_of_run = time_now;

    printf("[Status] Testing complete\n");

    plotf = fopen(plotfile, "w");
    if (!plotf) {
        char __s[256];
        perf_log_fatal("could not open %s: %s", plotfile, perf_strerror_r(errno, __s, sizeof(__s)));
        return 0; // fix clang scan-build
    }

    /* Print column headers */
    fprintf(plotf, "# time target_qps actual_qps responses_per_sec failures_per_sec avg_latency"
                   " connections conn_avg_latency\n");

    /* Don't print unused buckets */
    last_bucket_used = find_bucket(wait_phase_began) - buckets;

    /* Don't print a partial bucket at the end */
    if (last_bucket_used > 0)
        --last_bucket_used;

    for (i = 0; i <= last_bucket_used; i++) {
        double t          = (i + 0.5) * traffic_time / (n_buckets * (double)MILLION);
        double ramp_dtime = ramp_time / (double)MILLION;
        double target_qps = t <= ramp_dtime ? (t / ramp_dtime) * max_qps : max_qps;
        double latency    = buckets[i].responses ? buckets[i].latency_sum / buckets[i].responses : 0;
        double interval   = bucket_interval / (double)MILLION;

        double conn_latency = buckets[i].connections ? buckets[i].conn_latency_sum / buckets[i].connections : 0;

        fprintf(plotf, "%7.3f %8.2f %8.2f %8.2f %8.2f %8.6f %8.2f %8.6f\n",
            t,
            target_qps,
            (double)buckets[i].queries / interval,
            (double)buckets[i].responses / interval,
            (double)buckets[i].failures / interval,
            latency,
            (double)buckets[i].connections / interval,
            conn_latency);
    }

    fclose(plotf);
    print_statistics();
    perf_net_stats_init(mode);
    cleanup();
    perf_net_stats_print(mode);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_free_strings();
#endif

    return 0;
}
