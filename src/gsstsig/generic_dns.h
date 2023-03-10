#include "buffer.h"
#include "result.h"

#ifndef PERF_GEN_DNS_H
#define PERF_GEN_DNS_H 1


#define MAX_DNS_NAME 256
#define WHITESPACE " \t\n"


typedef struct dns_header
{
    unsigned short          msg_id;
    unsigned short          msg_rcode;
    unsigned short          query_count;
    unsigned short          answer_count;
    unsigned short          authority_count;
    unsigned short          additional_count;
} dns_header_t;

typedef struct dns_query
{
    unsigned char           *query_name;
    unsigned short          query_type;
    unsigned short          query_class;
} dns_query_t;

typedef struct dns_message {
    dns_header_t            msg_header;
    // query should be a list but currently there is just one
    dns_query_t             msg_query;
    void                    *msg_answer;
} dns_message_t;


perf_result_t perf_create_dns_message(unsigned short *mid, unsigned short flags, \
    unsigned short question_count, unsigned short answer_count, \
    unsigned short authority_count, unsigned short additional_count, \
    perf_buffer_t *out_msg
);
perf_result_t perf_add_dns_query(const char *qname, const char *qtype, unsigned short qclass, perf_buffer_t* out_msg);
perf_result_t perf_add_dns_rr(const char *rr_name, const char *rr_type, unsigned short rr_class, unsigned int rr_ttl, unsigned char *rr_data, perf_buffer_t* out_msg);
perf_result_t get_dname_from_wire(perf_buffer_t *source, unsigned char *target);

#endif
