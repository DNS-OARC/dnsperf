#ifndef PERF_GSS_H
#define PERF_GSS_H 1

#include "buffer.h"
#include "generic_dns.h"
#include "net.h"


#define GSS_API_MODE 3


typedef struct  tkey_rr
{
    unsigned char       rr_name[MAX_DNS_NAME];
    unsigned short      rr_type;        //249
    unsigned short      rr_class;       //255
    uint32_t            rr_ttl;         //0
    unsigned short      rr_data_len;
    // rr data
    unsigned char       algorithm[MAX_DNS_NAME];
    uint32_t            inception;
    uint32_t            expiration;
    unsigned short      mode;
    unsigned short      error;
    unsigned short      key_size;
    perf_buffer_t       key_data;
    unsigned short      other_size;
    perf_buffer_t       other_data;
} tkey_rr_t;

typedef struct perf_gsstsig {
    char        key_name[MAX_DNS_NAME];
    void        *gss_context;
} perf_gsstsig_t;


perf_result_t perf_init_gss_context(const char *server_name, perf_sockaddr_t local_addr, perf_sockaddr_t server_addr, perf_gsstsig_t *gss_tsig);
perf_result_t perf_add_dns_tkey_record(const char *rec_name, perf_buffer_t *key_data, perf_buffer_t* out_msg);
perf_result_t perf_send_receive_tkey(perf_sockaddr_t local_addr, perf_sockaddr_t server_addr, const char *key_name, perf_buffer_t *key_data, perf_buffer_t *resp_msg);
perf_result_t perf_parse_tkey_response(perf_buffer_t *resp_msg, dns_message_t *tkey_resp);
perf_result_t perf_add_gsstsig_signature(perf_gsstsig_t *gss_tsig, perf_buffer_t *out_msg);
void perf_remove_gsstsig_context(perf_gsstsig_t *gssctx);

#endif
