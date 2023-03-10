#include <string.h>

#include "buffer.h"
#include "dns.h"
#include "generic_dns.h"
#include "log.h"
#include "random_num.h"


perf_result_t perf_create_dns_message(unsigned short *mid, unsigned short flags, unsigned short question_count, unsigned short answer_count, \
    unsigned short authority_count, unsigned short additional_count, perf_buffer_t *out_msg) {
    // the packet buffer size must not less than 512 bytes as TCP is using for TKEY query and the keydata size is large
    unsigned char   packet_buffer[MAX_EDNS_PACKET];
    perf_buffer_init(out_msg, packet_buffer, sizeof(packet_buffer));

    /* Create the DNS packet header */
    unsigned short query_id = 0;
    if (!mid || *mid == 0) {
        if (perf_get_random_number(&query_id, sizeof(query_id)) != PERF_R_SUCCESS){
            return PERF_R_FAILURE;
        }
        *mid = query_id;
    }
    perf_buffer_putuint16(out_msg, query_id);
    perf_buffer_putuint16(out_msg, flags);
    perf_buffer_putuint16(out_msg, question_count);
    perf_buffer_putuint16(out_msg, answer_count);
    perf_buffer_putuint16(out_msg, authority_count);
    perf_buffer_putuint16(out_msg, additional_count);

    return PERF_R_SUCCESS;
}


perf_result_t perf_add_dns_query(const char *qname, const char *qtype, unsigned short qclass, perf_buffer_t* out_msg) {
    size_t        domain_len, qtype_len;
    perf_result_t result;
    domain_len = strcspn(qname, WHITESPACE);
    qtype_len = strcspn(qtype, WHITESPACE);

    if (!domain_len) {
        perf_log_warning("invalid domain name format: %s", qname);
        return PERF_R_FAILURE;
    }
    if (!qtype_len) {
        perf_log_warning("invalid query type format: %s", qtype);
        return PERF_R_FAILURE;
    }

    /* Create the question section */
    result = perf_dname_fromstring(qname, domain_len, out_msg);
    if (result != PERF_R_SUCCESS) {
        perf_log_warning("invalid domain name (or out of space): %.*s", (int)domain_len, qname);
        return result;
    }

    result = perf_qtype_fromstring(qtype, qtype_len, out_msg);
    if (result != PERF_R_SUCCESS) {
        perf_log_warning("invalid query type: %.*s", (int)qtype_len, qtype);
        return result;
    }

    perf_buffer_putuint16(out_msg, qclass);

    return PERF_R_SUCCESS;
}


perf_result_t perf_add_dns_rr(const char *rr_name, const char *rr_type, unsigned short rr_class,
                             unsigned int rr_ttl, unsigned char *rr_data, perf_buffer_t* out_msg) {
    return PERF_R_SUCCESS;
}


perf_result_t get_dname_from_wire(perf_buffer_t *source, unsigned char *target) {
    unsigned int bytes_in_label = 0;
    unsigned int label_length = 0;
    unsigned int current_offset_to_move = 0;
    unsigned int current_offset = source->current;
    unsigned char *current_char = perf_buffer_base(source) + current_offset;
    uint16_t current_data;

    typedef enum { STATE_START = 0, STATE_FORWARD, STATE_JUMP } pointer_state;
    pointer_state pstate = STATE_START;
    bool done = false;
    bool has_pointer = false;

    while (!done)
    {
        current_data = *current_char++;
        switch (pstate)
        {
        case STATE_START:
            // 2 first bits set to 0
            if (current_data < 64)
            {
                if (current_data == 0) {
                    // null character, end of string
                    *target++ = '\0';
                    done = true;
                }
                bytes_in_label = current_data;
                label_length += current_data + 1;
                pstate = STATE_FORWARD;
            }
            // 2 first bits is 01 (binary format) or 10
            else if (current_data >= 64 && current_data < 192)
            {
                // not supported for now
                return PERF_R_FAILURE;
            }
            // 2 first bits set to 1 indicates a pointer
            else if (current_data >= 192)
            {
                // read 14 bits pointer
                current_offset = current_data & 0x3F;
                pstate = STATE_JUMP;
            }
            break;
        case STATE_FORWARD:
            *target++ = current_data;
            bytes_in_label--;
            if (bytes_in_label == 0) {
                *target++ = '.';
                pstate = STATE_START;
            }
            break;
        case STATE_JUMP:
            // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            current_offset = (current_offset << 8) | current_data;
            current_char = perf_buffer_base(source) + current_offset;
            has_pointer = true;
            // pointer size is 2 octets and is always the last part of a compressed dname
            current_offset_to_move = label_length + 2;
            pstate = STATE_START;
            break;
        default:
            perf_log_warning("Unknown pointer state: %d.", pstate);
            break;
        }
    }

    if (has_pointer) {
        perf_buffer_add_current(source, current_offset_to_move);
    }
    else {
        perf_buffer_add_current(source, label_length);
    }
    return PERF_R_SUCCESS;
}
