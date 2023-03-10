#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <gssapi/gssapi.h>
#include <krb5/krb5.h>

#include "buffer.h"
#include "dns.h"
#include "edns.h"
#include "generic_dns.h"
#include "gss.h"
#include "log.h"
#include "net.h"
#include "random_num.h"


#ifndef GSS_SPNEGO_MECHANISM
static unsigned char spnego_mech_oid_bytes[] = { 0x2b, 0x06, 0x01,
                         0x05, 0x05, 0x02 };
static gss_OID_desc __gss_spnego_mechanism_oid_desc = {
    sizeof(spnego_mech_oid_bytes), spnego_mech_oid_bytes
};
#define GSS_SPNEGO_MECHANISM (&__gss_spnego_mechanism_oid_desc)
#endif /* ifndef GSS_SPNEGO_MECHANISM */


char *
gss_error_tostring(uint32_t major, uint32_t minor, char *buf, size_t buflen) {
    gss_buffer_desc msg_minor = GSS_C_EMPTY_BUFFER,
            msg_major = GSS_C_EMPTY_BUFFER;
    OM_uint32 msg_ctx, minor_stat;

    /* Handle major status */
    msg_ctx = 0;
    (void)gss_display_status(&minor_stat, major, GSS_C_GSS_CODE,
                 GSS_C_NULL_OID, &msg_ctx, &msg_major);

    /* Handle minor status */
    msg_ctx = 0;
    (void)gss_display_status(&minor_stat, minor, GSS_C_MECH_CODE,
                 GSS_C_NULL_OID, &msg_ctx, &msg_minor);

    snprintf(buf, buflen, "GSSAPI error: Major = %s, Minor = %s.",
         (char *)msg_major.value, (char *)msg_minor.value);

    if (msg_major.length != 0U) {
        (void)gss_release_buffer(&minor_stat, &msg_major);
    }
    if (msg_minor.length != 0U) {
        (void)gss_release_buffer(&minor_stat, &msg_minor);
    }
    return (buf);
}


void print_gss_err(uint32_t major, uint32_t minor) {
    char buff[1024];
    gss_error_tostring(major, minor, buff, sizeof(buff));
    perf_log_printf("Error: %s", buff);
}


void get_ticket_realm(char *realm) {
    krb5_context ctx;
    krb5_error_code rc;
    krb5_ccache ccache;
    krb5_principal princ;
    char *name;
    const char *ticket_realm;

    rc = krb5_init_context(&ctx);
    if (rc != 0) {
        return;
    }

    rc = krb5_cc_default(ctx, &ccache);
    if (rc != 0) {
        krb5_free_context(ctx);
        return;
    }

    rc = krb5_cc_get_principal(ctx, ccache, &princ);
    if (rc != 0) {
        krb5_cc_close(ctx, ccache);
        krb5_free_context(ctx);
        return;
    }

    rc = krb5_unparse_name(ctx, princ, &name);
    if (rc != 0) {
        krb5_free_principal(ctx, princ);
        krb5_cc_close(ctx, ccache);
        krb5_free_context(ctx);
        return;
    }

    ticket_realm = strrchr(name, '@');
    if (ticket_realm != NULL) {
        memcpy(realm, ticket_realm, strlen(ticket_realm));
    }

    free(name);
    krb5_free_principal(ctx, princ);
    krb5_cc_close(ctx, ccache);
    krb5_free_context(ctx);
}


perf_result_t perf_init_gss_context(const char *server_name, perf_sockaddr_t local_addr, perf_sockaddr_t server_addr, perf_gsstsig_t *gss_tsig) {
    /*
     * server_name: input - target service name to access using gss
     * local_addr: input - source that sends the query
     * server_addr: input - destination that receives the query
     * gss_tsig: output - the output GSS information which contains GSS security context
    */
    char realm_name[100];
    memset(realm_name, 0, sizeof(realm_name));
    get_ticket_realm(realm_name);
    char spname[4 + strlen(server_name) + strlen(realm_name) + 1];
    snprintf(spname, sizeof(spname), "%s/%s%s", "DNS", server_name, realm_name);
    gss_buffer_desc name_buffer;
    name_buffer.value = spname;
    name_buffer.length = strlen(name_buffer.value) + 1;

    gss_name_t gss_target_name;
    OM_uint32 gret, minor;
    gret = gss_import_name(&minor, &name_buffer, GSS_C_NO_OID, &gss_target_name);
    if (gret != GSS_S_COMPLETE) {
        gss_release_name(&minor, &gss_target_name);
        perf_log_warning("gss_import_name error: %u", gret);
        return PERF_R_FAILURE;
    }

    gss_ctx_id_t gss_ctx = GSS_C_NO_CONTEXT;
    gss_buffer_t input_token = GSS_C_NO_BUFFER;
    gss_buffer_desc goutput_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 ret_flags, flags;
    flags = GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;
    unsigned short try_count = 1;

    unsigned int random_number = 0;
    perf_get_random_number(&random_number, sizeof(random_number));
    snprintf(gss_tsig->key_name, MAX_DNS_NAME, "%u.gss-tsig.%s", random_number, server_name);

    char arr_data[MAX_EDNS_PACKET];
    perf_buffer_t key_data;
    perf_buffer_init(&key_data, arr_data, sizeof(arr_data));
    do
    {
        // initialize the security context
        gret = gss_init_sec_context(
            &minor, GSS_C_NO_CREDENTIAL, &gss_ctx, gss_target_name,
            GSS_SPNEGO_MECHANISM, flags, 0, NULL, input_token, NULL,
            &goutput_token, &ret_flags, NULL);

        if (GSS_ERROR(gret))
        {
            // only memory allocated by gss internal api should be released by gss_release_name or gss_release_buffer
            perf_log_warning("gss_init_sec_context error: major = %d, minor = %d", gret, minor);
            print_gss_err(gret, minor);
        }

        if (goutput_token.length > 0)
        {
            perf_buffer_putmem(&key_data, goutput_token.value, goutput_token.length);
            perf_buffer_t resp_msg;
            perf_result_t ret = perf_send_receive_tkey(local_addr, server_addr, gss_tsig->key_name, &key_data, &resp_msg);
            if (ret != PERF_R_SUCCESS) {
                break;
            }

            dns_message_t resp_dns_msg;
            ret = perf_parse_tkey_response(&resp_msg, &resp_dns_msg);
            if (ret != PERF_R_SUCCESS) {
                break;
            }

            tkey_rr_t *tkeyrr = (tkey_rr_t*)resp_dns_msg.msg_answer;
            gss_buffer_desc new_token;
            new_token.length = tkeyrr->key_size;
            new_token.value = perf_buffer_base(&tkeyrr->key_data);
            input_token = &new_token;
            // release for reusing in the next loop
            gss_release_buffer(&minor, &goutput_token);
        }

        if (GSS_ERROR(gret))
        {
            if (gss_ctx != GSS_C_NO_CONTEXT)
                gss_delete_sec_context(&minor,
                                &gss_ctx,
                                GSS_C_NO_BUFFER);
            break;
        }

        try_count++;
    } while (gret & GSS_S_CONTINUE_NEEDED && try_count <= 10);

    if (gret == GSS_S_COMPLETE)
        gss_tsig->gss_context = gss_ctx;

    // cleanup data
    gss_release_name(&minor, &gss_target_name);
    gss_release_buffer(&minor, &goutput_token);

    return (gret == GSS_S_COMPLETE) ? PERF_R_SUCCESS : PERF_R_FAILURE;
}


perf_result_t perf_send_receive_tkey(perf_sockaddr_t local_addr, perf_sockaddr_t server_addr, const char *key_name, perf_buffer_t *key_data, perf_buffer_t *resp_msg) {
    // 00000001 00000000
    unsigned short flags = 0x0100U;
    // we have 1 query
    unsigned short qcount = 1;
    unsigned short anscount = 0;
    unsigned short authcount = 0;
    // we have 1 tkey record
    unsigned short addcount = 1;
    unsigned short out_msg_id;
    const char *qtype = "TKEY";
    unsigned short qclass = 255;

    struct perf_net_socket *qsock = NULL;
    perf_buffer_t  out_msg;
    perf_result_t ret;
    enum perf_net_mode tcp_mode = sock_tcp;
    unsigned char *base = NULL;
    unsigned int length = 0;
    unsigned int offset = 10000; // set a high offset to stay clear of thread sockets
    size_t buf_size;
    int num_bytes = 0;
    unsigned char packet_buffer[MAX_EDNS_PACKET];
    time_t snap_time;

    ret = perf_create_dns_message(&out_msg_id, flags, qcount, anscount, authcount, addcount, &out_msg);
    if (ret != PERF_R_SUCCESS) {
        perf_log_warning("Failed to create message.");
        return ret;
    }

    /* Create query section */
    ret = perf_add_dns_query(key_name, qtype, qclass, &out_msg);
    if (ret != PERF_R_SUCCESS) {
        perf_log_warning("Failed to add query section.");
        return ret;
    }

    /* Create additional section */
    ret = perf_add_dns_tkey_record(key_name, key_data, &out_msg);
    if (ret != PERF_R_SUCCESS) {
        perf_log_warning("Failed to add TKEY record.");
        return ret;
    }

    /* Sending query */
    qsock = perf_net_opensocket(tcp_mode, &server_addr, &local_addr, offset, buf_size, NULL, NULL, NULL);
    base = perf_buffer_base(&out_msg);
    length = perf_buffer_usedlength(&out_msg);

    while (num_bytes != length) {
        // num_bytes comes as -1 in case of failure for non-blocking sockets
        if (num_bytes > 0) {
            length = length - num_bytes;
        }
        else {
            num_bytes = 0;
        }
        
        num_bytes = perf_net_sendto(qsock, out_msg_id, base + num_bytes, length, 0, &server_addr.sa.sa, server_addr.length);
        if (num_bytes != length)
            usleep(10); //retry after 10 milliseconds
    }

    if (num_bytes <= 0) {
        perf_log_warning("Timeout. No TKEY query send.");
        return PERF_R_TIMEDOUT;
    }

    snap_time = time(NULL);
    // wait for max 10 seconds for the response
    while (time(NULL) < snap_time + 10)
    {
        num_bytes = perf_net_recv(qsock, packet_buffer, sizeof(packet_buffer), 0);
        if (num_bytes > 0) {
            break;
        }
        usleep(10); //retry after 10 milliseconds
    }
    if (num_bytes <= 0){
        perf_log_warning("Timeout. No response for TKEY query.");
        return PERF_R_TIMEDOUT;
    }

    perf_buffer_init(resp_msg, packet_buffer, sizeof(packet_buffer));
    perf_buffer_add(resp_msg, sizeof(packet_buffer));
    perf_net_close(qsock);
    
    return PERF_R_SUCCESS;
}


perf_result_t perf_add_dns_tkey_record(const char *rec_name, perf_buffer_t *key_data, perf_buffer_t* out_msg)
{
    const char     *rec_type = "TKEY";
    unsigned short rec_class = 255;
    unsigned int   rec_ttl = 0;
    size_t         rec_name_len, rec_type_len, rec_data_len;
    const char     *alg_name = "gss-tsig";
    size_t         alg_name_len = strcspn(alg_name, WHITESPACE);
    uint32_t       now;
    perf_result_t  result;

    now = time(NULL);
    rec_name_len = strcspn(rec_name, WHITESPACE);
    rec_type_len = strcspn(rec_type, WHITESPACE);

    /* Add the record. */
    switch ((result = perf_dname_fromstring(rec_name, rec_name_len, out_msg))) {
    case PERF_R_SUCCESS:
        break;
    case PERF_R_NOSPACE:
        perf_log_warning("adding additional record: out of space");
        return result;
    default:
        perf_log_warning("adding additional record: invalid record name");
        return result;
    }

    result = perf_qtype_fromstring(rec_type, rec_type_len, out_msg);
    if (result != PERF_R_SUCCESS) {
        perf_log_warning("invalid record type: %.*s", (int)rec_type_len, rec_type);
        return result;
    }

    perf_buffer_putuint16(out_msg, rec_class);
    perf_buffer_putuint32(out_msg, rec_ttl);
    // 1 byte encodes size of alg_name_len + 1 null-byte at the end of string + alg_name_len + 16 bytes of other fields + size of key data
    rec_data_len = 1 + alg_name_len + 1 + 16 + key_data->used;
    perf_buffer_putuint16(out_msg, rec_data_len);

    result = perf_dname_fromstring(alg_name, alg_name_len, out_msg);
    if (result != PERF_R_SUCCESS) {
        perf_log_warning("invalid algorithm name: %.*s", (int)alg_name_len, alg_name);
        return result;
    }

    perf_buffer_putuint32(out_msg, now);                            /* inception */
    perf_buffer_putuint32(out_msg, now);                            /* expiration */
    perf_buffer_putuint16(out_msg, GSS_API_MODE);                   /* mode */
    perf_buffer_putuint16(out_msg, 0);                              /* error */
    perf_buffer_putuint16(out_msg, key_data->used);                 /* key size */
    perf_buffer_putmem(out_msg, key_data->base, key_data->used);    /* key data */
    perf_buffer_putuint16(out_msg, 0);                              /* other len */

    return PERF_R_SUCCESS;
}


perf_result_t perf_parse_tkey_response(perf_buffer_t *resp_msg, dns_message_t *tkey_resp) {
    // read 12 byes header
    unsigned short msgId = perf_buffer_getuint16(resp_msg);
    unsigned short msg_rcode = perf_buffer_getuint16(resp_msg) & 0xF;
    if (msg_rcode != 0) {
        perf_log_warning("Error reading TKEY response: rcode = %d", msg_rcode);
        return PERF_R_FAILURE;
    }

    tkey_resp->msg_header.msg_id = msgId;
    tkey_resp->msg_header.msg_rcode = msg_rcode;
    tkey_resp->msg_header.query_count = perf_buffer_getuint16(resp_msg);
    tkey_resp->msg_header.answer_count = perf_buffer_getuint16(resp_msg);
    tkey_resp->msg_header.authority_count = perf_buffer_getuint16(resp_msg);
    tkey_resp->msg_header.additional_count = perf_buffer_getuint16(resp_msg);

    // read question section
    unsigned char dns_name[MAX_DNS_NAME];
    get_dname_from_wire(resp_msg, dns_name);
    tkey_resp->msg_query.query_name = dns_name;
    tkey_resp->msg_query.query_type = perf_buffer_getuint16(resp_msg);
    tkey_resp->msg_query.query_class = perf_buffer_getuint16(resp_msg);

    // read answer section
    tkey_rr_t tkey_rr;
    get_dname_from_wire(resp_msg, tkey_rr.rr_name);
    tkey_rr.rr_type = perf_buffer_getuint16(resp_msg);
    tkey_rr.rr_class = perf_buffer_getuint16(resp_msg);
    tkey_rr.rr_ttl = perf_buffer_getuint32(resp_msg);
    tkey_rr.rr_data_len = perf_buffer_getuint16(resp_msg);
    // read tkeydata
    get_dname_from_wire(resp_msg, tkey_rr.algorithm);
    tkey_rr.inception = perf_buffer_getuint32(resp_msg);
    tkey_rr.expiration = perf_buffer_getuint32(resp_msg);
    tkey_rr.mode = perf_buffer_getuint16(resp_msg);
    tkey_rr.error = perf_buffer_getuint16(resp_msg);

    tkey_rr.key_size = perf_buffer_getuint16(resp_msg);
    unsigned char key_data[tkey_rr.key_size];
    perf_buffer_init(&tkey_rr.key_data, key_data, sizeof(key_data));
    perf_buffer_putmem(&tkey_rr.key_data, resp_msg->base + resp_msg->current, tkey_rr.key_size);
    perf_buffer_add_current(resp_msg, tkey_rr.key_size);
    tkey_rr.other_size = perf_buffer_getuint16(resp_msg);

    tkey_resp->msg_answer = &tkey_rr;
    return PERF_R_SUCCESS;
}


perf_result_t perf_add_gsstsig_signature(perf_gsstsig_t *gss_tsig, perf_buffer_t *out_msg) {   
    perf_buffer_t msg_and_tsig_vars;
    unsigned char tmpdata[MAX_EDNS_PACKET];
    perf_buffer_init(&msg_and_tsig_vars, tmpdata, sizeof tmpdata);
    perf_buffer_putmem(&msg_and_tsig_vars, out_msg->base, out_msg->used);

    // gss key name
    perf_result_t result;
    size_t key_len = strcspn(gss_tsig->key_name, WHITESPACE);
    switch ((result = perf_dname_fromstring(gss_tsig->key_name, key_len, &msg_and_tsig_vars))) {
    case PERF_R_SUCCESS:
        break;
    case PERF_R_NOSPACE:
        perf_log_warning("adding TSIG: out of space in digest record");
        return result;
    default:
        perf_log_warning("adding TSIG: invalid owner name");
        return result;
    }

    // record class and TTL
    perf_buffer_putuint16(&msg_and_tsig_vars, 255);
    perf_buffer_putuint32(&msg_and_tsig_vars, 0);

    // algorithm name must be gss-tsig
    // https://datatracker.ietf.org/doc/html/rfc3645#section-5.1
    unsigned char alg_name[] = "gss-tsig";
    unsigned short alg_len = strlen(alg_name);
    switch ((result = perf_dname_fromstring(alg_name, alg_len, &msg_and_tsig_vars))) {
    case PERF_R_SUCCESS:
        break;
    case PERF_R_NOSPACE:
        perf_log_warning("adding TSIG: out of space in digest record");
        return result;
    default:
        perf_log_warning("adding TSIG: invalid algorithm name in digest record");
        return result;
    }

    uint32_t now = time(NULL);
    // time signed high and low
    perf_buffer_putuint16(&msg_and_tsig_vars, 0);
    perf_buffer_putuint32(&msg_and_tsig_vars, now);
    // fudge
    perf_buffer_putuint16(&msg_and_tsig_vars, 300);
    // error
    perf_buffer_putuint16(&msg_and_tsig_vars, 0);
    // other length
    perf_buffer_putuint16(&msg_and_tsig_vars, 0);

    // https://datatracker.ietf.org/doc/html/rfc2845, section 3.4
    // data need to be digested include: DNS message, TSIG variables
    gss_buffer_desc digest_msg;
    digest_msg.length = perf_buffer_usedlength(&msg_and_tsig_vars);
    digest_msg.value = perf_buffer_base(&msg_and_tsig_vars);
    OM_uint32 gss_ret, gss_minor;
    gss_buffer_desc out_msg_token;
    gss_ctx_id_t gss_context = (gss_ctx_id_t)gss_tsig->gss_context;
    gss_ret = gss_get_mic(&gss_minor, gss_context, GSS_C_QOP_DEFAULT, &digest_msg, &out_msg_token);
    if (gss_ret == GSS_S_COMPLETE)
    {
        // current base that point to the start of message buffer
        unsigned char *current_base = perf_buffer_base(out_msg);
        // create TSIG record
        switch ((result = perf_dname_fromstring(gss_tsig->key_name, key_len, out_msg))) {
        case PERF_R_SUCCESS:
            break;
        case PERF_R_NOSPACE:
            perf_log_warning("adding TSIG: out of space");
            return result;
        default:
            perf_log_warning("adding TSIG: invalid owner name");
            return result;
        }
        // type TSIG
        perf_buffer_putuint16(out_msg, 250);
        // class ANY
        perf_buffer_putuint16(out_msg, 255);
        // TTL must be zero
        perf_buffer_putuint32(out_msg, 0);
        // record data len
        unsigned int rdlen = alg_len + 18 + out_msg_token.length;
        perf_buffer_putuint16(out_msg, rdlen);
        switch ((result = perf_dname_fromstring(alg_name, alg_len, out_msg))) {
        case PERF_R_SUCCESS:
            break;
        case PERF_R_NOSPACE:
            perf_log_warning("adding TSIG: out of space");
            return result;
        default:
            perf_log_warning("adding TSIG: invalid algorithm name");
            return result;
        }
        // time signed high and low
        perf_buffer_putuint16(out_msg, 0);
        perf_buffer_putuint32(out_msg, now);
        // fudge: 5 minutes
        perf_buffer_putuint16(out_msg, 300);
        // digest len and digest data
        perf_buffer_putuint16(out_msg, out_msg_token.length);
        perf_buffer_putmem(out_msg, out_msg_token.value, out_msg_token.length);
        // original message ID: read 2 first bytes
        perf_buffer_putmem(out_msg, current_base, 2);
        // error
        perf_buffer_putuint16(out_msg, 0);
        // other len
        perf_buffer_putuint16(out_msg, 0);

        // increase the additional count which is at byte 11th of the buffer
        current_base[11]++;
    } else {
        perf_log_warning("Failed to get the message digest.");
        print_gss_err(gss_ret, gss_minor);
        return PERF_R_FAILURE;
    }

    // cleanup
    gss_release_buffer(&gss_minor, &out_msg_token);
    return PERF_R_SUCCESS;
}


void perf_remove_gsstsig_context(perf_gsstsig_t *gssctx) {
    gss_ctx_id_t gss_ctx = (gss_ctx_id_t)(gssctx->gss_context);
    if (gss_ctx != GSS_C_NO_CONTEXT) {
        OM_uint32 gret, minor;
        gret = gss_delete_sec_context(&minor, &gss_ctx, GSS_C_NO_BUFFER);
        gssctx->gss_context = gss_ctx;
        if (gret != GSS_S_COMPLETE) {
            print_gss_err(gret, minor);
        }
    }
}
