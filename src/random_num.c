#include <openssl/err.h>
#include <openssl/rand.h>

#include "log.h"
#include "random_num.h"


perf_result_t perf_get_random_number(void *out_buff, int buff_len){
    // https://www.openssl.org/docs/manmaster/man3/ERR_get_error.html
    short result = RAND_bytes(out_buff, buff_len);
    if (result < 1) {
        // use ERR_error_string to get readable text of code returned by ERR_get_error
        perf_log_warning("An error occurred while generating random number. Return code: %d", ERR_get_error());
        return PERF_R_FAILURE;
    }
    return PERF_R_SUCCESS;
}
