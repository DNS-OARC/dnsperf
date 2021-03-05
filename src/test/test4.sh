#!/bin/sh -xe

test "$TEST_DNSPERF_WITH_NETWORK" = "1" || exit 0

../dnsperf -vvv -d "$srcdir/datafile4" -t 0 -s 127.0.0.1 >test4.out 2>test4err.out

grep 'api-read.facebook.com.\\002\\004\\003\\002\\002\\002\\002\\005\\004\\004\\003\\004\\006\\005\\006\\006\\006\\005\\006\\006\\006\\007\\009\\008\\006\\007\\009\\007\\006\\006\\008\\011\\008\\009\\010\\010\\010\\010\\010\\006\\008\\011\\012\\011\\010\\012\\009\\010\\010\\010\\255\\219. A' test4.out
grep 'T valid\\.quote.com A' test4.out
grep 'Warning: invalid domain name (or out of space): invalid\\0quote.com' test4err.out
