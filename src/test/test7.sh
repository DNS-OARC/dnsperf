#!/bin/sh -xe

# expect non-zero exit code
function malformed_input_fmt() {
    FILESTEM="$1"
    ../dnsperf -vvv -B -d "$srcdir/$FILESTEM.blob" &> "$FILESTEM.out" && exit 1
    grep -F "Error: input file contains no data" "$FILESTEM.out"
}

malformed_input_fmt "empty"
malformed_input_fmt "tooshortlength"
malformed_input_fmt "missingpayload"

test "$TEST_DNSPERF_WITH_NETWORK" = "1" || exit 0

function check_sent_and_lost() {
    FILESTEM="$1"
    EXPECTEDCOUNT="$2"
    grep "Queries sent:         $EXPECTEDCOUNT$" "$FILESTEM.out"
    grep -F "Queries lost:         $EXPECTEDCOUNT (" "$FILESTEM.out"
}

# send to an address which does not reply anyway;
# typically for weird blobs which do not even have DNS header - so we cannot expect a response
function blackhole() {
    FILESTEM="$1"
    EXTRAARGS="$2"
    EXPECTEDCOUNT="$3"
    ../dnsperf -t 0.001 -vvv -B -d "$srcdir/$FILESTEM.blob" -s 192.0.2.1 $EXTRAARGS &> "$FILESTEM.out"
    check_sent_and_lost "$FILESTEM" "$EXPECTEDCOUNT"
}

blackhole "emptypayload" "" 1
blackhole "shortpayload" "" 1
blackhole "largestudp" "" 1
# too large for UDP; at least it should not crash
blackhole "largesttcp" "" 0
grep -F 'failed to send packet' largesttcp.out

# valid DNS queries as blobs
function expect_noerror() {
    FILESTEM="$1"
    EXTRAARGS="$2"
    EXPECTEDCOUNT="$3"
    ../dnsperf -vvv -B -d "$srcdir/$FILESTEM.blob" -s 1.1.1.1 $EXTRAARGS &> "$FILESTEM.out"
    grep "Queries sent:         $EXPECTEDCOUNT$" "$FILESTEM.out"
    grep -F "Queries completed:    $EXPECTEDCOUNT (" "$FILESTEM.out"
}

# single plain run
expect_noerror "querywithcookie" "" 1

# loop over the binary twice
expect_noerror "querywithcookie" "-n 2" 2

# multiple queries in one file
expect_noerror "twoquerieswithnsid" "" 2

# file too big to cache
rm -f 10queries.tmp.blob
cat "$srcdir/twoquerieswithnsid.blob" "$srcdir/querywithcookie.blob" "$srcdir/emptypayload.blob" \
    "$srcdir/largestudp.blob" "$srcdir/twoquerieswithnsid.blob" "$srcdir/querywithcookie.blob" \
    "$srcdir/emptypayload.blob" "$srcdir/largestudp.blob" \
    > 10queries.tmp.blob
blackhole "10queries.tmp" "" 10

# repeat non-cacheable file the same twice
blackhole "10queries.tmp" "-n 2" 20

# large binary on stdin should work too
cat 10queries.tmp.blob | ../dnsperf -t 0.001 -vvv -B -s 192.0.2.1 &> "stdinlarge.out"
check_sent_and_lost "stdinlarge" 10

# small binary on stdin
cat twoquerieswithnsid.blob | ../dnsperf -t 0.001 -vvv -B -s 192.0.2.1 &> "stdinsmall.out"
check_sent_and_lost "stdinsmall" 2
