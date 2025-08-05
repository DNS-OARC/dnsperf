#!/bin/sh -xe

test "$TEST_DNSPERF_WITH_NETWORK" = "1" || exit 0

dumdumd=`which dumdumd`
dumdohd=`which dumdohd`

pkill -9 dumdumd || true
pkill -9 dumdohd || true

if [ -n "$dumdumd" ]; then
    $dumdumd 127.0.0.1 5353 -r -D 100 &
    pid="$!"
    sleep 2
    ../dnsperf -s 127.0.0.1 -p 5353 -d "$srcdir/datafile" -t 2 -l 2 -Q 10 -m tcp
    kill "$pid"
    wait "$pid" || true

    $dumdumd 127.0.0.1 5353 -r -D 10 &
    pid="$!"
    sleep 2
    ../dnsperf -s 127.0.0.1 -p 5353 -d "$srcdir/datafile" -t 2 -l 10 -Q 100 -m tcp
    kill "$pid"
    wait "$pid" || true

    rm -f key.pem cert.pem
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd"

    $dumdumd 127.0.0.1 5353 -r -T -D 100 &
    pid="$!"
    sleep 2
    ../dnsperf -s 127.0.0.1 -p 5353 -d "$srcdir/datafile" -t 2 -l 2 -Q 10 -m dot
    kill "$pid"
    wait "$pid" || true

    $dumdumd 127.0.0.1 5353 -r -T -D 10 &
    pid="$!"
    sleep 2
    ../dnsperf -s 127.0.0.1 -p 5353 -d "$srcdir/datafile" -t 2 -l 10 -Q 100 -m dot
    kill "$pid"
    wait "$pid" || true
fi

if [ -n "$dumdohd" ]; then
    rm -f key.pem cert.pem
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd"

    $dumdohd 5354 key.pem cert.pem -D 100 &
    pid="$!"
    sleep 2
    ../dnsperf -s 127.0.0.1 -p 5354 -d "$srcdir/datafile" -t 2 -l 2 -Q 10 -m doh
    kill "$pid"
    wait "$pid" || true

    $dumdohd 5354 key.pem cert.pem -D 10 &
    pid="$!"
    sleep 2
    ../dnsperf -s 127.0.0.1 -p 5354 -d "$srcdir/datafile" -t 2 -l 10 -Q 100 -m doh
    kill "$pid"
    wait "$pid" || true
fi
