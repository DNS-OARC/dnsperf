#!/bin/sh -xe

! ../dnsperf -d does_not_exist
! ../resperf -d does_not_exist
! ../dnsperf -f invalid
! ../dnsperf -f any -s 256.256.256.256
! ../dnsperf -f inet -s 256.256.256.256
! ../dnsperf -f inet6 -s 256.256.256.256
! ../dnsperf -a 127.0.0.1 -d does_not_exist
! ../dnsperf -a ::1 -d does_not_exist
! ../dnsperf -a 256.256.256.256
! ../dnsperf -m invalid
! ../dnsperf -n 43f8huishfs
! ../dnsperf -p 12345 unexpected argument
! ../dnsperf -p 65536

! echo "" | ../dnsperf -y test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8=
! echo "" | ../dnsperf -y hmac-md5:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8=
! echo "" | ../dnsperf -y hmac-sha1:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8=
! echo "" | ../dnsperf -y hmac-sha224:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8=
! echo "" | ../dnsperf -y hmac-sha256:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8=
! echo "" | ../dnsperf -y hmac-sha384:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8=
! echo "" | ../dnsperf -y hmac-sha512:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8=
! echo "" | ../dnsperf -y invalid:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8=
! echo "" | ../dnsperf -y test:invalid
! echo "" | ../dnsperf -y test
echo "" | ../dnsperf -W -y toooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooolongname:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= \
  | grep "unable to setup TSIG, name too long"
echo "" | ../dnsperf -W -y test: | grep "unable to setup TSIG, secret empty"

! ../dnsperf -e -E invalid
! ../dnsperf -e -E 9999999:invalid
! ../dnsperf -e -E 123:invalid
! ../dnsperf -e -E 123:fa0
../dnsperf -W -E a: | grep "invalid EDNS Option, value is empty"
../dnsperf -W -E a:a | grep "invalid EDNS Option, value must hex string (even number of characters)"
../dnsperf -W -E a:aa | grep "invalid EDNS Option code 'a'"
../dnsperf -W -E 1:xx | grep "invalid EDNS Option hex value 'xx'"

! ../resperf -e -E invalid
! ../resperf -e -E 9999999:invalid
! ../resperf -e -E 123:invalid
! ../resperf -e -E 123:fa0
../resperf -W -E a: | grep "invalid EDNS Option, value is empty"
../resperf -W -E a:a | grep "invalid EDNS Option, value must hex string (even number of characters)"
../resperf -W -E a:aa | grep "invalid EDNS Option code 'a'"
../resperf -W -E 1:xx | grep "invalid EDNS Option hex value 'xx'"

! ../resperf -d does_not_exist
! ../resperf -r 0 -c 0
! ../resperf -f invalid
! ../resperf -q 256000
! ../resperf -m 123.45 unexpected argument
! ../resperf -m 123..
! ../resperf -m 123a

echo "invalid" | ../dnsperf -W | grep "invalid query input format: invalid"
echo "invalid invalid" | ../dnsperf -W | grep "invalid qtype: invalid"
if ! echo "invalid" | ../dnsperf -u -W | grep "Unable to dynamic update, support not built in"; then
    echo "invalid" | ../dnsperf -u -W | grep "incomplete update: invalid"
    echo -e "invalid\ninvalid" | ../dnsperf -u -W | grep "invalid update command: invalid"
    echo -e "invalid\ninvalid" | ../dnsperf -u -W | grep "error processing update command: invalid"
fi
