# dnsperf-ecs-gen

Small python script to generate EDNS Client Subnet options for `dnsperf`.

Requires `dnspython` to be installed.

```
$ ./dnsperf-ecs-gen 192.168.0.1/24
-e 8:00011800c0a800
```
