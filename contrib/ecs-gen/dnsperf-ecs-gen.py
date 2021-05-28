#!/usr/bin/env python3

import dns.edns
import sys

if len(sys.argv) > 1:
    opt = dns.edns.ECSOption.from_text(sys.argv[1])
    print("-e %d:%s" % (dns.edns.ECS, opt.to_wire().hex()))
else:
    print("usage: dnsperf-ecs-gen.py <address/srclen[/scopelen]>")
