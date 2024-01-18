#!/usr/bin/python3

import csv
from urllib.request import Request, urlopen
from io import StringIO

qtype = {}

for row in csv.reader(StringIO(urlopen(Request('https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv')).read().decode('utf-8'))):
    if row[0] == 'TYPE':
        continue
    try:
        qtype[row[0]] = int(row[1])
    except Exception:
        continue

print("""/*
 * Copyright 2019-2024 OARC, Inc.
 * Copyright 2017-2018 Akamai Technologies
 * Copyright 2006-2016 Nominum, Inc.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include "qtype.h"

const perf_qtype_t qtype_table[] = {""")

for k, v in qtype.items():
    if k == "Unassigned" or k == "Reserved":
        continue
    if k == "*":
        k = "ANY"
    print("    { \"%s\", %d }," % (k, v))

print("""    { 0, 0 }
};""")
