ARG BASE_IMAGE=ubuntu:23.10
FROM $BASE_IMAGE AS runtime_base
MAINTAINER Petr Spacek <pspacek@isc.org>
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get upgrade -y -qqq
# dnsperf's runtime depedencies
RUN apt-get install -y -qqq -o APT::Install-Suggests=0 -o APT::Install-Recommends=0 libck0 libldns3 libnghttp2-14
# separate image for build, will not be tagged at the end
FROM runtime_base AS build_stage
RUN apt-get install -y -qqq -o APT::Install-Suggests=0 -o APT::Install-Recommends=0 autoconf automake build-essential git libck-dev libldns-dev libnghttp2-dev libssl-dev libtool pkg-config # copy repo as build context
COPY . /dnsperf
WORKDIR /dnsperf
RUN ./autogen.sh
RUN ./configure --prefix=/usr/local
RUN make -j$(nproc)
RUN make install
RUN git log -1 > /usr/local/dnsperf.git.log
RUN git diff > /usr/local/dnsperf.git.diff
RUN git status > /usr/local/dnsperf.git.status

# copy only installed artifacts and throw away everything else
FROM runtime_base AS installed
COPY --from=build_stage /usr/local /usr/local

ENTRYPOINT ["/usr/local/bin/dnsperf"]
