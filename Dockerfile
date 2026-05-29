FROM ubuntu:26.04

RUN apt update &&\
    apt install -y jq ldnsutils sqlite3 golang ca-certificates &&\
    apt clean &&\
    go install github.com/monoidic/dns-tools@dac6e32a3033521fbdc219be590bcd5417f89d6c
