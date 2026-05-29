FROM ubuntu:26.04

RUN apt update &&\
    apt install -y jq ldnsutils sqlite3 golang ca-certificates git wget python3 &&\
    apt clean &&\
    go install -trimpath github.com/monoidic/dns-tools@2347e642c13a53559c01195e0e097346fcae98ca &&\
    cp /root/go/bin/dns-tools /usr/local/bin
