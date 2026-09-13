FROM ubuntu:26.04

RUN apt update &&\
    apt install -y jq ldnsutils sqlite3 golang ca-certificates git wget python3 curl build-essential &&\
    apt clean &&\
    go install -trimpath github.com/monoidic/dns-tools@c6748dda1d07f5611eb1d0c87cd5d43adefc3e01 &&\
    cp /root/go/bin/dns-tools /usr/local/bin
