FROM ubuntu:26.04

RUN apt update &&\
    apt install -y jq ldnsutils sqlite3 golang ca-certificates git wget python3 curl build-essential &&\
    apt clean &&\
    go install -trimpath github.com/monoidic/dns-tools@435e812575a67b0b34605e80ae8563b4054b0e1a &&\
    cp /root/go/bin/dns-tools /usr/local/bin
