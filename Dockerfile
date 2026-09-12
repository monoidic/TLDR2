FROM ubuntu:26.04

RUN apt update &&\
    apt install -y jq ldnsutils sqlite3 golang ca-certificates git wget python3 curl build-essential &&\
    apt clean &&\
    go install -trimpath github.com/monoidic/dns-tools@0c2117b089d00fdf2d45de2b0c0d53cf936805f4 &&\
    cp /root/go/bin/dns-tools /usr/local/bin
