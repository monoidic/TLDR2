FROM ubuntu:26.04

RUN apt update &&\
    apt install -y jq ldnsutils sqlite3 golang ca-certificates git wget python3 curl build-essential &&\
    apt clean &&\
    go install -trimpath github.com/monoidic/dns-tools@7d0feb05c6818924b467cf7f097504dadfd79369 &&\
    cp /root/go/bin/dns-tools /usr/local/bin
