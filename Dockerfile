FROM ubuntu:26.04

RUN apt update &&\
    apt install -y jq ldnsutils sqlite3 golang ca-certificates git wget python3 curl build-essential &&\
    apt clean &&\
    go install -trimpath github.com/monoidic/dns-tools@e7ad8f4b261b6fbc23c28201706291e8e11acad4 &&\
    cp /root/go/bin/dns-tools /usr/local/bin
