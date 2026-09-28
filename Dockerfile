FROM ubuntu:26.04

RUN apt update &&\
    apt install -y jq ldnsutils sqlite3 golang ca-certificates git wget python3 curl build-essential &&\
    apt clean &&\
    go install -trimpath github.com/monoidic/dns-tools@813917e7481c77d372078dcdbeb8896a49a320cb &&\
    cp /root/go/bin/dns-tools /usr/local/bin
