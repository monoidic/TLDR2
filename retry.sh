#!/bin/bash

exitcode=0

for i in {1..3}; do
    eval $* && { exitcode=0; break; }
    sleep 10
    exitcode=$?
done
exit $exitcode
