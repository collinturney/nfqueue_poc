#!/bin/bash

modprobe nfnetlink
modprobe nfnetlink_queue

for i in `seq 0 3`; do
   nohup ./nfqueue $i >nfqueue.${i}.log 2>&1 &
done
