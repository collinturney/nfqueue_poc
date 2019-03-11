#!/bin/bash

#iptables -A INPUT \
#   -p udp \
#   --dport 6000 \
#   -j NFQUEUE \
#   --queue-num 0

iptables -A INPUT \
    -p udp \
    --dport 6000 \
    -j NFQUEUE \
    --queue-balance 0:3 \
    --queue-bypass \
    --queue-cpu-fanout
