#!/bin/bash
cargo build --release
ext=$?
if [[ $ext -ne 0 ]]; then
    exit $ext
fi
sudo setcap cap_net_admin=eip /home/aaron/trust/target/release/trust
/home/aaron/trust/target/release/trust &
pid=$!
# tun0 绑定 ip 地址
sudo ip address add 192.168.0.1/24 dev tun0
# 启动 tun0
sudo ip link set up dev tun0
# grceful shutdown
trap "kill $pid" INT TERM
wait $pid
