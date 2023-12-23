#!/bin/bash
cargo build --release
ext=$?
if [[ $ext -ne 0 ]]; then
    exit $ext
fi
sudo setcap cap_net_admin=eip /home/aaron/trust/target/release/trust
/home/aaron/trust/target/release/trust &
pid=$!
sudo ip address add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
