#!/bin/bash
echo "===== My IP Address ====="
ip addr show | grep "inet "
echo "===== Open Ports on This Machine ====="
sudo ss -tulnp
echo "===== DNS Resolution Test ====="
dig google.com +short
echo "===== Ping Test ====="
ping -c 2 8.8.8.8
