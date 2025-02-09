#!/bin/bash

echo "[+] غیرفعال کردن IP Forwarding..."
echo 0 > /proc/sys/net/ipv4/ip_forward

echo "[+] متوقف کردن ARP Spoofing..."
pkill arpspoof

echo "[+] ریست کردن جدول ARP..."
ip -s -s neigh flush all

echo "[+] حذف قوانین iptables..."
iptables -t nat -F
iptables -F
iptables --flush

echo "[+] متوقف کردن SSLStrip..."
pkill sslstrip

echo "[+] بررسی جدول ARP..."
arp -a

echo "[+] راه‌اندازی مجدد کارت شبکه..."
ifconfig eth0 down && ifconfig eth0 up

echo "[+] تنظیمات با موفقیت به حالت اولیه بازگردانی شد!"
