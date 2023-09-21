#!/usr/bin/env python3

import nmap
import sys
import re
import socket
from datetime import datetime

np = nmap.PortScanner();

ip_add_pattern = re.compile("^(?:[0-9]{1,3}.){3}[0-9]{1,3}$")
ip_addr = socket.gethostbyname(sys.argv[1])


print(ip_addr)

def welcome_message():

    print("-" * 25)
    print("Welcome to Nmap port Scanner!")
    print("Nmap Will Run A Basic Port Scan Followed By An Advance Port Scan On " + str(ip_addr) +  "!")
    print("-" * 25)

def basic_scan(ip):

    print("-" * 25)
    print("Beginning Basic Scan: " + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    
    try:
        np.scan(ip, '-p-', '-sV -sC -T4')
    except:
        print("Failed Scan")
        exit()

    print("Scan Completed: " + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    print("-" * 25)
    
def get_open_ports():
    ports = []
    
    with open('basic-scan.txt', 'r') as f:
        for line in f:
            if re.search('open', line):
                line = line.strip("/tcp")
                ports.append(line[1])
    
    return ports
    
    
def advance_scan(ip, ports):
    
    print("-" * 25)
    print("Beginning Advance Scan! " + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    
    try:
        np.scan(ip, "-p " + str(ports)+ "-T4 -A -oN > advance-scan.txt", timeout=1)
    except:
        print("Failed Scan")
        exit()

    print("Scan Completed: " + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    print("-" * 25)

open_ports = get_open_ports()

if ip_add_pattern.search(ip_addr):
    welcome_message()
    basic_scan(ip_addr)
    advance_scan(ip_addr, open_ports)
else:
    print("Invalid IPv4 address")
    exit()

