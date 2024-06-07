# ocs
This repository contains a command-line tool to perform ARP poisoning, DNS poisoning and SSL stripping attacks.

## Dependencies:
A linux system using iptables and python 2.7 (e.g. in a virtual environment) are required. 
Before first use, install the required python packages by:
```
# python -m pip install -r requirements.txt
```

## Example usage:
To run the program, use:
```
# python cli.py
```
Note that root priviliges are required to modify packets.
The interface is automatically set to match the default gateway. It can also be set manually:
```
>>> set iface enp0s3
```
Before any attack, we first need to scan for hosts:
```
>>> scan
gateway at 192.168.18.1
0: host at 192.168.18.2
1: host at 192.168.18.3
2: host at 192.168.18.4
```
