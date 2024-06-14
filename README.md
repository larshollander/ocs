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
Let's say we want to perform a man-in-the-middle ARP spoofing/poisoning attack.

We simply run the command:
```
>>> arp mitm [host]
```
Now, a continuous stream of ARP packets is being sent out to the specified host and the gateway. Their ARP tables are poisoned such that all traffic will now go through our attacker machine.

If we want to stop the poisoning attack, we run:
```
>>> arp stop [host]
```
Now, the stream of ARP packets is no longer being sent out.

One final step to fully finish the ARP poisoning attack, is to restore the ARP tables of both the specified host and the gateway, by running:
```
>>> arp restore [host]
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

### SSL stripping example

Before SSL stripping is possible, we have to run the ARP MITM poisoning attack so that all traffic goes through the attacker and can be stripped. 

We again run:
```
>>> arp mitm [host]
```

Then, we run:
```
>>> ssl strip [host]
```

This will run the SSL stripping script, which will automatically perform the stripping while the specified host browses the internet. 
