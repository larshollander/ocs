# ocs
This repository contains a command-line tool to perform ARP poisoning, DNS poisoning and SSL stripping attacks.

## Dependencies
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

Now that we have the available hosts scanned, we can perform ARP poisoning and DNS poisoning attacks, with SSL stripping capabilities.

### ARP poisoning example

Let's say we want to perform a man-in-the-middle ARP spoofing/poisoning attack.

We simply run the command:
```
arp mitm [host]
```
Now, a continuous stream of ARP packets is being sent out to the specified host and the gateway. Their ARP tables are poisoned such that all traffic will now go through our attacker machine.

If we want to stop the poisoning attack, we run:
```
arp stop [host]
```
Now, the stream of ARP packets is no longer being sent out.

One final step to fully finish the ARP poisoning attack, is to restore the ARP tables of both the specified host and the gateway, by running:
```
arp restore [host]
```

### DNS poisoning example



### SSL stripping example

Before SSL stripping is possible, we have to run the ARP MITM poisoning attack so that all traffic goes through the attacker and can be stripped. 

We again run:
```
arp mitm [host]
```

Then, we run:
```
ssl strip [host]
```

This will run the SSL stripping script, which will automatically perform the stripping while the specified host browses the internet. 
