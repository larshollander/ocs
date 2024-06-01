from scapy.all import *
from netfilterqueue import NetfilterQueue
import multiprocessing

class SslRemover(multiprocessing.Process):

    def __init__(self, ip_victim, queue_num):
        
        multiprocessing.Process.__init__(self)

        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -I FORWARD -p tcp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)
        self.iprule_remove = "iptables -D FORWARD -p tcp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)
        self.exit          = False

        self.queue.bind(queue_num, self.handle_packet)

    def handle_packet(self, packet):
        packet.accept()
