from scapy.all import *
from netfilterqueue import NetfilterQueue
import multiprocessing

class DnsPoisoner(multiprocessing.Process):

    def __init__(self, queue_num):

        multiprocessing.Process.__init__(self)

        self.urls_to_spoof = {}
        self.queue         = NetfilterQueue()
        self.queue_num     = queue_num
        self.exit          = False

    def add_url(self, url, ip):
        self.urls_to_spoof[url] = ip

    def handle_packet(self, packet):
        pass

    def run(self):

        self.queue.bind(self.queue_num, self.handle_packet)
        self.queue.run()

        while not self.exit:
            time.sleep(1)

        self.queue.unbind()

    def stop(self):

        self.exit = True
