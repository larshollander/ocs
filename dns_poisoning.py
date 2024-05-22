from scapy.all import *
from netfilterqueue import NetfilterQueue
import multiprocessing

class DnsPoisoner(multiprocessing.Process):

    def __init__(self):
        multiprocessing.Process.__init__(self)


    def run(self):
        pass

    def stop(self):
        pass
