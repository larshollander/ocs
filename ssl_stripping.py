from scapy.all import *
from netfilterqueue import NetfilterQueue
import multiprocessing
import cryptography    #required for tls

load_layer("tls")    #enables tls for the https connection with the server
load_layer("http")    #also useful

class SslRemover(multiprocessing.Process:

    def __init__(self, ip_victim, queue_num):
        
        multiprocessing.Process.__init__(self)

        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -I FORWARD -p tcp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)
        self.iprule_remove = "iptables -D FORWARD -p tcp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)
        self.exit          = multiprocessing.Event()

        self.queue.bind(queue_num, self.handle_packet)

    def handle_packet(self, packet):
        packet_scapy = IP(packet_nfqueue.get_payload())

        if packet_scapy[IP].src = ip_victim

        
        packet.accept()

    def stripped_victim_automation(self):
        # socket = TCP_client.tcplink(HTTP, <>, 80)


    def tls_client_automation(self):
        greeting = TLSClientHello(ciphers=<int code of the cipher suite>)
        connection = TLSClientAutomaton(dport=50000, client_hello=ch)
        connection.run()
