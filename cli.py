from collections import defaultdict
import netifaces
import os

from hosts import get_hosts


class CLI:

    commands    = {}
    params_all = {}
    params_mut  = {}

    def __init__(self):

        # enable ip forwarding and store original value to reset upon exiting
        self.ip_forward = os.system("cat /proc/sys/net/ipv4/ip_forward")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        # parameters based on default gateway
        self.interface = self.default_interface()
        self.range_    = self.default_range()
        self.own_mac   = self.default_mac()
        self.timeout   = 3

        # after scanning, hosts are stored in a list and gateway is stored separately
        self.hosts   = []
        self.gateway = None

    # main function: store user input in list and call specified command
    # e.g. input 'foo bar baz' calls "self.foo(['bar', 'baz'])"
    def prompt(self):

        args = raw_input(">>> ").split(' ')
    
        # obtain specified function from dict "commands" with key "args[0]" and call it
        try:
            self.commands[args[0]](self, args[1:])

        # if specified command "args[0]" is not recognized, "commands[args[0]]" will throw a KeyError
        except KeyError as _:
            print "E: Unknown command \"{}\"".format(args[0])
            self.prompt()

    ### show & set functions for parameters ###

    # print specified parameter
    # e.g. "self.show(['bar', 'baz'])" calls "self.show_bar(['baz'])"
    def show(self, args):

        # obtain 'show' function for specified parameter from dict "params_all" with key "args[0]" and call it
        try:
            self.params_all[args[0]](self, args[1:])

        # if specified parameter "args[0]" is not recognized, "params[args[0]]" will throw a KeyError
        except KeyError as _:
            print "E: Unknown parameter \"{}\"".format(args[0])

        # if "args" is empty, no parameter is specified and "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: No parameter specified"

        self.prompt()

    commands["show"] = show

    # set specified parameter
    # e.g. "self.set(['bar', 'baz'])" calls "self.set_bar(['baz'])"
    def set_(self, args):

        # obtain 'set' function for specified parameter from dict "params_mut" with key "args[0]" and call it
        try:
            self.params_mut[args[0]](self, args[1:])

        # if specified parameter "args[0]" is not recognized, "params[args[0]]" will throw a KeyError
        except KeyError as _:
            print "E: Unknown parameter \"{}\"".format(args[0])

        # if "args" is empty, no parameter is specified and "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: No parameter specified"

        self.prompt()

    commands["set"] = set_

    # simply print interface
    def show_interface(self, _args):
        print self.interface

    params_all["iface"]     = show_interface
    params_all["interface"] = show_interface

    # set "self.interface" to specified value or get default
    # also obtains "self.mac" and "self.range" automatically
    def set_interface(self, args):
        
        # set interface to specified value "args[0]", or default
        # mac and ip range will be different for another interface and are thus set automatically
        try:
            self.interface = self.default_interface() if args[0] == "default" else args[0]
            self.own_mac   = self.default_mac()
            self.range_    = self.default_range()

        # if "args" is empty, no value is specified and "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: No value specified"
    
    params_mut["iface"]     = set_interface
    params_mut["interface"] = set_interface

    # return default network interface (interface of default gateway)
    def default_interface(self):
    
        # "netifaces.gateways()" returns a dictionary of available gateways, where "'default', netifaces.AF_INET" is the key to the default gateway (if found)
        # the format is then "(ip, interface)", so we retrieve the second element
        try:
            return netifaces.gateways()["default"][netifaces.AF_INET][1].encode("ascii")

        # generic error message
        except:
            print "E: Could not find default gateway. Configure manually if needed."

    # simply print own mac address
    def show_mac(self, _args):
        print self.own_mac

    params_all["mac"] = show_mac

    # manually configure own mac address
    def set_mac(self, args):
        self.own_mac = self.default_mac() if args[1] == "default" else args[1]

    params_mut["mac"] = set_mac

    # return own mac address on interface "self.interface"
    def default_mac(self):

        # "netifaces.ifaddresses(self.interface)" returns a dictionary of own network addresses, where "netifaces.AF_LINK" is the key to link layer addresses and "0,'addr'" retrieves own mac address
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"].encode("ascii")

        # generic error message
        except:
            print "E: Could not find own MAC address. Configure manually if needed"

    # simply print ip range of local network
    def show_range(self, _args):
        print self.range_

    params_all["range"] = show_range

    # manually configure ip range
    def set_range(self, args):

        try:
            self.range_ = self.default_range() if args[1] == "default" else args[1]

        # if "args" is empty, no value is specified and "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: No value specified"

    params_mut["range"] = set_range

    # return ip range of local network
    def default_range(self):

        # "netifaces.ifaddresses(self.interface)" returns a dictionary of own network addresses, where "netifaces.AF_INET" is the key to ipv4 addresses and "0," retrieves own ip address
        try:
            addrs = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]
            return addrs["addr"] + "/" + addrs["netmask"]

        # generic error message
        except:
            print "E: Could not find default gateway. Configure manually if needed."

    # simply print timeout parameter for scanning
    def show_timeout(self, _args):
        print self.timeout

    params_all["timeout"] = show_timeout

    # set timeout parameter
    def set_timeout(self, args):

        # parse specified value as float and set "self.timeout"
        try:
            self.timeout = float(args[0])
        
        # if "args" is empty, no value is specified and "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: no value specified"

        # specified value "args[0]" cannot be parsed as float
        except:
            print "E: Could not parse input \"{}\" as number".format(args[0])

    params_mut["timeout"] = set_timeout

    # show gateway's ip address, obtained from scanning
    def show_gateway(self, _args):
        print "gateway at {}".format(self.gateway.ip)

    params_all["gateway"] = show_gateway

    # show hosts' (excluding gateway) ip addresses, obtained from scanning
    # also prints integers indexing hosts
    def show_hosts(self, _args):
        print "\n".join(["{}: host at {}".format(i, self.hosts[i].ip) for i in range(len(self.hosts))])

    params_all["hosts"] = show_hosts

    # scan for hosts (and gateway) on local network
    def scan(self, args):
    
        # "get_hosts" function from file "hosts.py"
        self.gateway, self.hosts = get_hosts(self.interface, self.range_, self.timeout)
        
        # show found gateway ip or print warning message
        if self.gateway:
            self.show_gateway(None)

        else:
            print "W: No gateway found"

        # show found host ip's or print warning message
        if self.hosts:
            self.show_hosts(None)

        else:
            print "W: No hosts found"
        
        self.prompt()
        
    commands["scan"] = scan

    # easy access to terminal commands without having to quit
    # can even start a new terminal session with "os su"
    def os_(self, args):
        os.system(" ".join(args[1:]))
        self.prompt()

    commands["os"] = os_

    # reset ip forwarding and quit (by not calling "self.prompt()" again)
    def quit_(self, _args):
        os.system("echo {} > /proc/sys/net/ipv4/ip_forward".format(self.ip_forward))

    commands["quit"] = quit_

    # return target specified by argument
    def get_target(self, args):
        
        # return specified host
        try:
            return self.hosts[int(args[1])]

        # specified input cannot be parsed as integer
        except TypeError as _:
            print "E: Could not parse input \"{}\" as integer".format(args[1])

        # if no (or a non-existent) host is specified, "self.hosts[int(args[1])]" will throw an IndexError
        except IndexError as _:
            print "E: No or non-existent host specified"

    # main arp command, calls subcommands 
    def arp(self, args):

        # obtain and call function specified by subcommand
        # e.g. "arp mitm foo" calls ".arp_mitm(['foo'])"
        try:
            self.commands[".arp_" + args[0]](self, args[1:])
        
        # if unknown command is specified, "self.commands['.arp_' + args[0]]" will throw a KeyError
        except KeyError as _:
            print "E: Unknown command \"arp {}\"".format(args[0])

        # if no command is specified, "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: No command specified"

    commands["arp"] = arp

    # give a prompt to the user to specify addresses for one-way arp poisoning
    # not needed for mitm attack as the gateway is used there
    # TODO kun je überhaupt een andere mac gebruiken?
    def arp_set_addrs(self):

        # user input
        ip_to_spoof  = raw_input("IP address to spoof (leave empty for gateway address): ")
        mac_to_spoof = raw_input("MAC address to lead to (leave emtpy for own address): ")

        # set "ip_to_spoof" to gateway ip if none specified
        if not ip_to_spoof:
            ip_to_spoof = 

        # set "mac_to_spoof" to own mac if none specified
        if not mac_to_spoof:
            mac_to_spoof = self.own_mac

        return ip_to_spoof, mac_to_spoof

    # prepare and start one-way arp poisoning attack against specified host
    # addresses to spoof are obtained by a prompt
    def arp_oneway(self, args):

        target = self.get_target(args)
        ip_to_spoof, mac_to_spoof = self.arp_set_addrs()
        target.arp_attack(True, ip_to_spoof, mac_to_spoof)
        target.arp_start()
        self.prompt()

    # prepare and start man-in-the-middle arp poisoning attack agains specified host
    def arp_mitm(self, args):

        target = self.get_target(args)
        ip_to_spoof, mac_to_spoof = self.gateway.ip, self.own_mac
        target.arp_attack(False, ip_to_spoof, mac_to_spoof)
        target.arp_start()
        self.prompt()

    # stops arp poisoning attack against specified host
    def arp_stop(self, args):

        target = self.get_target(args)
        target.arp_stop()
        self.prompt()

    commands[".arp_oneway"] = arp_oneway
    commands[".arp_mitm"]   = arp_mitm
    commands[".arp_stop"]   = arp_stop

    # ensure that man-in-the-middle arp poisoning attack is running against specified host
    def ensure_mitm(self, target):
        
        if target.arp_active:
            
            # mitm attack against target is already running, so do nothing
            if target.arp_attack == "mitm":
                pass

            # one-way arp poisoning attack is running against target, so stop it and run mitm attack instead
            else:
                target.arp_stop()
                self.arp_mitm(["mitm", "target"])

        else:

            # mitm attack is prepared but not running, so just start it
            if target.arp_attack == "mitm":
                target.arp_start()

            # mitm attack is not yet prepared, so prepare and start it
            else:
                self.arp_mitm(["mitm", "target"])

    # main dns command, calls subcommands
    def dns(self, args):

        # obtain and call function specified by subcommand
        # e.g. "dns poison foo" calls ".dns_poison(['foo'])"
        try: 
            self.commands[".dns_" + args[0]](self, args[1:])
    
        # if unknown command is specified, "self.commands['.dns_' + args[0]]" will throw a KeyError
        except KeyError as _:
            print "E: Unknown command \"dns {}\"".format(args[0])

        # if no command is specified, "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: No command specified"

    commands["dns"] = dns

    # prompt user to add url and ip to spoof, use own ip by default
    def dns_set_addrs(self):

        # user input
        url_to_spoof = raw_input("URL to spoof: ")
        ip_to_spoof  = raw_input("IP address to lead to (leave empty for own address): ")

        # if no ip is specified, use own ip
        # TODO eigen ip onafhankelijk opslaan van range
        if not ip_to_spoof:
            ip_to_spoof = self.range_.split('/')[0]

        return url_to_spoof, ip_to_spoof

    # set up and start dns poisoning attack against specified host
    def dns_start(self, args):

        # get target and ensure that mi
        target = self.get_target(args)
        self.ensure_mitm(target)

        # add url to spoof via user prompt
        # TODO meerdere urls mogelijk maken
        url_to_spoof, ip_to_spoof = self.dns_set_addrs()
        target.dns_add(url_to_spoof, ip_to_spoof)

        # start dns attack
        target.dns_start()
        self.prompt()

    commands[".dns_poison"] = dns_start

    # stop dns attack against specified host
    def dns_stop(self, args):
        
        target = self.get_target(args)
        target.dns_stop()
        self.prompt()

    commands[".dns_stop"] = dns_stop

# create and start cli
if __name__ == "__main__":

    cli = CLI()
    cli.prompt()
