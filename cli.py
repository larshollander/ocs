from collections import defaultdict
import netifaces

from hosts import get_hosts


class CLI:

    commands   = {}
    show_params = {}
    set_params = {}

    def __init__(self):

        self.interface = self.default_interface()
        self.range_    = self.default_range()
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

        self.run()

    commands["set"] = set_

    def show_interface(self, args):
        print self.interface

    show_params["iface"] = show_interface
    show_params["interface"] = show_interface

    def set_interface(self, args):
        self.interface = self.default_interface() if args[1] == "default" else args[1]
    
    set_params["iface"] = set_interface
    set_params["interface"] = set_interface

    def default_interface(self):
        try:
            return netifaces.gateways()["default"][netifaces.AF_INET][1].encode("ascii")
        except:
            print "E: Could not find default gateway. Configure manually if needed."

    def show_range(self, args):
        print self.range_

    show_params["range"] = show_range

    def set_range(self, args):
        self.range_ = self.default_range if args[1] == "default" else args[1]

    set_params["range"] = set_range

    def default_range(self):
        try:
            addrs = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]
            return addrs["addr"] + "/" + addrs["netmask"]
        except:
            print "E: Could not find default gateway. Configure manually if needed."

    def scan(self, _args):

        self.gateway, self.hosts = get_hosts(self.interface, self.range_, self.timeout)
        
        if not self.gateway:
            print "W: no gateway found"

        if not self.hosts:
            print "W: no hosts found"
        
        self.run()
        
    commands["scan"] = scan

    def quit_(self, _args):
        pass

    commands["quit"] = quit_


if __name__ == "__main__":

    cli = CLI()

    cli.run()
