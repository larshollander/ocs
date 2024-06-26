class HelpFor():

    help_for = {}

    def __init__(self, commands, params_all, params_mut):
        self.commands   = sorted(commands)
        self.params_mut = sorted(params_mut)
        self.params_imm = sorted([key for key in params_all.keys() if not key in params_mut])

    def __call__(self, args):

        try:
            self.help_for[args[0]](self, args[1:])

        except KeyError as _:
            print "E: Unknown command \"{}\"".format(args[0])

        except IndexError as _:
            print "available commands:"
            print "\n".join([" " + command for command in self.commands if command[0] != '.'])
            print "use \"help [command]\" for information about a specific command"

    ### list parameters ###

    def list_params(self, _args):
        print "mutable parameters:"
        print "\n".join([" " + param for param in self.params_mut])
        print "immutable parameters:"
        print "\n".join([" " + param for param in self.params_imm])

    help_for["params"] = list_params

    ### help commands ###

    def help_help(self, _args):
        print "usage: help [command]"
        print "displays help for specified command"

    help_for["help"] = help_help

    def help_params(self, _args):
        print "usage: params"
        print "lists available parameters"

    def help_scan(self, _args):
        print "usage: scan"
        print "find hosts and gateway specified by range parameter"

    help_for["scan"] = help_scan

    def help_os(self, _args):
        print "usage: os [command]"
        print "executes the specified terminal command"

    help_for["os"] = help_os

    def help_quit(self, _args):
        print "usage: quit"
        print "exits the program"

    help_for["quit"] = help_quit

    def help_show(self, _args):
        print "usage: show [parameter]"
        print "shows the specified parameter"

    help_for["show"] = help_show

    def help_set(self, _args):
        print "usage: set [parameter] [value]"
        print "assigns the specified value to the specified parameter"

    help_for["set"] = help_set

    def help_arp(self, args):

        try:
            self.help_for["arp_" + args[0]](self, args[1:])

        except KeyError as _:
            print "E: Unknown command \"arp {}\"".format(args[0])

        except IndexError as _:
            print "usage: arp [command] [host]"
            print "available commands:"
            print "\n".join([" " + command[5:] for command in self.commands if command[:5] == ".arp_"])
            print "host can be specified by index or address"

    help_for["arp"] = help_arp

    def help_arp_oneway(self, _args):
        print "usage: arp oneway [host]"
        print "starts one-way arp poisoning attack against specified host"
        print "a prompt will appear to specify the IP address to spoof"

    help_for["arp_oneway"] = help_arp_oneway
    
    def help_arp_mitm(self, _args):
        print "usage: arp mitm [host]"
        print "starts a man-in-the-middle arp poisoning attack between the specified host and the gateway"

    help_for["arp_mitm"] = help_arp_mitm

    def help_arp_restore(self, _args):
        print "usage: arp resotre [host]"
        print "restores the arp table of the specified host to its pre-spoof state"
        print "use after stopping all currently running arp poisoning attacks"

    help_for["arp_restore"] = help_arp_restore

    def help_arp_stop(self, _args):
        print "usage: arp stop [host]"
        print "stops the arp poisoning attack against the specified host"
        print "use \"arp stop all\" to stop all currently running arp poisoning attacks"

    help_for["arp_stop"] = help_arp_stop

    def help_dns(self, args):

        try:
            self.help_for["dns_" + args[0]](self, args[1:])

        except KeyError as _:
            print "E: Unknown command \"dns {}\"".format(args[0])

        except IndexError as _:
            print "usage: dns [command] [host]"
            print "available commands:"
            print "\n".join([" " + command[5:] for command in self.commands if command[:5] == ".dns_"])
            print "host can be specified by index or address"

    help_for["dns"] = help_dns

    def help_dns_add(self, _args):
        print "usage: dns add [host]"
        print "add a url/ip combination to spoof"
        print "a prompt will appear to specify both"
        print "wildcards are permitted, e.g. \"*.google.com\""

    help_for["dns_add"] = help_dns_add

    def help_dns_poison(self, _args):
        print "usage: dns poison [host]"
        print "starts a dns poisoning attack against the specified host"

    help_for["dns_poison"] = help_dns_poison

    def help_dns_stop(self, _args):
        print "usage: dns stop [host]"
        print "stops the dns poisoning attack against the specified host"
        print "use \"dns stop all\" to stop all currently running dns poisoning attacks"

    help_for["dns_stop"] = help_dns_stop

    def help_ssl(self, args):

        try:
            self.help_for["ssl_" + args[0]](self, args[1:])

        except KeyError as _:
            print "E: Unknown command \"ssl {}\"".format(args[0])

        except IndexError as _:
            print "usage: ssl [command] [host]"
            print "available commands:"
            print "\n".join(["    " + command[5:] for command in self.commands.keys() if command[:5] == ".ssl_"])
            print "host can be specified by index or address"

    help_for["ssl"] = help_ssl

    def help_ssl_strip(self, _args):
        print "usage: ssl strip [host]"
        print "starts ssl stripping against the specified host"

    help_for["ssl_strip"] = help_ssl_strip

    def help_ssl_stop(self, _args):
        print "usage: ssl stop [host]"
        print "stops ssl stripping against the specified host"
        print "use \"ssl stop all\" to stop all currently running ssl stripping"

    help_for["ssl_stop"] = help_ssl_stop
