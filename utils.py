import argparse
import re

#Regex for domain name check
def domain_type(arg_value, pat=re.compile(r"(?=^.{1,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")):
        if not pat.match(arg_value):
            raise argparse.ArgumentTypeError("Domain name incorrect. Please check format or run --help")
        return arg_value

#Regex for IP  check
#TODO: add regex match for subent (with subnet number /XX)
#TODO: add support for IPv6 ?? usefull ?
def ip_type(arg_value, pat=re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")):
        if not pat.match(arg_value):
            raise argparse.ArgumentTypeError("IP address/subnet incorrect. Please, check format or run --help")
        return arg_value