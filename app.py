"""
Author: adamsb0
Project: Starting steps for CTF
Description: ?
Version: ?
How to: ?
Dependencies:
    dnspython
    nmap (nmap soft must be installed on OS)
    python-whois
Note:
    Try as much as we can to get rid of dependencies
"""

import time, sys, os, re, argparse

#Import nmap
import nmap

#For async functions
import trio

#Custom librairies
import dns_checks
import utils

#print("🐱 🐱 🐱 🐱 🐱 🐱 🐱")
#print("Cat Hunter by Adamsb0")
#print("🐱 🐱 🐱 🐱 🐱 🐱 🐱")
#print("-----------------------------")


start = time.time()

#Handle arguments
parser = argparse.ArgumentParser(description='Parameters:')

#NMAP parameters (input checks are done here)
nmap_params= parser.add_argument_group('NMAP Parameters: ')
nmap_params.add_argument("-host", type=utils.ip_type ,help="Host to scan, e.g 0.0.0.0. Subnet are not supported yet ")

#Domain name parameters (input checks are done here)
domain_params= parser.add_argument_group('Domain name parameters: ')
domain_params.add_argument("-domain", required=False, type=utils.domain_type ,help="Domain to scan, e.g test.com")

#TODO: add ASN, website check
#parser.add_argument("--asn", required=True, help="ASN to scan") 
#parser.add_argument("--website", required=True, help="Subnet to scan")

args = parser.parse_args()

if len(args)==1:
		parser.print_help()
		sys.exit(1)

ip_addr = args.host
domain_name = args.domain
resolved = ""


#Step 1: Nmap basic test (TCP SYN connect scan, verbose on)
scanner = nmap.PortScanner()
print("Nmap Version: ", scanner.nmap_version())
params = input("TCP or UDP scan ? Default [TCP] ")
port_range = input("Port range to scan (format XX-YY) ? Default [22-443] ")
#Check for UDP
if params == "UDP":
    #Check for user-defined scan port-range
    if port_range:
        scanner.scan(ip_addr, port_range ,'-v -sU')
        print("Nmap parameters : ", scanner.scaninfo())
        open_ports = list(scanner[ip_addr]['udp'])
    else:
        scanner.scan(ip_addr, "22-443" ,'-v -sU')
        print("Nmap parameters : ", scanner.scaninfo())
        open_ports = list(scanner[ip_addr]['udp'])
else:
    if port_range:
        scanner.scan(ip_addr, port_range ,'-v -sS')
        print("Nmap parameters : ", scanner.scaninfo())
        open_ports = list(scanner[ip_addr]['tcp'])
    else:
        scanner.scan(ip_addr,"22-443" ,'-v -sS')
        print("Nmap parameters : ", scanner.scaninfo())
        open_ports = list(scanner[ip_addr]['tcp'])

print("Open Ports: ", open_ports)

#Step 2: Run actions based on open ports

for port in open_ports:
    if (port == 53):
        print("-----------------------------")
        if domain_name:
            print("Launching DNS recognition for ", domain_name)
            req_type = input("DNS REQ TYPE (A, AAAA, MX, ...). Default [A] : ")
        else:
            print("Launching DNS recognition for ", ip_addr)
            req_type = ""

        if req_type != "":
            print("REQ TYPE: ", req_type)
            if domain_name != None:
                dns_checks.dns_req_domain_name(domain_name, req_type)
            else:
                resolved = dns_checks.dns_reverse_lookup(ip_addr, req_type)
        else:
            if domain_name != None:
                dns_checks.dns_req_domain_name(domain_name)
            else:
                resolved = dns_checks.dns_reverse_lookup(ip_addr)
        
        print("--------------------------------")
        print("Launching WHOIS for ", domain_name)
        nameservers = dns_checks.get_nameservers_whois()

        print("--------------------------------")
        if resolved:
            print("Launching zone transfer (AXFR) vuln check for " + resolved)
            dns_checks.check_zone_transfer(resolved)
        else:
            print("Launching zone transfer (AXFR) vuln check for " + domain_name)
            dns_checks.check_zone_transfer(domain_name)


    elif (port == 135):
        print("Launching NetBios recognition... ")
        dns_checks.dns_req(ip_addr)
    elif (port == 137):
        print("Launching MSRPC recognition... ")

