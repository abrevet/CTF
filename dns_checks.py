import sys
import dns.reversename as reversename
import dns.resolver as resolver
import dns.message
import dns.asyncquery
import dns.asyncresolver
import dns.zone
import dns.exception

import whois

DNS_RESOLVER = "1.1.1.1"

def dns_req_domain_name(domain_name=None, REQ_TYPE="A", verbose=False):
        try:
                answer = dns.resolver.query(domain_name, REQ_TYPE)
                if not verbose:
                    print("[+] " + str(domain_name) + " : " + str(answer[0]))
                return 1, str(answer[0])
        except dns.resolver.NXDOMAIN:
                if not verbose:
                    print("[.] Resolved but no entry for " + str(domain_name))
                return 2, None
        except dns.resolver.NoNameservers:
                if not verbose:
                    print("[-] Answer refused for " + str(domain_name))
                return 3, None
        except dns.resolver.NoAnswer:
                if not verbose:
                    print("[-] No answer section for " + str(domain_name))
                return 4, None
        except dns.exception.Timeout:
                if not verbose:
                    print("[-] Timeout")
        return 5, None

def dns_reverse_lookup(address, REQ_TYPE="PTR"):
    try:
            resolved = resolver.query(
                reversename.from_address(address),
                 REQ_TYPE)[0]
            print("DNS Reverse lookup result: ", resolved)
    except:
            print("Cannot make DNS reverse lookup from address ", address)
        
    return resolved

def check_zone_transfer(domain):

        LIFETIME = 5.0
        nservers = []


        # Attempt to get a list of nameservers for the domain. Quit if there are any
        # problems.
        try:
                nservers = [n.to_text() for n in dns.resolver.query(domain, 'NS')]

        except:
                print("Unable to get nameserver(s) for AXFR DNS vuln check")
                sys.exit(1)
                
    

        # Check each nameserver for zone transfer. If there are any issues move to
        # the next server.
        resp = ['DOMAIN: {0}'.format(domain), '=' * (len(domain) + 8)]

        for ns in nservers:
                try:
                        z = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=LIFETIME))
                        recs = [z[n].to_text(n) for n in z.nodes.keys()]

                        resp.append('NS: {0}'.format(ns))
                        resp.append('-' * (len(ns) + 4))
                        resp.extend(recs)
                        resp.append('')

                except:
                        continue
        if len(resp) > 2:
                print("AXFR answer found for ", domain )
                print("Response: ", resp)
                filename = '{0}.axfr'.format(domain)
                with open(filename, 'w') as f:
                        f.write('\n'.join(resp))

def get_nameservers_whois(domain):
        request = whois.whois(domain)
