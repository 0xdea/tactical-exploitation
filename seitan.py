#!/usr/bin/env python3

"""
seitan.py 0.1 - OSINT Tool Built on Shodan.io API Search
Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>

"The Other Way to Pen-Test" --HD Moore & Valsmith

Seitan is a Python script that uses the Shodan.io API
search to collect open source intelligence on targets.

The following attacks are currently supported:
ipaddr: view all available information for an IP address
domain: search services related to a domain or host name

In order to use this tool you will need a valid API key
from https://account.shodan.io/, the shodan-python
library, and the netaddr module:
$ pip3 install shodan
$ pip3 install netaddr

Example usage:
$ ./seitan.py ipaddr -f targets.txt # ipaddr scan
$ ./seitan.py domain -t test.com # domain scan
$ ./seitan.py domain -t test.com -S # domain scan (ssl)

TODO:
Implement additional search methods (e.g. Amazon S3)
Expand information displayed for SSL/TLS services
Add download/parse/convert capabilities
Add on-demand scanning functionality (Shodan.scan)

Get the latest version at:
https://github.com/0xdea/tactical-exploitation/
"""

VERSION = "0.1"
BANNER = """
seitan.py {0} - OSINT Tool Built on Shodan.io API Search
Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
""".format(VERSION)

# fill in with your own api key from https://account.shodan.io/
SHODAN_API_KEY = ""

import sys
import argparse
import time
import netaddr
import shodan

def init(api_key):
    """
    Initialize the Shodan API
    """

    # load api key and print credits
    api = shodan.Shodan(SHODAN_API_KEY)
    info(api)

    return api

def info(api):
    """
    Print currently available credits
    """

    info = api.info()

    print("Active plan:\t{}".format(info["plan"]))
    print("Query credits:\t{}".format(info["query_credits"]))
    print("Scan credits:\t{}\n".format(info["scan_credits"]))

def search(api, search_str, limit):
    """
    Search with Shodan API
    """

    try:
        res = api.search(search_str, limit=limit)

        for banner in res["matches"]:

            # header
            print("[", end="")
            if "ip_str" in banner and banner["ip_str"]:
                print(banner["ip_str"], end=", ")
            if "hostnames" in banner and banner["hostnames"]:
                for hostname in banner["hostnames"]:
                    print(hostname, end=", ")
            if "os" in banner and banner["os"]:
                print(banner["os"], end=", ")
            if "port" in banner and banner["port"]:
                print(banner["port"], end=", ")
            if "timestamp" in banner and banner["timestamp"]:
                date = banner["timestamp"][:10]
                print(date, end="")
            print("]\n")

            # service information
            if "ssl" in banner and banner["ssl"]["cert"]["subject"]:
                b = banner["ssl"]["cert"]["subject"]
                for field in b:
                    print("{}: {}".format(field, b[field]))
                print()
            if "data" in banner and banner["data"]:
                print(banner["data"].rstrip(), end="\n\n")
        
    except shodan.APIError as err:
        print("\t// error: {}\n".format(err))
        return 0

    return res["total"]

def ipaddr(args):
    """
    View all available information for an IP address (based on Shodan CLI tool)
    """

    api = init(SHODAN_API_KEY)
    targets = get_targets(args)
    history = args.history
    minify = args.minify
    found_glob = 0

    for entry in targets:

        # try to resolve cidr
        try:
            net = netaddr.IPNetwork(entry)
        except (KeyboardInterrupt, SystemExit):
            sys.exit(1)
        except Exception as err:
            print("// error: {}\n".format(err))
            continue

        print("*** Scanning target IP network range {} ***".format(entry))
        found = 0

        # scan the target cidr
        for ip in net:

            ip = str(ip)
            print("\n{}".format(ip))

            try:
                res = api.host(ip, history=history, minify=minify)

                # general information
                if len(res["hostnames"]):
                    print("\t{:25s}{}"
                            .format("Hostnames:", ";".join(res["hostnames"])))
                if "org" in res and res["org"]:
                    print("\t{:25s}{}".format("Organization:", res["org"]))
                if "city" in res and res["city"]:
                    print("\t{:25s}{}".format("City:", res["city"]))
                if "country_name" in res and res["country_name"]:
                    print("\t{:25s}{}".format("Country:", res["country_name"]))
                if "os" in res and res["os"]:
                    print("\t{:25s}{}".format("Operating System:", res["os"]))

                # vulnerability information
                if "vulns" in res and len(res["vulns"]):
                    vulns = []
                    for vuln in res["vulns"]:
                         if vuln.startswith("!"): continue
                         vulns.append(vuln)
                    if len(vulns):
                        print("\t{:25s}".format("Vulnerabilities:"), end="")
                        for vuln in vulns:
                            print(vuln + "\t", end="")
                        print()

                # service information
                print("\t{:25s}{}"
                        .format("Number of open ports:", len(res["ports"])))
                if not minify:
                    print("\tPorts:")
                for banner in sorted(
                        res["data"], 
                        key=lambda k: (k["port"], k["timestamp"])
                        ):
                    product = ""
                    if "product" in banner and banner["product"]:
                        product = banner["product"]
                    version = ""
                    if "version" in banner and banner["version"]:
                        version = "({})".format(banner["version"])
                    print("\t{:>7d}".format(banner["port"]), end=" ")
                    if "timestamp" in banner and banner["timestamp"]:
                        date = banner["timestamp"][:10]
                        print("\t{}".format(date), end="")
                    print("\t{} {}".format(product, version), end="")
                    print()

            except shodan.APIError as err:
                print("\t// error: {}".format(err))

            else:
                found += 1

            # throttle requests to work around shodan request limit
            time.sleep(1)

        found_glob += found
        print("\n*** {} interesting addresses found on {} ***\n"
                .format(found, entry))

    print("*** {} interesting addresses found globally ***\n"
            .format(found_glob))

    info(api)

def domain(args):
    """
    Search services related to a domain or host name
    """

    api = init(SHODAN_API_KEY)
    targets = get_targets(args)
    limit = args.l
    ssl = args.ssl

    # scan the target domains
    for dom in targets:

        # ssl cert based search
        if ssl:
            search_str = "ssl:{}".format(dom)
            print("*** Scanning target domain {} (ssl cert based) ***\n"
                    .format(dom))

        # hostname based search
        else:
            search_str = "hostname:{}".format(dom)
            print("*** Scanning target domain {} (hostname based) ***\n"
                    .format(dom))

        # enforce hard limit of 1000 results (100 pages)
        if limit > 1000:
            limit = 1000
            print("// warning: enforcing a hard limit of 1000 results\n")

        # perform the actual search
        count = search(api, search_str, limit)

        # throttle requests to work around shodan request limit
        time.sleep(1)

        if limit > count:
            limit = count
        print("*** Displayed {} results out of {} for domain {} ***\n"
                .format(limit, count, dom))

    info(api)

def get_targets(args):
    """
    Get targets from command line or file
    """

    if args.t: return [args.t]
    return [t.rstrip() for t in args.f]

def get_args():
    """
    Get command line arguments
    """

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
            title="commands",
            help="choose action")

    # ipaddr scan
    parser_h = subparsers.add_parser(
            "ipaddr",
            help="ipaddr scan")
    parser_h.set_defaults(func=ipaddr)

    # ipaddr args
    group_h_targets = parser_h.add_mutually_exclusive_group(required=True)
    group_h_targets.add_argument(
            "-t",
            metavar="CIDR",
            help="specify target network CIDR")
    group_h_targets.add_argument(
            "-f",
            metavar="FILE",
            type=argparse.FileType("r"),
            help="specify file containing a list of CIDRs")
    parser_h.add_argument(
            "-H", "--history",
            action="store_true",
            help="include historical (non-current) services")
    parser_h.add_argument(
            "-M", "--minify",
            action="store_true",
            help="only return general information")

    # domain scan
    parser_d = subparsers.add_parser(
            "domain",
            help="domain scan")
    parser_d.set_defaults(func=domain)

    # domain args
    group_d_targets = parser_d.add_mutually_exclusive_group(required=True)
    group_d_targets.add_argument(
            "-t",
            metavar="DOMAIN",
            help="specify target domain name")
    group_d_targets.add_argument(
            "-f",
            metavar="FILE",
            type=argparse.FileType("r"),
            help="specify file containing a list of domain names")
    parser_d.add_argument(
            "-l",
            metavar="LIMIT",
            type=int,
            default=100,
            help="maximum number of results to return (default: 100)")
    parser_d.add_argument(
            "-S", "--ssl",
            action="store_true",
            help="search SSL Common Name instead of hostname")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    return parser.parse_args()

def main():
    """
    Main function
    """

    print(BANNER)

    if sys.version_info[0] != 3:
        print("// error: this script requires python 3")
        sys.exit(1)

    if not SHODAN_API_KEY:
        print("// error: please fill in SHODAN_API_KEY")
        sys.exit(1)

    args = get_args()

    try:
        args.func(args)
    except (KeyboardInterrupt, SystemExit):
        sys.exit(1)
    except Exception as err:
        print("// error: {}".format(err))
        sys.exit(1)

if __name__ == "__main__":
    main()
