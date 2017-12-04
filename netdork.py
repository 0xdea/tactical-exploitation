#!/usr/bin/env python3

"""
netdork.py 0.1 - Google Custom Search Network Recon Tool
Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>

"The Other Way to Pen-Test" --HD Moore & Valsmith

Netdork is a Python script that uses the Google Custom
Search Engine API to collect interesting information on
public networks and stealthily map the available attack
surface. The following attacks are supported:

ipaddr: network search sweep based on target CIDRs
domain: subdomain discovery via search engine

Beware that Google enforces a hard limit of 100 free
searches per day. Use it wisely! 

Based on:
http://www.0xdeadbeef.info/code/scan-tools.tgz (gsw)
http://www.securityfocus.com/archive/101/422607/30/0/

Requirements (see also https://goo.gl/TRoQVT):
1. Make sure you have Python 3 installed
   (https://www.python.org/downloads/)
2. Get a Google API key
   (https://goo.gl/aQ1TR8)
3. Setup Custom Search Engine to search the entire web
   (https://cse.google.com/)
4. Enable the Custom Search API
   (https://console.developers.google.com/apis/)
5. Install the Google API client for Python and other
   dependencies:
   $ pip3 install google-api-python-client
   $ pip3 install netaddr

Example usage:
$ ./netdork.py ipaddr -t x.x.x.x/29
$ ./netdork.py domain -t test.com

TODO:
32 words limit bypass (siteSearch, siteSearchFilter)?
Implement optional automatic recursive subdomain search
Perform a reverse DNS lookup and search for hostnames
HTML reporting in the style of https://goo.gl/tv2BZF
Implement Bing support (Microsoft Cognitive Services)
Test https://github.com/tristantao/py-ms-cognitive
Implement support for other less greedy search engines;)

Get the latest version at:
https://github.com/0xdea/tactical-exploitation/
"""

VERSION = "0.1"
BANNER = """
netdork.py {0} - Google Custom Search Network Recon Tool
Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
""".format(VERSION)

# fill in with your own api key from https://console.developers.google.com/
GOOGLE_API_KEY = ""
# fill in with your own search engine id from https://cse.google.com/
GOOGLE_CSE_ID = ""

import sys
import argparse
import netaddr
from googleapiclient.discovery import build

def google_search(search_str, api_key, cse_id, **kwargs):
    """
    Search with Google Custom Search Engine API
    """

    # build a service object for interacting with the api
    service = build("customsearch", "v1", developerKey=api_key)

    # perform the search (see https://goo.gl/uVBZBf)
    res = service.cse().list(q=search_str, cx=cse_id, **kwargs).execute()
    return res

def ipaddr(args):
    """
    Perform network search sweep
    """

    targets = get_targets(args)

    for entry in targets:

        # try to resolve cidr
        try:
            net = netaddr.IPNetwork(entry)
        except (KeyboardInterrupt, SystemExit):
            sys.exit(1)
        except Exception as err:
            print("// error: {0}\n".format(err))
            continue

        print("*** Scanning target IP network range {0} ***\n".format(entry))
        found = 0

        # scan the target cidr
        for ip in net:

            print(ip)
            results = google_search(
                    ip,
                    GOOGLE_API_KEY,
                    GOOGLE_CSE_ID,
                    filter="0",
                    safe="off",
                    num=10)

            try: # found some results
                for item in results["items"]:
                    print("\t" + item["link"])
                found += 1

            except (KeyboardInterrupt, SystemExit):
                sys.exit(1)

            except: # no results found
                pass

        print("\n*** {0} interesting addresses found on {1} ***\n"
                .format(found, entry))

def domain(args):
    """
    Perform subdomain discovery

    Note that Google processes a maximum of 32 words in
    the search string. This means that we're gonna miss
    some results on large network perimeters, regardless
    of our optimizations.
    """

    targets = get_targets(args)
    max_tries = args.m

    for dom in targets:

        print("*** Scanning target domain {0} ***\n".format(dom))
        subdomains = set()

        # scan the target domain
        for i in range(max_tries):

            search_str = build_domain_search(dom, subdomains)
            #print(search_str) # debug

            if not search_str:
                print("// warning: 32 words limit reached\n")
                break

            results = google_search(
                    search_str,
                    GOOGLE_API_KEY,
                    GOOGLE_CSE_ID,
                    filter="0", # filter="1" causes more searches?!
                    safe="off",
                    num=10)

            try: # found some results
                last = 1
                for item in results["items"]:
                    if item["displayLink"] != dom: last = 0
                    subdomains.add(item["displayLink"])
                    #print(item["displayLink"]) # debug
                if last:
                    print("// warning: only the base domain is left\n")
                    break

            except (KeyboardInterrupt, SystemExit):
                sys.exit(1)

            except: # no results found
                break

        # print results
        if subdomains:
            for sub in sorted(subdomains):
                if dom_level(sub) > dom_level(dom) + 1:
                    print(sub + " // subdomain should be scanned too")
                else:
                    print(sub)
        else:
            print("// error: no results found")

        if i == (max_tries - 1):
            print("\n// warning: max tries reached")
        print("\n*** {0} subdomains found on {1} ({2} tries) ***\n"
                .format(len(subdomains), dom, i + 1))

def build_domain_search(dom, subdomains):
    """
    Build domain search string
    """

    search_str = "site:" + dom
    exclusions = set()

    # exclude known subdomains (optimization: +1 level)
    for sub in sorted(subdomains):
        if dom_level(sub) > dom_level(dom):
            exc = sub.split(sep=".", maxsplit=dom_level(sub)-dom_level(dom)-1)
            exclusions.add(exc[-1])
    for exc in sorted(exclusions):
        search_str += " -site:" + exc

    if len(exclusions) > 31: return
    return search_str

def dom_level(dns_name):
    """
    Get domain level
    """

    return dns_name.count(".")

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
            help="choose mode of operation")

    # ipaddr mode
    parser_i = subparsers.add_parser(
            "ipaddr",
            help="enter ipaddr mode")
    parser_i.set_defaults(func=ipaddr)

    # ipaddr args
    group_i_targets = parser_i.add_mutually_exclusive_group(required=True)
    group_i_targets.add_argument(
            "-t",
            metavar="CIDR",
            help="specify target network CIDR")
    group_i_targets.add_argument(
            "-f",
            metavar="FILE",
            type=argparse.FileType("r"),
            help="specify file containing a list of CIDRs")

    # domain mode
    parser_d = subparsers.add_parser(
            "domain",
            help="enter domain mode")
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
            "-m",
            metavar="MAX",
            type=int,
            default=10,
            help="specify maximum number of searches (default: 10)")

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

    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
        print("// error: please fill in GOOGLE_API_KEY and GOOGLE_CSE_ID")
        sys.exit(1)

    args = get_args()

    try:
        args.func(args)
    except (KeyboardInterrupt, SystemExit):
        sys.exit(1)
    except Exception as err:
        print("// error: {0}".format(err))
        sys.exit(1)

if __name__ == "__main__":
    main()
