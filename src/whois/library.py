#!/usr/bin/env python
""" whois - Internet domain name and network number directory service
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import datetime
import hashlib
import ipaddress
import logging
import lzma
import os
import pathlib
import re
import socket
import sys


####################################################################################################
def _get_port_by_name(service, protocol):
    """ Find a port number in the services database """
    services_database = "/etc/services"
    if os.name == "nt":
        services_database = "C:\\Windows\\System32\\drivers\\etc\\services"

    if os.path.isfile(services_database):
        lines = []
        with open(services_database, "r", encoding="utf-8", errors="ignore") as txtfile:
            lines = txtfile.readlines()
        for line in lines:
            # Discard comments
            line = re.sub(r"#.*", "", line)

            parts = line.split()

            # Discard empty or malformed lines
            if len(parts) < 2:
                continue

            # Keep only the requested protocol (tcp, udp, sctp, ucp, divert)
            if "/" + protocol in parts[1]:
                # Search the requested service in the names and aliases
                if parts[0] == service or (len(parts) > 2 and service in parts[2:]):
                    return int(parts[1].split("/")[0])

    # Service not found
    return 0


####################################################################################################
def _get_query_type(query):
    """ Try to guess the type of query submitted """
    query_type = ""

    query = query.lower()
    if query.startswith("org-"):
        query_type = "organisation"
    elif query.startswith("mnt-") or query.endswith("-mnt"):
        query_type = "mntner"
    elif query.startswith("irt-"):
        query_type = "irt"
    elif query.startswith("as-") or re.match(r"as[0-9]*:as-", query):
        query_type = "as-set"
    elif query.startswith("fltr-") or re.match(r"as[0-9]*:fltr-", query):
        query_type = "filter-set"
    elif query.startswith("prng-") or re.match(r"as[0-9]*:prng-", query):
        query_type = "peering-set"
    elif query.startswith("rs-") or re.match(r"as[0-9]*:rs-", query):
        query_type = "route-set"
    elif query.startswith("rtrs-") or re.match(r"as[0-9]*:rtrs-", query):
        query_type = "rtr-set"
    elif re.match(r"as[0-9]*$", query):
        if "-" in query:
            query_type = "as-block"
        else:
            query_type = "as"
    elif query.startswith("pgpkey-") or query.startswith("x509-"):
        query_type = "key-cert"
    elif query.startswith("poem-"):
        query_type = "poem"
    elif query.startswith("form-"):
        query_type = "poetic-form"
    elif query.startswith("lim-"):
        query_type = "limerick"
    elif query.endswith(".in-addr.arpa") or query.endswith(".ip6.arpa"):
        query_type = "domain"
    elif re.match(r"^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/[0-9]*$", query) \
      or re.match(r"^[0-9]*\.[0-9]*\.[0-9]*/[0-9]*$", query) \
      or re.match(r"^[0-9]*\.[0-9]*/[0-9]*$", query) \
      or re.match(r"^[0-9]*/[0-9]*$", query):
        query_type = "subnet4"
    elif re.match(r"^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$", query):
        query_type = "ip4"
    elif re.match(r"[0-9a-f]*:", query) or query.startswith("::"):
        if "/" in query:
            query_type = "subnet6"
        else:
            query_type = "ip6"
    elif re.search(r"[-a-z0-9]*\.[a-z]*$", query):
        query_type = "hostname"
    else:
        query_type = "handle"

    return query_type


####################################################################################################
# NAME:
#   auto_select_server
# DESCRIPTION:
#   This function attempts to determine the authoritative server for the query and returns its name.
#   For IP addresses, it uses the IPv4 Address Space from IANA, in a way similar to RDAP.
# PARAMETERS:
#   query - the string we are submitting to the WHOIS server
# RETURN VALUE:
#   server - the server that should provide the most detailed answer
####################################################################################################
def auto_select_server(query):
    """ Auto-select a WHOIS server based on a IP address or subnet, or domain query """
    server = "whois.iana.org"

    if " " in query:
        # query with specific WHOIS server options
        # We assume that the object is in the last word
        query = query.split(" ")[-1]

    query_type = _get_query_type(query)
    if query_type in ("ip4", "subnet4"):
        if query_type == "ip4":
            network = ipaddress.ip_network(query + "/32")
        else:
            network = ipaddress.ip_network(query)

        # From https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
        if network.subnet_of(ipaddress.ip_network("41.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("102.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("105.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("154.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("196.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("197.0.0.0/8")):
            server = "whois.afrinic.net"

        if network.subnet_of(ipaddress.ip_network("1.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("14.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("27.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("36.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("39.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("42.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("43.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("49.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("58.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("59.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("60.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("61.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("101.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("103.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("106.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("110.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("111.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("112.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("113.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("114.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("115.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("116.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("117.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("118.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("119.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("120.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("121.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("122.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("123.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("124.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("125.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("126.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("133.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("150.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("153.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("163.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("171.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("175.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("180.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("182.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("183.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("202.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("203.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("210.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("211.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("218.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("219.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("220.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("221.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("222.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("223.0.0.0/8")):
            server = "whois.apnic.net"

        if network.subnet_of(ipaddress.ip_network("3.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("4.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("6.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("7.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("8.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("9.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("11.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("12.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("13.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("15.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("16.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("17.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("18.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("19.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("20.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("21.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("22.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("23.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("24.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("26.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("28.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("29.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("30.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("32.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("33.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("34.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("35.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("38.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("40.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("44.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("45.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("47.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("48.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("50.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("52.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("54.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("55.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("56.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("63.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("64.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("65.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("66.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("67.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("68.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("69.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("70.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("71.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("72.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("73.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("74.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("75.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("76.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("96.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("97.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("98.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("99.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("100.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("104.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("107.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("108.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("128.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("129.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("130.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("131.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("132.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("134.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("135.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("136.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("137.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("138.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("139.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("140.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("142.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("143.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("144.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("146.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("147.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("148.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("149.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("152.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("155.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("156.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("157.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("158.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("159.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("160.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("161.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("162.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("164.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("165.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("166.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("167.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("168.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("169.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("170.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("172.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("173.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("174.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("184.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("192.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("198.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("199.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("204.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("205.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("206.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("207.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("208.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("209.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("214.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("215.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("216.0.0.0/8")):
            server = "whois.arin.net"

        if network.subnet_of(ipaddress.ip_network("177.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("179.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("181.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("186.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("187.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("189.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("190.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("191.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("200.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("201.0.0.0/8")):
            server = "whois.lacnic.net"

        if network.subnet_of(ipaddress.ip_network("2.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("5.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("25.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("31.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("37.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("46.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("51.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("53.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("57.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("62.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("77.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("78.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("79.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("80.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("81.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("82.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("83.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("84.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("85.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("86.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("87.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("88.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("89.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("90.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("91.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("92.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("93.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("94.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("95.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("109.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("141.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("145.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("151.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("176.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("178.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("185.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("188.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("193.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("194.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("195.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("212.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("213.0.0.0/8")) \
        or network.subnet_of(ipaddress.ip_network("217.0.0.0/8")):
            server = "whois.ripe.net"

    elif query_type in ("ip6", "subnet6"):
        if query_type == "ip6":
            network = ipaddress.ip_network(query + "/128")
        else:
            network = ipaddress.ip_network(query)

        # From https://www.iana.org/assignments/ipv6-unicast-address-assignments/
        #      ipv6-unicast-address-assignments.xhtml
        if network.subnet_of(ipaddress.ip_network("2001:4200::/23")) \
        or network.subnet_of(ipaddress.ip_network("2c00::/12")):
            server = "whois.afrinic.net"

        if network.subnet_of(ipaddress.ip_network("2001:0200::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:4400::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:8000::/19")) \
        or network.subnet_of(ipaddress.ip_network("2001:a000::/20")) \
        or network.subnet_of(ipaddress.ip_network("2001:b000::/20")) \
        or network.subnet_of(ipaddress.ip_network("2001:0c00::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:0e00::/23")) \
        or network.subnet_of(ipaddress.ip_network("2400::/12")) \
        or network.subnet_of(ipaddress.ip_network("2410::/12")):
            server = "whois.apnic.net"

        if network.subnet_of(ipaddress.ip_network("2001:1800::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:0400::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:4800::/23")) \
        or network.subnet_of(ipaddress.ip_network("2600::/12")) \
        or network.subnet_of(ipaddress.ip_network("2610::/23")) \
        or network.subnet_of(ipaddress.ip_network("2620::/23")) \
        or network.subnet_of(ipaddress.ip_network("2630::/12")):
            server = "whois.arin.net"

        if network.subnet_of(ipaddress.ip_network("2001:1200::/23")) \
        or network.subnet_of(ipaddress.ip_network("2800::/12")):
            server = "whois.lacnic.net"

        if network.subnet_of(ipaddress.ip_network("2001:1400::/22")) \
        or network.subnet_of(ipaddress.ip_network("2001:1a00::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:1c00::/22")) \
        or network.subnet_of(ipaddress.ip_network("2001:2000::/19")) \
        or network.subnet_of(ipaddress.ip_network("2001:4000::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:4600::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:4a00::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:4c00::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:5000::/20")) \
        or network.subnet_of(ipaddress.ip_network("2001:0600::/23")) \
        or network.subnet_of(ipaddress.ip_network("2001:0800::/22")) \
        or network.subnet_of(ipaddress.ip_network("2003::/18")) \
        or network.subnet_of(ipaddress.ip_network("2a00::/12")) \
        or network.subnet_of(ipaddress.ip_network("2a10::/12")):
            server = "whois.ripe.net"

    elif query_type in ("hostname", "domain"):
        if query.endswith(".gov"):
            server = "whois.nic.gov"

        elif query.endswith(".com") \
        or query.endswith(".edu") \
        or query.endswith(".net"):
            server = "whois.internic.net"

        else:
            server = query.split(".")[-1].lower() + ".whois-servers.net"

    return server


####################################################################################################
# NAME:
#   whois
# DESCRIPTION:
#   Makes a direct query to a WHOIS server and returns the results as a list of lines.
#   Do not alter the server results, with the possible exception of comments
#   which can be stripped on request.
# PARAMETERS:
#   query - the string we are submitting to the WHOIS server
#   server - the server name or address we want to use (default: "whois.iana.org")
#   port - the server port we want to connect to (default: 43)
#   show_comments - a boolean stating if we want to keep comments, lines starting with "%" or "#"
#                   (default: True)
# RETURN VALUE:
#   results - a list of resulting lines
# CAVEAT:
#   The encoding is incorrectly assumed to be UTF-8 but the WHOIS protocol doesn't provide a way
#   to know for sure and experimentation shows that auto-detection/conversion is even less reliable
####################################################################################################
def whois(query, server="whois.iana.org", port=43, show_comments=True):
    """ Make a query to a WHOIS server, return the results as a list of lines """
    if server == "auto":
        server = auto_select_server(query)

    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect((server, port))
    except socket.gaierror as error:
        logging.error("Server '%s' doesn't exist: %s", server, error)
        return []
    except ConnectionRefusedError as error:
        logging.error("Server '%s:%s' unreachable: %s", server, str(port), error)
        return []

    connection.send((query + "\r\n").encode())
    data = b""
    while True:
        data_chunk = connection.recv(1024)
        if data_chunk:
            data += data_chunk
        else:
            break
    connection.close()

    # Incorrectly assume we'll have UTF-8 encoding
    # Anyway, there's no possibility in the WHOIS protocol to specify the encoding...
    results = data.decode(errors="ignore").split("\n")

    #pylint: disable=W0105
    """
    # Character set detection (needs import chardet)
    # Encoding detected can be sometimes weird...
    encoding = chardet.detect(data)["encoding"].lower()
    print("DEBUG encoding =", encoding, file=sys.stderr)
    results = data.decode(encoding).split("\n")

    # or

    # Forced conversion for certain RIR
    # For example, LACNIC bulk data is iso-8859-1 encoded,
    # but it's not always the case for individual WHOIS records...
    if server == "whois.lacnic.net":
        results = data.decode("iso-8859-1").split("\n")
    else:
        results = data.decode().split("\n")
    """
    #pylint: enable=W0105

    if show_comments:
        return results

    return [line for line in results if line[0] not in ('%', '#')]


####################################################################################################
# NAME:
#   recursive_whois
# DESCRIPTION:
#   Makes a direct query to a WHOIS server, possibly following redirections,
#   and returns the results as a list of lines. Do not alter the server results,
#   with the possible exception of comments which can be stripped on request,
#   and intermediate servers results which can also be filtered out.
# PARAMETERS:
#   query - the string we are submitting to the WHOIS server
#   server - the server name or address we want to use (default: "whois.iana.org")
#   port - the server port we want to connect to (default: 43)
#   recursive - a boolean stating if the request is to be recursive (default: True)
#   show_intermediates - a boolean stating if we want keep results from intermediate servers
#                        (default: True)
#   show_redirections - a boolean stating if we want to print redirections to stderr
#                       (default: False)
#   show_comments - a boolean stating if we want to keep comments,
#                   lines starting with "%" or "#" (default: True)
# RETURN VALUE:
#   results - a list of resulting lines
####################################################################################################
def recursive_whois(
        query,
        server="whois.iana.org",
        port=43,
        recursive=True,
        show_intermediates=True,
        show_redirections=False,
        show_comments=True
        ):
    """ Make a recursive query to a WHOIS server, return the results as a list of lines """
    if server == "auto":
        server = auto_select_server(query)

    results = whois(query, server, port, show_comments=show_comments)

    if recursive:
        new_server = ""
        for line in results:
            if line.startswith("whois: "):
                new_server = re.sub(r"^whois: *", "", line)
                break

            # The ARIN registry doesn't use the "whois:" redirection instruction
            # So let's imitate that if he points to another registry
            # (the following list may be incomplete...)
            if line.startswith("NetName:"):
                if line.endswith("APNIC"):
                    new_server = "whois.apnic.net"
                    break
                if line.endswith("LACNIC"):
                    new_server = "whois.lacnic.net"
                    break
                if line.endswith("RIPE"):
                    new_server = "whois.ripe.net"
                    break
                if line.endswith("AfriNIC") or line.endswith("AFRINIC"): # guessing...
                    new_server = "whois.afrinic.net"
                    break
                if line.endswith("KRNIC"): # guessing...
                    new_server = "whois.krnic.net"
                    break
                if line.endswith("TWNIC"): # guessing...
                    new_server = "whois.twnic.net"
                    break
                if line.endswith("InterNIC") or line.endswith("INTERNIC"): # guessing...
                    new_server = "whois.internic.net"
                    break

        if new_server:
            if show_redirections:
                print(f"Redirection to: {new_server}", file=sys.stderr)

            if show_intermediates:
                results.extend(
                    recursive_whois(query,
                        server=new_server,
                        port=port,
                        recursive=recursive,
                        show_intermediates=show_intermediates,
                        show_redirections=show_redirections,
                        show_comments=show_comments
                        )
                    )
            else:
                results = recursive_whois(
                    query,
                    server=new_server,
                    port=port,
                    recursive=recursive,
                    show_intermediates=show_intermediates,
                    show_redirections=show_redirections,
                    show_comments=show_comments
                    )

    return results


####################################################################################################
def _complete_ipv4(ip4):
    """ Make sure that an IPv4 address or subnet contains 4 dot separated parts """
    if "/" in ip4:
        address = ip4.split("/")[0]
        mask = "/" + ip4.split("/")[1]
    else:
        address = ip4
        mask = ""

    quads = address.split(".")

    for quad in quads:
        try:
            value = int(quad)
        except ValueError:
            return ""
        if value < 0 or value > 255:
            return ""

    length = len(quads)
    if length == 4:
        return ip4
    if length == 3:
        return ".".join(quads) + ".0" + mask
    if length == 2:
        return ".".join(quads) + ".0.0" + mask
    if length == 1:
        return ".".join(quads) + ".0.0.0" + mask
    return "0.0.0.0" + mask


####################################################################################################
def _complete_ipv6(ip6):
    """ Make sure that an IPv6 address or subnet contains 8 colon separated parts """
    if "/" in ip6:
        address = ip6.split("/")[0]
        mask = "/" + ip6.split("/")[1]
    else:
        address = ip6
        mask = ""

    if ":" not in address:
        try:
            value = int(address, 16)
        except ValueError:
            return ""
        if value < 0 or value > 65535:
            return ""
        address += "::"

    ip_address = ipaddress.ip_address(address)

    return ip_address.exploded + mask


####################################################################################################
def _get_answers_locations(query, database):
    """ Try to guess possible cache filenames containing the answer """
    filenames = []

    query = query.lower()
    value = re.sub(r"[^-_A-Za-z0-9:\./]", "", query) # remove special characters from the query
    if query.startswith("mnt-") or query.endswith("-mnt"):
        value = re.sub(r":", ".", value)
        filenames.append(database + os.sep + "mntner" + os.sep + value)
    elif query.startswith("as-") or re.match(r"as[0-9]*:as-", query):
        value = re.sub(r":", ".", value)
        filenames.append(database + os.sep + "as-set" + os.sep + value)
    elif query.startswith("fltr-") or re.match(r"as[0-9]*:fltr-", query):
        value = re.sub(r":", ".", value)
        filenames.append(database + os.sep + "filter-set" + os.sep + value)
    elif query.startswith("prng-") or re.match(r"as[0-9]*:prng-", query):
        value = re.sub(r":", ".", value)
        filenames.append(database + os.sep + "peering-set" + os.sep + value)
    elif query.startswith("rs-") or re.match(r"as[0-9]*:rs-", query):
        value = re.sub(r":", ".", value)
        filenames.append(database + os.sep + "route-set" + os.sep + value)
    elif query.startswith("rtrs-") or re.match(r"as[0-9]*:rtrs-", query):
        value = re.sub(r":", ".", value)
        filenames.append(database + os.sep + "rtr-set" + os.sep + value)
    elif re.match(r"as[0-9]*$", query):
        if "-" in query:
            filenames.append(database + os.sep + "misc" + os.sep + value[0] + os.sep + value)
        else:
            numerical_value = re.sub(r"[^0-9]", "", query)
            filenames.append(
                database + os.sep + "aut-num" + os.sep +
                str(int(numerical_value) // 1000) + "k" + os.sep + "as" + numerical_value
                )
    elif query.startswith("pgpkey-") \
    or query.startswith("x509-") \
    or query.startswith("poem-") \
    or query.startswith("form-") \
    or query.startswith("lim-"):
        filenames.append(database + os.sep + "misc" + os.sep + value[0] + os.sep + value)
    elif query.endswith(".in-addr.arpa") or query.endswith(".ip6.arpa"):
        parts = query.split(".")
        parts.reverse()
        filenames.append(database + os.sep + "domain" + os.sep + os.sep.join(parts))
    elif re.match(r"^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/[0-9]*$", query) \
      or re.match(r"^[0-9]*\.[0-9]*\.[0-9]*/[0-9]*$", query) \
      or re.match(r"^[0-9]*\.[0-9]*/[0-9]*$", query) \
      or re.match(r"^[0-9]*/[0-9]*$", query):
        value = value.replace(".", os.sep)
        filenames.append(database + os.sep + "inetnum" + os.sep + value)
        filenames.append(database + os.sep + "route" + os.sep + value)
    elif re.match(r"^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$", query):
        # Let's try all the supernets of this IPv4 address
        subnet = ipaddress.ip_network(query)
        newvalue = str(subnet).replace(".", os.sep)
        filenames.append(database + os.sep + "inetnum" + os.sep + newvalue)
        for _ in range(32, 8, -1):
            subnet = subnet.supernet()
            newvalue = str(subnet).replace(".", os.sep)
            filenames.append(database + os.sep + "inetnum" + os.sep + newvalue)

        value = value.replace(".", os.sep)
        filenames.append(database + os.sep + "misc" + os.sep + value[0] + os.sep + value)
    elif re.match(r"[0-9a-f]*:", query) or query.startswith("::"):
        value = _complete_ipv6(value)
        value_as_path = value.replace(":", os.sep)
        if "/" in query:
            filenames.append(database + os.sep + "inet6num" + os.sep + value_as_path)
            filenames.append(database + os.sep + "route6" + os.sep + value_as_path)
        else:
            # Let's try all the supernets of this IPv6 address
            subnet = ipaddress.ip_network(value)
            newvalue_as_path = _complete_ipv6(str(subnet)).replace(":", os.sep)
            filenames.append(database + os.sep + "inet6num" + os.sep + newvalue_as_path)
            for _ in range(128, 3, -1):
                subnet = subnet.supernet()
                newvalue_as_path = _complete_ipv6(str(subnet)).replace(":", os.sep)
                filenames.append(database + os.sep + "inet6num" + os.sep + newvalue_as_path)
        filenames.append(database + os.sep + "misc" + os.sep + value_as_path[0] + os.sep \
            + value_as_path
        )
    elif re.search(r"[-a-z0-9]*\.[a-z]*$", query):
        filenames.append(database + os.sep + "misc" + os.sep + value[0] + os.sep + value)
    else:
        # peculiarly for: irt-*, nic-hdl, orgabusehandle, org-*, orgname, orgnochandle,
        # orgroutinghandle, orgtechhandle, person, role, nic-hdl-br
        filenames.append(database + os.sep + "handle" + os.sep + value[0] + os.sep + value)

    return filenames


####################################################################################################
def _get_ipv4_subnets_from_range(start_ip4, stop_ip4):
    """ Return subnets from a range of IPv4 addresses """
    subnets = []
    start = ipaddress.IPv4Address(start_ip4)
    end = ipaddress.IPv4Address(stop_ip4)
    networks = list(ipaddress.summarize_address_range(start, end))
    for network in networks:
        subnets.append(str(network))

    return subnets


####################################################################################################
def _get_block_filenames(lines, database):
    """ Return the storage filename(s) for a block """
    filenames = []

    if ":" in lines[0]:
        key = re.sub(r":[ 	]*.*$", "", lines[0].lower())
        value = re.sub(r"^[-a-z0-9]*:[ 	]*", "", lines[0].lower())
        value = re.sub(r"[ 	]*#.*", "", value) # remove comments
        value = re.sub(r"[^-_A-Za-z0-9:\./]", "", value) # remove special characters

        filename = database + os.sep + key + os.sep

        if key in ("as-set", "filter-set", "mntner", "peering-set", "route-set", "rtr-set"):
            filename += re.sub(r":", ".", value)
            filenames.append(filename)
        elif key == "aut-num":
            # value to (file)name examples:
            #    AS1     => 0k/as1
            #    AS99999 => 99k/as99999
            #    278     => 0k/as278
            #    273662  => 273k/as273662
            numerical_value = re.sub(r"[^0-9]", "", value)
            filename += str(int(numerical_value) // 1000) + "k" + os.sep + "as" + numerical_value
            filenames.append(filename)
        elif key == "domain":
            # value to (file)name example:
            #    176.201.82.in-addr.arpa => arpa/in-addr/82/201/176
            parts = value.split(".")
            parts.reverse()
            filename += os.sep.join(parts)
            filenames.append(filename)
        elif key in ("inetnum", "route"):
            if "/" in value:
                address = _complete_ipv4(value.split("/")[0])
                mask = value.split("/")[1]
                filename += address.replace(".", os.sep) + os.sep + mask
                filenames.append(filename)
            elif "-" in value:
                start_ip4 = _complete_ipv4(value.split("-")[0])
                stop_ip4 = _complete_ipv4(value.split("-")[1])
                for subnet in _get_ipv4_subnets_from_range(start_ip4, stop_ip4):
                    address = _complete_ipv4(subnet.split("/")[0])
                    mask = subnet.split("/")[1]
                    filenames.append(filename + address.replace(".", os.sep) + os.sep + mask)
            else:
                address = _complete_ipv4(value)
                mask = "32"
                filename += address.replace(".", os.sep) + os.sep + mask
                filenames.append(filename)
        elif key in ("inet6num", "route6"):
            if "/" in value:
                address = _complete_ipv6(value.split("/")[0])
                mask = value.split("/")[1]
            else:
                address = _complete_ipv6(value)
                mask = "128"
            filename += address.replace(":", os.sep) + os.sep + mask
            filenames.append(filename)
        elif key == "netrange":
            ips = value.split("-")
            if len(ips) == 2:
                first_ip = ipaddress.IPv4Address(ips[0])
                last_ip = ipaddress.IPv4Address(ips[1])
                networks = ipaddress.summarize_address_range(first_ip, last_ip)
                for network in networks:
                    network = str(network)
                    address = _complete_ipv4(network.split("/")[0])
                    mask = network.split("/")[1]
                    filename = database + os.sep + "inetnum" + os.sep \
                               + address.replace(".", os.sep) + os.sep + mask
                    filenames.append(filename)
        elif key in ("person", "role"):
            # The value is usually not unique. Let's use "nic-hdl:" instead
            new_value = ""
            for line in lines:
                if line.startswith("nic-hdl:"):
                    new_value = re.sub(r"^[-a-z0-9]*:[ 	]*", "", line.lower())
                    break
            if new_value:
                filename = database + os.sep + "handle" + os.sep + new_value[0] + os.sep + new_value
            else:
                filename = database + os.sep + "handle" + os.sep + value[0] + os.sep + value
            filenames.append(filename)
        elif key in ("irt", "nic-hdl", "nic-hdl-br", "orgabusehandle", "organisation", "orgname",
             "orgnochandle", "orgroutinghandle", "orgtechhandle") \
        or key.startswith("irt-") \
        or key.startswith("org-"):
            filenames.append(database + os.sep + "handle" + os.sep + value[0] + os.sep + value)
        elif key in ("resourcelink", "referralserver") \
        or key.startswith("no match for") \
        or key.startswith("notice") \
        or key.startswith("terms of use"):
            pass
        elif key.startswith("query rate limit exceeded") \
        or key.startswith("permission denied"):
            print(f"WARNING: {lines[0]}", file=sys.stderr)
        else:
            # key in ("as-block", "inet-rtr", "key-cert", "poem", "poetic-form", ...)
            filenames.append(database + os.sep + "misc" + os.sep + value[0] + os.sep + value)
    elif " (NET-" in lines[0]:
        for line in lines:
            value = re.sub(r".* \(NET-.*\) ", "", line)
            value = re.sub(r" *", "", value)
            ips = value.split("-")
            if len(ips) == 2:
                first_ip = ipaddress.IPv4Address(ips[0])
                last_ip = ipaddress.IPv4Address(ips[1])
                networks = ipaddress.summarize_address_range(first_ip, last_ip)
                for network in networks:
                    network = str(network)
                    address = _complete_ipv4(network.split("/")[0])
                    mask = network.split("/")[1]
                    filename = database + os.sep + "inetnum" + os.sep \
                               + address.replace(".", os.sep) + os.sep + mask
                    filenames.append(filename)
    else:
        print("WARNING: Uncacheable server answer:", file=sys.stderr)
        for line in lines:
            print(f"	{line}", file=sys.stderr)

    return filenames


####################################################################################################
def _hash_file(filename):
    """ Hash a file using SHA-256 and return its hexadecimal digest """
    file_hash = hashlib.sha256()
    if os.path.isfile(filename):
        with open(filename, 'rb') as file:
            block = file.read(4096)
            while len(block) > 0:
                file_hash.update(block)
                block = file.read(4096)

    return file_hash.hexdigest()


####################################################################################################
# CAVEAT:
#   Need to detect and handle reduced information records sent by NIC.br while
#   the server is rate limiting queries
####################################################################################################
def _process_block(lines, database, debug):
    """ Save a block to the WHOIS cache """
    filenames = _get_block_filenames(lines, database)

    # For most records there will be only 1 savefile, however inetnum records with an IPv4 address
    # range can be represented with several IPv4 subnets, for which we'll duplicate the savefiles
    for filename in filenames:
        # Create intermediate directories, if needed
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        # Temporarily write the savefile with LZMA compression (.xz)
        with lzma.open(filename + ".tmp.xz", "w") as xzfile:
            for line in lines:
                xzfile.write(bytes(line + "\n", "utf-8"))

        # Compute a Message Digest for the new file
        md_new_file = _hash_file(filename + ".tmp.xz")

        # Don't overwrite previous records
        if os.path.isfile(filename + ".xz"):
            md_existing_file = _hash_file(filename + ".xz")
            if md_new_file == md_existing_file:
                # It's a duplicate, we remove it
                os.remove(filename + ".tmp.xz")
                if debug:
                    print(f"# Already cached in '{filename}.xz'", file=sys.stderr)
            else:
                number = 1
                removed = False
                while os.path.isfile(filename + ".bak" + str(number) + ".xz"):
                    md_existing_file = _hash_file(filename + ".bak" + str(number) + ".xz")
                    if md_new_file == md_existing_file:
                        # It's a duplicate, we remove it
                        os.remove(filename + ".tmp.xz")
                        removed = True
                        if debug:
                            print(
                                f"# Already cached in '{filename}.bak{str(number)}.xz'",
                                file=sys.stderr
                            )
                        break
                    number += 1

                if not removed:
                    # It's not a duplicate, we rename it and keep it
                    os.rename(filename + ".tmp.xz", filename + ".bak" + str(number) + ".xz")
                    if debug:
                        print(f"# Cached '{filename}.bak{str(number)}.xz'", file=sys.stderr)
        else:
            # It's not a duplicate, we rename it and keep it
            os.rename(filename + ".tmp.xz", filename + ".xz")
            if debug:
                print(f"# Cached '{filename}.xz'", file=sys.stderr)


####################################################################################################
def _parse_blocks(lines, database, debug):
    """ Parse text blocks delimited by a blank line or the end of data """
    block = []
    for line in lines:
        line = line.strip()
        if line == "" or line.startswith("%") or line.startswith("#"):
            if block:
                _process_block(block, database, debug)
                block = []
        else:
            block.append(line)

    if block:
        _process_block(block, database, debug)


####################################################################################################
# NAME:
#   cached_whois
# DESCRIPTION:
#   Answers from its cache database if a fresh enough result is available or make a direct query
#   to a WHOIS server, possibly following redirections, and returns the results as a list of lines.
#   Intermediate servers results are filtered out, but the last server results are unaltered
#   with the possible exception of comments which can be stripped on request;
# PARAMETERS:
#   query - the string we are submitting to the WHOIS server
#   database - the WHOIS cache database we want to use
#   cachedays - the number of days a cached result can be reused
#   force_refresh - a boolean stating if we want to bypass cached answers (default: False)
#   server - the server name or address we want to use (default: "whois.iana.org")
#   port - the server port we want to connect to (default: 43)
#   recursive - a boolean stating if the request is to be recursive (default: True)
#   show_comments - a boolean stating if we want to include comments in results (default: True)
#   debug - a boolean stating if we want to print DEBUG messages about cache hits/misses to stderr
#           (default: False)
# RETURN VALUE:
#   results - a list of resulting lines
####################################################################################################
def cached_whois(
        query,
        database,
        cachedays,
        force_refresh=False,
        server="whois.iana.org",
        port=43,
        recursive=True,
        show_comments=True,
        debug=False
        ):
    """ Serve a query from a cache or do a recursive query and store the results in the cache """
    results = []
    cache_hit = False

    if server == "auto":
        server = auto_select_server(query)

    if not force_refresh and " " not in query:
        # Are query answers already available in the cache?
        filenames = _get_answers_locations(query, database)
        for filename in filenames:
            if os.path.isfile(filename + ".xz"):
                # And are they fresh enough?
                filepath = pathlib.Path(filename + ".xz")
                filestat = filepath.stat()
                filestamp = filestat.st_mtime
                filedate = datetime.datetime.fromtimestamp(filestamp, tz=datetime.timezone.utc)
                filedays = (datetime.datetime.now(datetime.timezone.utc) - filedate).days
                if filedays <= cachedays:
                    cache_hit = True
                    if debug:
                        print(f"# Cache HIT in file '{filename}.xz':", file=sys.stderr)
                    with lzma.open(filename + ".xz", "rt") as xzfile:
                        lines = xzfile.readlines()
                    for line in lines:
                        results.append(line.strip())
                    results.append("")

    if not cache_hit:
        # If not, or refresh forced, let's query a WHOIS server recursively
        results = recursive_whois(
                    query,
                    server=server,
                    port=port,
                    recursive=recursive,
                    show_intermediates=False,
                    show_redirections=debug,
                    show_comments=show_comments
                    )

        # And then store the results in the cache
        _parse_blocks(results, database, debug)

    return results
