#!/usr/bin/env python3

import json
from ipaddress import IPv4Network, IPv4Address

from esnicheck.check import ESNICheck

import dns.resolver

# From https://www.cloudflare.com/ips-v4.
CF_IPS = [
    IPv4Network(network) for network in [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/12",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ]
]


def is_cloudflare(hostname):
    """Check if the hostname is behind Cloudflare.

    We do this by checking if the A record for the domain points to an IP
    address that is in the list of IPv4 ranges of and provided by Cloudflare.
    """
    host_address = dns.resolver.query(hostname, "A")
    ip_address = host_address[0].address
    return any(IPv4Address(ip_address) in network for network in CF_IPS)


def main():
    urls = []
    with open("mostvisited.txt", "r") as f:
        for each in f:
            if not each.startswith("#"):
                urls.append(each.strip())

    result = {}
    for each in urls:
        has_esni = ESNICheck(each).has_esni()
        if has_esni:
            result[each] = {"is_cf": is_cloudflare(each)}

    with open("esni.txt", "w") as w:
        json.dump(result, w, indent=2)


if __name__ == "__main__":
    main()
