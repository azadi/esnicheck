"""
**ESNICheck** is a Python module (with a web application frontend at
[esnicheck.com](https://esnicheck.com)) that checks if a hostname supports the
Encrypted Server Name Indication (`ESNI`), an extension to `TLSv1.3` that
encrypts the `SNI` field. This module checks if a hostname supports `ESNI` by
checking for `TLSv1.3` support and verifying the `ESNI` key published on its
`_esni` `TXT` record. It supports drafts 01 and 02 of the `ESNI`
[RFC](https://tools.ietf.org/html/draft-ietf-tls-esni-02).

The assumption as of this release is that if a hostname supports the `TLSv1.3`
protocol, publishes a valid `ESNI` key (for versions 01 and 02 of the draft;
the current versions supported by Firefox and CloudFlare), then that hostname
supports `ESNI`. The current version of the module does not try to establish a
connection with the server using the `encrypted_server_name` field in the
`ClientHello` to further confirm `ESNI` support but there are plans to add it
in a future release.

If you are not familiar with `ESNI`, please start by reading this [simple
introduction from
EFF](https://www.eff.org/deeplinks/2018/09/esni-privacy-protecting-upgrade-https)
or [the post by CloudFlare](https://blog.cloudflare.com/esni/).
"""

import base64
import binascii
import datetime
import hashlib
import ipaddress
import socket
import ssl
import textwrap
import urllib.parse

import dns.resolver


# ESNI Draft 02 RFC
# https://tools.ietf.org/html/draft-ietf-tls-esni-02#section-4
#
# The version bytes are the same for draft 01 and draft 02. Note that the
# current version of the draft is 06 but neither Firefox nor CloudFlare support
# it, and given that they are the (only) major adopters of ESNI at this point,
# that's what we will be implementing and working with.

ESNI_VERSION = bytearray([0xff, 0x01])

# TLSv1.3 RFC
# https://tools.ietf.org/html/rfc8446#appendix-B.3.1.4
#
# enum {
#   unallocated_RESERVED(0x0000),
#
#   /* Elliptic Curve Groups (ECDHE) */
#   obsolete_RESERVED(0x0001..0x0016),
#   secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
#   obsolete_RESERVED(0x001A..0x001C),
#   x25519(0x001D), x448(0x001E),
#
#   /* Finite Field Groups (DHE) */
#   ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
#   ffdhe6144(0x0103), ffdhe8192(0x0104),
#
#   /* Reserved Code Points */
#   ffdhe_private_use(0x01FC..0x01FF),
#   ecdhe_private_use(0xFE00..0xFEFF),
#   obsolete_RESERVED(0xFF01..0xFF02),
#   (0xFFFF)
# } NamedGroup;

TLS_NAMED_GROUPS = {
    "0017": "secp256r1",
    "0018": "secp384r1",
    "0019": "secp521r1",
    "001d": "x25519",
    "001e": "x448",
    "0100": "ffdhe2048",
    "0101": "ffdhe3072",
    "0102": "ffdhe4096",
    "0103": "ffdhe6144",
    "0104": "ffdhe8192",
}

# TLSv1.3 RFC
# https://tools.ietf.org/html/rfc8446#appendix-B.4
#
# +------------------------------+-------------+
# | Description                  | Value       |
# +------------------------------+-------------+
# | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
# |                              |             |
# | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
# |                              |             |
# | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
# |                              |             |
# | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
# |                              |             |
# | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
# +------------------------------+-------------+

TLS_CIPHERS = {
    "1301": "TLS_AES_128_GCM_SHA256",
    "1302": "TLS_AES_256_GCM_SHA384",
    "1303": "TLS_CHACHA20_POLY1305_SHA25",
    "1304": "TLS_AES_128_CCM_SHA256",
    "1305": "TLS_AES_128_CCM_8_SHA256",
}


class ESNICheck:
    def __init__(self, hostname):
        self.hostname = self.get_hostname(hostname)

    def get_hostname(self, hostname):
        """Parse a string to return the hostname.

        If the input string (for some reason?) is https://domain.tld, this will
        return domain.tld. This may not cover all possible input cases.

        :param hostname: string with hostname (or URI)
        :return hostname: parsed string with hostname extracted
        """
        if hostname.startswith(("http", "https")):
            return urllib.parse.urlsplit(hostname).netloc
        else:
            return hostname

    def format_hex(self, string):
        """Format a string and return a two-spaced hex-like representation.

        If the input string is "abcd", this returns "AB CD". We use this to
        format the hex values so that they are easier to read; instead of
        displaying something like ffff, we print FF FF.

        :param string: string to format
        :return string: formatted string
        """
        return ' '.join(e.upper() for e in textwrap.wrap(string, 2))

    def has_tls13(self):
        """Check if the hostname supports TLSv1.3

        TLSv1.3 is required for ESNI so this method connects to the server and
        tries to initiate a connection using that. If the connection is
        successful, we confirm TLSv1.3 support, otherwise we return the highest
        protocol supported by the server.

        Note that as per the documentation, `create_default_context` uses
        `ssl.PROTOCOL_TLS`, which in turn selects the highest protocol version
        that both the client and the server support.

        :return tuple: (True, protocol) if TLSv1.3 is supported,
                       (False, protocol with error message) if it is not
        """
        assert ssl.HAS_TLSv1_3
        conn = ssl.create_default_context()
        try:
            socket.setdefaulttimeout(10)
            with socket.create_connection((self.hostname, 443)) as sock:
                with conn.wrap_socket(sock,
                                      server_hostname=self.hostname) as ssock:
                    protocol = ssock.version()
        except (ConnectionRefusedError, ConnectionResetError):
            return (False, "Unable to connect to port 443")
        except ssl.SSLError as error:
            return (False, error.reason)
        except socket.gaierror:
            return (False, "Hostname lookup failed")
        except socket.timeout:
            return (False, "Hostname connection failed")
        if protocol == "TLSv1.3":
            return (True, protocol)
        else:
            return (False, f"{self.hostname} supports {protocol}")

    def has_esni(self):
        """Checks if a given hostname supports ESNI.

        This is intended to be the main method that checks if the given
        hostname supports ESNI or not. It does this by checking for TLSv1.3
        support (prerequisite for ESNI), and the existence and validity of an
        _esni DNS TXT record that publishes the ESNI keys.

        This return True if both `has_tls13` and `has_dns` methods return True.

        :return bool: True if hostname supports ESNI, else False
        """
        has_tls = self.has_tls13()[0]
        has_dns = self.has_dns()[0]
        esni = all((has_tls, has_dns))
        return esni

    def dns_lookup(self):
        """Look up _esni TXT record for a hostname.

        Resolves the _esni TXT (_esni.hostname) record, which has the ESNI keys
        that we later check for validity.

        :return tuple: (True, record) if the lookup was successful,
                       (False, error) if it failed
        """
        esni_record = "_esni." + self.hostname
        try:
            dns_record = dns.resolver.query(esni_record, "TXT")
        except dns.resolver.NXDOMAIN:
            return (False, "No _esni TXT record found")
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as error:
            return (False, error)

        record = dns_record[0].strings[0]
        return (True, record)

    def to_int(self, arr):
        """Convert a byte object to an int literal.

        If the input is 00ff, this returns 255. Python converts 0x (base-16) to
        int (base-10) automatically but the reason we have to explicitly cast
        the int and specify the base is because our string is not prefixed with
        0x, so the conversion fails.

        :param arr: a bytearray slice to be cast to int
        :return int: the integer value of the bytearray
        """
        return int(arr.hex(), 16)

    def is_cloudflare(self):
        """Check if the hostname is behind Cloudflare.

        We do this by checking if the A record for the domain points to an IP
        address that is in the list of IPv4 ranges of and provided by
        Cloudflare.

        :return tuple: (str: IP address, bool: if IP is a Cloudflare IP)
        """
        # From https://www.cloudflare.com/ips-v4.
        cf_ips = [
            ipaddress.IPv4Network(network) for network in [
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

        host_address = dns.resolver.query(self.hostname, "A")
        ip_address = host_address[0].address
        return (ip_address, any(ipaddress.IPv4Address(ip_address) in network
                                for network in cf_ips))

    def has_dns(self):
        """Checks if a hostname has ESNI keys and confirms their validity.

        This function parses the ESNI keys to confirm their validity. It does
        that by comparing the key structure as returned by DNS TXT record
        against the draft 02 ESNIKeys struct specified in the standard. If at
        any point the parsing fails, it returns an error message otherwise it
        returns an output dict() with keys set to the fields in the struct and
        the values set to the parsed values.

        :return tuple: (True, None, output) if ESNIKeys is valid,
                       (False, error, message) if ESNIKeys is invalid
        """
        # https://tools.ietf.org/html/draft-ietf-tls-esni-03#section-4.1
        #
        # For the output dict, we will assume the same structure for its keys
        # as in the ESNIKeys structure below.
        #
        # struct {
        #     uint16 version;
        #     uint8 checksum[4];
        #     KeyShareEntry keys<4..2^16-1>;
        #     CipherSuite cipher_suites<2..2^16-2>;
        #     uint16 padded_length;
        #     uint64 not_before;
        #     uint64 not_after;
        #     Extension extensions<0..2^16-1>;
        # } ESNIKeys;
        #
        # output["version"], output["checksum"] ...
        output = dict()

        # Lookup the DNS for _esni.hostname
        success, response = self.dns_lookup()
        # Something went wrong during the resolution, just fail and report it.
        if not success:
            return False, response, output

        # Start by getting ESNIKeys string from the DNS record.
        output["ESNIKeys"] = response.decode("utf-8")

        # Convert the DNS response to a bytearray. This makes it easy to refer
        # to the ESNIKeys struct by comparing the number of bytes each field in
        # the struct occupies and using that as a reference to parse the key.
        try:
            array = bytearray(base64.b64decode(response))
        except binascii.Error as e:
            return False, e, output

        # version
        #  The version of the structure.  For this specification, that value
        #  SHALL be 0xff02.  Clients MUST ignore any ESNIKeys structure with a
        #  version they do not understand.  [[NOTE: This means that the RFC
        #  will presumably have a nonzero value.]]
        #
        # If the version comparison fails, we stop parsing the rest of the key
        # as the RFC dictates that ("ignore"), and there isn't much we can do
        # anyway.
        #
        #     uint16 version;
        version = array[:2]
        if version == ESNI_VERSION:
            output["version"] = self.format_hex(version.hex())
        else:
            return False, "Unknown ESNI draft version", output

        # checksum
        #  The first four (4) octets of the SHA-256 message digest [RFC6234] of
        #  the ESNIKeys structure.  For the purpose of computing the checksum,
        #  the value of the "checksum" field MUST be set to zero.
        #
        #  The "checksum" field provides protection against transmission
        #  errors, including those caused by intermediaries such as a DNS proxy
        #  running on a home router.
        #
        #     uint8 checksum[4];

        # Since we will setting the checksum field to zero, make a copy, set
        # the four bytes to zero, and get the first (4) octets of the SHA256
        # checksum for the comparison.
        checksum_array = array[:]
        checksum_array[2:6] = b'\x00' * 4
        checksum_hash = hashlib.sha256(checksum_array).digest()
        if checksum_hash[:4] == array[2:6]:
            output["checksum"] = self.format_hex(checksum_hash[:4].hex())
        else:
            return False, "The key checksum does not match", output

        # https://tools.ietf.org/html/rfc8446#section-4.2.8
        #
        # From the TLSv1.3 RFC.
        #
        # struct {
        #     NamedGroup group;
        #     opaque key_exchange<1..2^16-1>;
        # } KeyShareEntry;
        #
        #     KeyShareEntry keys<4..2^16-1>;

        # Since the next steps deal with arbitrary byte sizes depending on the
        # NamedGroup, let's chomp the array so that it's easy to deal with.
        # There are cleaner ways to do this than the to_int approach I am using
        # here, but we will fix that for when the draft is finalized.
        array = array[6:]

        # There might be multiple keys, depending on the length of all the key
        # share entries and on the length of each key exchange. Therefore, 
        # tracking the covered length in bytes and using a while loop whilst
        # comparing that covered length to the actual key share entries vector's
        # length is a way to ensure getting all the keys.
        #
        # This gets us the length of all the key share entries
        keyshare_length = self.to_int(array[:2])

        # Chomp the array in order to start at the first key share entry
        array = array[2:]

        # The very first key share entry corresponds to key number 0
        covered_length = 0
        key_nb = 0
        while covered_length < keyshare_length:
            #     NamedGroup group;
            #
            # The NamedGroup is the next two bytes.
            named_group = TLS_NAMED_GROUPS[array[:2].hex()]
            output["keys [{}]".format(key_nb)] = named_group
            covered_length += 2

            #     opaque key_exchange<1..2^16-1>;
            #
            # This holds the actual value of the key. While most implementations
            # use x25519 with a 32-byte key, let's not make that assumption.
            key_exchange_length = self.to_int(array[2:4])
            covered_length += 2

            key_exchange = array[4:4+key_exchange_length].hex()
            output["keys_value [{}]".format(key_nb)] = self.format_hex(key_exchange)

            # Chomp the array to go to the end of the current key share entry, 
            # either to the beginning of the next one, or to the next section
            array = array[4+key_exchange_length:]
            covered_length += key_exchange_length
            key_nb += 1

        #     CipherSuite cipher_suites<2..2^16-2>;
        # Just like the key share entries, there might be more than one cipher suite,
        # so we need to get the total length of the cipher_suites vector. However, each
        # CipherSuite element is exactly 2-byte long, so there is no need to keep track
        # of the covered length. Instead, a simple division gives us the number of 
        # cipher suites.
        ciphers_length = self.to_int(array[:2])
        nb_of_ciphers = int(ciphers_length / 2)
        
        # Chomp the array in order to start at the first cipher suite
        array = array[2:]

        for cipher_nb in range(nb_of_ciphers):
            cipher = TLS_CIPHERS[array[:2].hex()]
            output["cipher_suites[{}]".format(cipher_nb)] = cipher

            # Chomp the array to get to the next cipher, or to the next section
            array = array[2:]

        # padded_length
        #  The length to pad the ServerNameList value to prior to encryption.
        #  This value SHOULD be set to the largest ServerNameList the server
        #  expects to support rounded up the nearest multiple of 16.  If the
        #  server supports wildcard names, it SHOULD set this value to 260.
        #
        #     uint16 padded_length;
        padded_len = self.to_int(array[:2])
        output["padded_length"] = padded_len

        # not_before
        #  The moment when the keys become valid for use.  The value is
        #  represented as seconds from 00:00:00 UTC on Jan 1 1970, not
        #  including leap seconds.
        #
        # We convert the epoch to UTC. (uint64, so 8 bytes).
        #
        #     uint64 not_before;
        not_before = self.to_int(array[2:10])
        output["not_before"] = datetime.datetime.utcfromtimestamp(not_before)

        # not_after
        #  The moment when the keys become invalid.  Uses the same unit as
        #  not_before.
        #     uint64 not_after;
        not_after = self.to_int(array[10:18])
        output["not_after"] = datetime.datetime.utcfromtimestamp(not_after)

        # extensions
        #  A list of extensions that the client can take into consideration
        #  when generating a Client Hello message.  The format is defined in
        #  [RFC8446]; Section 4.2.  The purpose of the field is to provide room
        #  for additional features in the future; this document does not define
        #  any extension.
        #
        #  Extension extensions<0..2^16-1>;
        extensions = array[18:]
        output["extensions"] = self.format_hex(extensions.hex())

        return True, None, output
