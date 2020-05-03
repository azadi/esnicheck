import datetime
from unittest.mock import patch

import dns.resolver

from esnicheck.check import ESNICheck


def test_get_hostname():
    check = ESNICheck("foobar.com")
    assert "example.com" == check.get_hostname("example.com")
    assert "example.com" == check.get_hostname("https://example.com")
    assert "example.com" == check.get_hostname("http://example.com")
    assert "example.com" == check.get_hostname("https://example.com/foobar")
    assert "example.com" != check.get_hostname("example.com/foobar")


def test_format_hex():
    check = ESNICheck("foobar.com")
    assert "FF FF" == check.format_hex("ffff")
    assert "00 FF" == check.format_hex("00ff")


def test_has_tls13():
    check = ESNICheck("127.0.0.1")
    assert (False, "Unable to connect to port 443") == check.has_tls13()
    ssl_check = ESNICheck(" ")
    assert (False, "Hostname lookup failed") == ssl_check.has_tls13()


def test_has_esni():
    check = ESNICheck("foobar.com")
    with patch("esnicheck.check.ESNICheck.has_dns") as mock_dns, \
            patch("esnicheck.check.ESNICheck.has_tls13") as mock_tls:
        mock_dns.return_value = (True,)
        mock_tls.return_value = (True,)
        assert (True) == check.has_esni()


def test_dns_lookup():
    check = ESNICheck(".")
    with patch("dns.resolver.query") as mock_dns:
        mock_dns.side_effect = [dns.resolver.NXDOMAIN,
                                dns.resolver.NoAnswer,
                                dns.resolver.NoNameservers]
        assert (False, "No _esni TXT record found") == check.dns_lookup()
        assert (False) == check.dns_lookup()[0]
        assert (False) == check.dns_lookup()[0]


def test_to_int():
    check = ESNICheck("foobar.com")
    assert 255 == check.to_int(bytearray([0xff]))
    assert 257 == check.to_int(bytearray([0x01, 0x01]))


def test_has_dns():
    output_valid = {'ESNIKeys': '/wFAca5pACQAHQAg/wJCen8ikwzbG8WEPaXqBqD+PnYAF07MA/JEmRbCmVYAAhMBAQQAAAAAXqjDgAAAAABesKyAAAA=',
                    'version': 'FF 01',
                    'checksum': '40 71 AE 69',
                    'keys [0]': 'x25519',
                    'keys_value [0]': '00 20 FF 02 42 7A 7F 22 93 0C DB 1B C5 84 3D A5 EA 06 A0 FE 3E 76 00 17 4E CC 03 F2 44 99 16 C2',
                    'cipher_suites': 'TLS_AES_128_GCM_SHA256',
                    'padded_length': 260,
                    'not_before': datetime.datetime(2020, 4, 29, 0, 0),
                    'not_after': datetime.datetime(2020, 5, 5, 0, 0),
                    'extensions': '00 00'}
    check = ESNICheck("example.com")
    with patch("esnicheck.check.ESNICheck.dns_lookup") as mock_dns:
        mock_dns.side_effect = [(False, "Error"),
                                (True, b"/wFAca5pACQAHQAg/wJCen8ikwzbG8WEPaXqBqD+PnYAF07MA/JEmRbCmVYAAhMBAQQAAAAAXqjDgAAAAABesKyAAAA=")]
        assert (False, "Error", {}) == check.has_dns()
        assert (True, None, output_valid) == check.has_dns()
