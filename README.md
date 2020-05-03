![esnicheck](static/esni.png)

# ESNICheck

![esnicheck](https://github.com/azadi/esnicheck/workflows/build/badge.svg)

**ESNICheck** is a Python module (with a web application frontend at [esnicheck.com](https://esnicheck.com)) that checks if a hostname supports the Encrypted Server Name Indication (`ESNI`), an extension to `TLSv1.3` that encrypts the `SNI` field. This module checks if a hostname supports `ESNI` by checking for `TLSv1.3` support and verifying the `ESNI` key published on its `_esni` `TXT` record. It supports drafts 01 and 02 of the `ESNI` [RFC](https://tools.ietf.org/html/draft-ietf-tls-esni-02).

The assumption as of this release is that if a hostname supports the `TLSv1.3` protocol, publishes a valid `ESNI` key (for versions 01 and 02 of the draft; the current versions supported by Firefox and CloudFlare), then that hostname supports `ESNI`. The current version of the module does not try to establish a connection with the server using the `encrypted_server_name` field in the `ClientHello` to further confirm `ESNI` support but there are plans to add it in a future release.

If you are not familiar with `ESNI`, please start by reading this [simple introduction from EFF](https://www.eff.org/deeplinks/2018/09/esni-privacy-protecting-upgrade-https) or [the post by CloudFlare](https://blog.cloudflare.com/esni/).

# Motivation

There is no easy (automated) way to check for `ESNI` support other than connecting to a website with Mozilla Firefox and looking at the `sni=encrypted` string in the logs (`HAR`), or observing the traffic using Wireshark (`encrypted_server_name`). [CloudFlare's ESNI Checker](https://www.cloudflare.com/ssl/encrypted-sni/) checks if your browser supports `ESNI` when connecting to `cloudflare.com`, however, it does not allow you to check if other websites support `ESNI`.

This module provides an easy way to check for `ESNI` support with the hope that this service will encourage the adoption of `ESNI`, helping increase the privacy of users on the internet.

# To-Do

- [x] Check for `TLSv1.3` support
- [x] Check for `_esni` DNS record and validity of `ESNIKeys`
- [ ] Establish a connection with `ESNI` (`encrypted_server_name` extension in `ClientHello`)

# Requirements

`Python 3.7+` and the `dnspython` module (used for the DNS lookup).

To install, clone the repository and run the usual `setup.py install` command.

# Module

```
>>> from esnicheck.check import ESNICheck
>>> host = ESNICheck("cloudflare.com")
>>> host.has_esni()
True
>>> host.has_tls13()
(True, 'TLSv1.3')
>>> host.has_dns()
(True, None, {'ESNIKeys': '/wH+dd/xACQAHQAgdy5Lv+M2t7kpbSzeytiOxYCW10CGZ8Pk8ZersvVMdlwAAhMBAQQAAAAAXqnOsAAAAABesbewAAA=', 'version': 'FF 01', 'checksum': 'FE 75 DF F1', 'keys [0]': 'x25519', 'keys_value [0]': '00 20 77 2E 4B BF E3 36 B7 B9 29 6D 2C DE CA D8 8E C5 80 96 D7 40 86 67 C3 E4 F1 97 AB B2 F5 4C', 'cipher_suites': 'TLS_AES_128_GCM_SHA256', 'padded_length': 260, 'not_before': datetime.datetime(2020, 4, 29, 19, 0), 'not_after': datetime.datetime(2020, 5, 5, 19, 0), 'extensions': '00 00'})
```

For more detailed instructions, run `help(esnicheck.check)`.

# Web Application

The version of this module deployed at [esnicheck.com](https://esnicheck.com) is a Flask frontend (see `app.py`) and also has a very basic API:

```
$ curl -X POST -H "Content-Type: application/json" -d '{"q":"cloudflare.com"}' https://esnicheck.com/check
{"has_esni":true}
```
