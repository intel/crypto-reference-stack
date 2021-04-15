# Intel&reg; Crypto Reference Stack

## Overview

Crypto Reference Stack (CRS) provides a highly optimized software stack that
accelerates the processing of the Transport Layer Security (TLS), by using
the built-in
[Intel® Crypto](https://newsroom.intel.com/articles/crypto-acceleration-enabling-path-future-computing/)
Acceleration included in the new
[3rd Gen Intel® Xeon® Scalable Processors](https://www.intel.com/content/www/us/en/products/docs/processors/xeon/3rd-gen-xeon-scalable-processors-brief.html),
which also feature a flexible architecture with integrated artificial
intelligence (AI) acceleration with Intel® DL Boost technology.

CRS provides an extended NGINX\* working with Asynchronous Mode OpenSSL\*
and WordPress\*/MySQL\* for demonstrating new Intel® Cryptography
instructions validated in
[3rd Gen Intel® Xeon® Scalable Processors](https://www.intel.com/content/www/us/en/products/docs/processors/xeon/3rd-gen-xeon-scalable-processors-brief.html).

## Optimized NGINX for Cryptography

Extended NGINX\* working with Asynchronous Mode OpenSSL\* is part of
Intel&reg Crypto Reference Stack, optimized for Web Services use cases.
NGINX\* is a free, open-source, high-performance HTTP server and
reverse proxy, as well as an IMAP/POP3 proxy server. NGINX\* is known
for its high performance, stability, rich feature set, simple
configuration, and low resource consumption.

Crypto Reference Stack NGINX* is packaged as a Docker container with
a set of scripts to build components including:

- [OpenSSL Project](https://github.com/openssl/openssl)
- [Intel® Integrated Performance Primitives Cryptography](https://github.com/intel/ipp-crypto)
- [Intel(R) Multi-Buffer Crypto for IPsec Library](https://github.com/intel/intel-ipsec-mb)
- [Intel® QuickAssist Technology(QAT) OpenSSL* Engine](https://github.com/intel/QAT_Engine)
- [Asynch Mode for NGINX*](https://github.com/intel/asynch_mode_nginx)

The documentation related to build and deploy NGINX\* as a standalone
web server working with Asynchronous Mode OpenSSL* can be found at:

- https://github.com/intel/crypto-reference-stack/blob/main/nginx/centos8/README.md

## WordPress/MySQL

WordPress* is a free and open-source content management system written in
PHP and paired with a MySQL database.

MySQL* is a widely used, open-source relational database management
system (RDBMS).

The documentation related to build NGINX\* and deploy the WordPress\*/MySQL\*
stack can be found at:

- https://github.com/intel/crypto-reference-stack/blob/main/wordpress/centos8/README.md

## oneContainer Portal

Explore more container solutions on the
[Intel® oneContainer Portal](https://software.intel.com/content/www/us/en/develop/tools/containers.html).

## How to provide feedback

Please submit an issue using native github.com interface:
https://github.com/intel/crypto-reference-stack/issues

## License

The Intel&reg; Crypto Reference Stack is distributed under the
Apache-2.0 License.

You may obtain a copy of the License at
[APACHE LICENSE, VERSION 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## Legal Notice

By accessing, downloading or using this software and any required dependent
software (the “Software Package”), you agree to the terms and conditions of
the software license agreements for the Software Package, which may also
include notices, disclaimers, or license terms for third party software
included with the Software Package. Please refer to the licenses directory
for additional details.

*Intel and the Intel logo are trademarks of Intel Corporation or its
subsidiaries*

*\*Other names and brands may be claimed as the property of others*
