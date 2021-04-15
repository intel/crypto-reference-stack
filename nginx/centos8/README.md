# Optimized NGINX for Cryptography

## Hardware Requirements

The Optimized NGINX for Cryptography is only supported in the platforms
starting with [3rd Gen Intel® Xeon® Scalable Processors](https://www.intel.com/content/www/us/en/products/docs/processors/xeon/3rd-gen-xeon-scalable-processors-brief.html).

## Software Requirements

1. Install Docker from the official [Docker Install](https://docs.docker.com/install/)
   documentation.
2. If you want to manage Docker as a non-root user, add your _user_ as part of the
   [_Docker_ Group](https://docs.docker.com/install/linux/linux-postinstall/).
3. If you are building the Docker image behind a corporate proxy,
   [configure Docker to use a proxy server](https://docs.docker.com/network/proxy/).

## Environment Variables

The following environment variable is available:

- SSL_ASYNC
  - Description: Enable / Disable OpenSSL\* Crypto Engine
  - Default value: off
  - Value options: on | off
    - on: Enabled TLS Asynchronous Mode, it can be set only in
      3rd Gen Intel® Xeon® Scalable Processors.
    - off: Disabled TLS Asynchronous Mode, to be set in case you want test a
      non TLS optimized path or you are running in a non 3rd Gen Intel® Xeon®
      Scalable Processors.
- NGINX_WP
  - Description: Define the number of NGINX Work Processes
  - Options: <X Number>
  - Default: 2
- NGINX_CIPHER
  - Description: Define the TLS Cipher Suite by NGINX
  - Format: <Cipher Suite>:<Key Exchange Algorithm>:<Authentication Algorithm>:<EC Curve>
    - ECDHE-RSA-AES128-GCM-SHA256:ECDH:RSA:X25519
    - ECDHE-ECDSA-AES128-GCM-SHA256:ECDH:ECDSA:X25519
    - TLS_AES_256_GCM_SHA384:ECDH:ECDSA:X25519
    - TLS_AES_256_GCM_SHA384:ECDH:ECDSA:secp384r1
  - Default: TLS_AES_256_GCM_SHA384:ECDH:ECDSA:secp384r1

## Build and Deploy

1. Clone the Crypto Reference Stack Github repository:

```sh
$ git clone https://github.com/intel/crypto-reference-stack.git
```

2. Go to the NGINX\* directory:

```sh
$ cd crypto-reference-stack/nginx/centos8/
```

3. Build the NGINX* Docker image:

```sh
$ docker build -t crypto-reference-stack .
```

4. Enable or disabled the OpenSSL\* Crypto Engine:

```sh
$ export SSL_ASYNC=off
```

5. Start up your NGINX Docker image:

```sh
$ docker run --name nginx --rm -itd -p 8443:8443 -e SSL_ASYNC=$SSL_ASYNC crypto-reference-stack
```

6. Go to https://localhost:8443, you should see a web page with a
   "Welcome to nginx!" message.
