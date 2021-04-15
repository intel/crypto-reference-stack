#!/usr/bin/env bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

set -e

# =============================================================================
# Variables
# =============================================================================

SSL_ASYNC=${SSL_ASYNC:-off}
NGINX_WP=${NGINX_WP:-2}
NGINX_CIPHER=${NGINX_CIPHER:-TLS_AES_256_GCM_SHA384:ECDH:ECDSA:secp384r1}
NGINX_HTTP=${NGINX_HTTP:-0}

# NGINX_HTTP overrides SSL_ASYNC
if [[ "$NGINX_HTTP" -eq "1" ]]; then
	echo "NGINX_HTTP overrides SSL_ASYNC to off"
	SSL_ASYNC=off
fi

export OPENSSL=openssl
export OPENSSL_ENGINES=/usr/local/lib/engines-1.1/
export NGINX_INSTALL_DIR=/usr/local/share/nginx/
export NGINX_CONF_DIRECTORY=/usr/local/share/nginx/conf/

# =============================================================================
# Functions
# =============================================================================

# None

# =============================================================================
# Main
# =============================================================================

echo "SSL Async: " $SSL_ASYNC
echo "NGINX_WP = $NGINX_WP"
echo "NGINX_CIPHER = $NGINX_CIPHER"

if [[ "$NGINX_HTTP" -eq "1" ]]; then
	/nginx-script.sh --http
elif [[ "$NGINX_HTTP" -eq "0" ]]; then
	/nginx-script.sh --https

	# set nginx ssl engine
	if [[ $SSL_ASYNC == 'on' ]]; then
		/nginx-script.sh -e 1
	else
		/nginx-script.sh -e 0
	fi
fi

# create certificates
/nginx-script.sh -g

# set nginx worker process
/nginx-script.sh -u $NGINX_WP

# set nginx cipher suite
if [[ "$NGINX_HTTP" -ne "1" ]]; then
	/nginx-script.sh -X $NGINX_CIPHER
fi

# start nginx
/nginx-script.sh -s

sleep 365d

