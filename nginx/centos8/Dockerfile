# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM centos:centos8.3.2011 AS compile-stage

RUN dnf -y install epel-release && \
    dnf -y update && \
    dnf group -y install "Development Tools" && \
    dnf -y install \
      cpuid \
      cmake \
      openssl-devel \
      wget \
      pcre \
      pcre-devel

RUN wget https://www.nasm.us/pub/nasm/releasebuilds/2.15.02/linux/nasm-2.15.02-0.fc31.x86_64.rpm && \
    rpm -i nasm-2.15.02-0.fc31.x86_64.rpm

ARG OPENSSL_RELEASE="OpenSSL_1_1_1j"
RUN git clone -b $OPENSSL_RELEASE https://github.com/openssl/openssl.git
RUN cd /openssl && \
    ./config && \
    make depend && \
    make && \
    make install_sw

ARG IPP_CRYPTO_VERSION="ippcp_2020u3"
RUN git clone -b $IPP_CRYPTO_VERSION https://github.com/intel/ipp-crypto && \
    cd /ipp-crypto/sources/ippcp/crypto_mb && \
    cmake . -B"../build" \
      -DOPENSSL_INCLUDE_DIR=/usr/local/include/openssl \
      -DOPENSSL_LIBRARIES=/usr/local/lib64 \
      -DOPENSSL_ROOT_DIR=/usr/local/bin/openssl && \
    cd ../build && \
    make crypto_mb && \
    make install

ARG IPSEC_MB_VERSION="v0.55"
RUN git clone -b $IPSEC_MB_VERSION https://github.com/intel/intel-ipsec-mb && \
    cd /intel-ipsec-mb && \
    make -j SAFE_DATA=y SAFE_PARAM=y SAFE_LOOKUP=y && \
    make install NOLDCONFIG=y PREFIX=/usr/local/

ARG QAT_ENGINE_VERSION="v0.6.5"
RUN git clone -b $QAT_ENGINE_VERSION https://github.com/intel/QAT_Engine.git && \
    cd /QAT_Engine && \
    ./autogen.sh && \
    ./configure \
      --with-openssl_install_dir=/usr/local/ \
      --with-qat_sw_install_dir=/usr/local/ \
      --enable-qat_sw && \
    make && \
    make install

ARG ASYNC_NGINX_VERSION="v0.4.5"
RUN git clone -b $ASYNC_NGINX_VERSION https://github.com/intel/asynch_mode_nginx.git && \
    cd /asynch_mode_nginx && \
    ./configure \
      --prefix=/var/www \
      --conf-path=/usr/local/share/nginx/conf/nginx.conf \
      --sbin-path=/usr/local/bin/nginx \
      --pid-path=/run/nginx.pid \
      --lock-path=/run/lock/nginx.lock \
      --modules-path=/var/www/modules/ \
      --without-http_rewrite_module \
      --with-http_ssl_module \
      --with-pcre \
      --add-dynamic-module=modules/nginx_qat_module/ \
      --with-cc-opt="-DNGX_SECURE_MEM -I/usr/local/include/openssl -Wno-error=deprecated-declarations -Wimplicit-fallthrough=0" \
      --with-ld-opt="-Wl,-rpath=/usr/local/lib64 -L/usr/local/lib64" \
      --user=nginx \
      --group=nginx && \
    make && \
    make install

FROM centos:centos8.3.2011 AS runnable

COPY --from=compile-stage /usr/local/ /usr/local/
COPY --from=compile-stage /var/www/ /var/www/

COPY --chown=1000:1000 main.sh /
RUN /bin/bash -c 'chmod +x /main.sh'

COPY nginx-script.sh /nginx-script.sh
COPY nginx-avg.conf /usr/local/share/nginx/conf/nginx-avg.conf

ENV OPENSSL_ENGINES=/usr/local/lib/engines-1.1

ARG SSL_ASYNC
ENV SSL_ASYNC="${SSL_ASYNC}"

ARG NGINX_WP
ENV NGINX_WP="${NGINX_WP}"

ARG NGINX_CIPHER
ENV NGINX_CIPHER="${NGINX_CIPHER}"

STOPSIGNAL SIGTERM

RUN useradd -ms /bin/bash nginx && \
    chown -R nginx:nginx /usr/local/share/nginx/ && \
    chown -R nginx:nginx /var/www/
USER nginx

ENTRYPOINT ["/main.sh"]
CMD ["/main.sh", "${SSL_ASYNC}". "${NGINX_WP}", "${NGINX_CIPHER}"]
