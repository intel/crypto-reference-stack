#!/usr/bin/env bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Default variables
NGINX_INSTALL_DIR=/usr/local/share/nginx
nginx_config_file=$NGINX_INSTALL_DIR/conf/nginx-avg.conf
nginx_qat_engine=-1
update_nginx_wp=-1
kill_nginx=0
start_nginx=0
list_nginx=0
check_errors=0
clear_errors=0
tune_network=0
generate_certs=0
ssl_cipher=''

mkdir -p /usr/local/share/nginx/logs/

##################################################################################

function generate_certs_fn () {
	mkdir -p "$NGINX_INSTALL_DIR/certs"
	# generate RSA certificate
	openssl req -newkey rsa:2048 -nodes -keyout $NGINX_INSTALL_DIR/certs/rsa.key -x509 -days 365 -out $NGINX_INSTALL_DIR/certs/rsa.crt -subj "/C=/ST=/L=/O=/OU=/CN=$(hostname)" 2> /dev/null

	# generate DSA certificate
	openssl ecparam -genkey -out $NGINX_INSTALL_DIR/certs/dsa.key -name prime256v1
	openssl req -x509 -new -key $NGINX_INSTALL_DIR/certs/dsa.key -out $NGINX_INSTALL_DIR/certs/dsa.crt -subj "/C=/ST=/L=/O=/OU=/CN=$(hostname)" 2> /dev/null
}

function kill_nginx_fn () {
	if [[ -f $NGINX_INSTALL_DIR/logs/nginx.pid ]]; then
		kill -quit $( cat $NGINX_INSTALL_DIR/logs/nginx.pid )
	elif ps -ef | grep '[n]ginx: .* process' > /dev/null; then
		ps -ef | grep '[n]ginx: .* process' | tr -s ' ' | cut -d ' ' -f 2 | for i in `xargs`; do kill -9 $i; done
	fi
}

function start_nginx_fn () {
	echo -e "\nStarting NGINX server: "
	echo -e "\tnginx -c $nginx_config_file"
	nginx -c $nginx_config_file
}

function list_nginx_fn () {
	if ps -ef | grep "[n]ginx.*worker" > /dev/null; then
		echo -e "\nNGINX master processes = $(ps -ef | grep "[n]ginx.*master" | wc -l)"
		echo -e "NGINX worker processes = $(ps -ef | grep "[n]ginx.*worker" | wc -l)\n"

		echo -e "UID\t\tPID\tPPID\tCOMMAND\t\tSOFT\tHARD\tUNITS"
		temp_IFS="$IFS"
		IFS=$'\n'
		nginx_ps=$(ps -e -o uid,pid,ppid,cmd | grep '[n]ginx.*process')
		for nginx_ps_iter in $nginx_ps; do
			cur_pid=$(echo $nginx_ps_iter | awk '{print $2}')
			echo -en "$(ps -o uid,pid,ppid,cmd -p $cur_pid| tail -n 1)\t"
			prlimit -p $cur_pid | grep NOFILE | sed -e 's/NOFILE\s\+max number of open files\s\+//'
		done
		IFS="$temp_IFS"
	else
		echo -e "\nNo NGINX processes found."
	fi
}

function check_errors_fn () {
	echo -e "\nChecking for errors : $NGINX_INSTALL_DIR/logs/error.log"
	if [[ ! -z "$(cat $NGINX_INSTALL_DIR/logs/error.log)" ]]; then
		cat $NGINX_INSTALL_DIR/logs/error.log
	else
		echo -e "No Errors."
	fi
}

function clear_errors_fn () {
	echo -e "\nClearing $NGINX_INSTALL_DIR/logs/error.log"
	echo "" > $NGINX_INSTALL_DIR/logs/error.log
}

function tune_network_fn () {
	echo 1025 65535 > /proc/sys/net/ipv4/ip_local_port_range
	echo 50000 > /proc/sys/net/ipv4/tcp_max_tw_buckets
	echo 5000 > /proc/sys/net/core/netdev_max_backlog
	echo 16777216 > /proc/sys/net/core/rmem_default
	echo 65535 > /proc/sys/net/core/somaxconn
	echo 262144 > /proc/sys/net/ipv4/tcp_max_syn_backlog

	ulimit -n 200000
	sysctl -w net.ipv4.tcp_congestion_control=bic > /dev/null
	set selinux=disabled
	service iptables stop 2>/dev/null
	service ip6tables stop 2>/dev/null
	service irqbalance stop 2>/dev/null
	service ufw stop 2>/dev/null
}

function update_nginx_wp_fn () {
	sed -i -r -e "s/^worker_processes\s+[0-9]+;/worker_processes $1;/" $nginx_config_file
	echo -e "\nUpdated nginx WP count to: $(grep -Po 'worker_processes \K\d+' $nginx_config_file)"
}

function update_ssl_cipher_fn () {
	# make sure input ssl_cipher is in correct format
	if [[ "$(echo $ssl_cipher | grep -o ':' | grep -c ':')" -lt 2 ]]; then
		echo -e "\nInput cipher suite must be of the format cipher_suite:kx:au:curve (curve is optional)"
		echo -e "Received $ssl_cipher\n"
		return 1
	fi

	# input cipher suite must be of the format cipher_suite:kx:au:curve
	cipher_suite=$(echo $ssl_cipher | cut -d ':' -f 1)
	kx=$(echo $ssl_cipher | cut -d ':' -f 2)
	au=$(echo $ssl_cipher | cut -d ':' -f 3)
	curve=$(echo $ssl_cipher | cut -d ':' -f 4)

	# validate input parameters
	if [[ "$kx" != "ECDH"* ]]; then
		echo -e "\n${RED}Use of RSA Kx has been deprecated.${RESET_COLOR} Key exchange has to be ECDH (input: $kx)"
		echo -e "Although the current script allows setting other Kx algorithms, the only valid use case as determined by the team is Kx=ECDH."
	fi

	if [[ "$au" != "ECDSA" ]] && [[ "$au" != "RSA" ]]; then
		echo -e "\nOnly ECDSA and RSA authentication modes are supported (input: $au)\n"
		return 1
	fi

	# get info in the cipher suite
	kx_ssl=$(openssl ciphers -v -V | grep -Po " - $cipher_suite\s+.*Kx=\K.*" | sed -e 's/\s\+.*//')
	au_ssl=$(openssl ciphers -v -V | grep -Po " - $cipher_suite\s+.*Au=\K.*" | sed -e 's/\s\+.*//')

	# verify input cipher suite
	if [[ -z "$kx_ssl" ]] && [[ -z "$au_ssl" ]]; then
		echo -e "\nInvalid cipher suite provided (input: $cipher_suite)\n"
		return 1
	fi

	# verify kx and au for TLSv1.2 cipher suites
	if [[ "$kx_ssl" != "any" ]]; then
		if [[ "$kx" != "$kx_ssl" ]] || [[ "$au" != "$au_ssl" ]]; then
			echo -e "\nkx or au does not match specification on cipher suite:\n\tkx=$kx (required: $kx_ssl)\n\tau=$au (required: $au_ssl)\n"
			return 1
		fi
	fi

	# set protocol and ciphers to use
	if [[ "$cipher_suite" == "TLS_"* ]]; then
		# TLS 1.3 ciphers
		sed -i -r -e "s/ssl_protocols .*/ssl_protocols TLSv1.3;/" $nginx_config_file
		sed -i -r -e "s/ssl_ciphers .*/ssl_ciphers ALL;/" $nginx_config_file
	else
		# TLS 1.2 ciphers
		sed -i -r -e "s/ssl_protocols .*/ssl_protocols TLSv1.2;/" $nginx_config_file
		sed -i -r -e "s/ssl_ciphers .*/ssl_ciphers $cipher_suite;/" $nginx_config_file
	fi
	sed -i -r -e "s/default_algorithms .*/default_algorithms ALL;/" $nginx_config_file

	# for ECDHE, specify the curve
	if [[ "$kx" == "ECDH"* ]]; then
		if [[ ! -z "$curve" ]]; then
			sed -i -r -e "s/(# )?ssl_ecdh_curve .*/ssl_ecdh_curve $curve;/" $nginx_config_file
		else
			echo -e "\nCurve not provided for ECDH, using default X25519."
			sed -i -r -e "s/(# )?ssl_ecdh_curve .*/ssl_ecdh_curve X25519;/" $nginx_config_file
		fi
	else
		sed -i -r -e "s/(# )?(ssl_ecdh_curve .*)/# \2/" $nginx_config_file
	fi

	# specify the certificates to use
	sed_nginx_dir=$(echo $NGINX_INSTALL_DIR | sed -e 's#/#\\/#g')
	if [[ "$au" == "ECDSA" ]]; then
		sed -i -r -e "s/ssl_certificate .*/ssl_certificate $sed_nginx_dir\/certs\/dsa.crt;/" $nginx_config_file
		sed -i -r -e "s/ssl_certificate_key .*/ssl_certificate_key $sed_nginx_dir\/certs\/dsa.key;/" $nginx_config_file
	elif [[ "$au" == "RSA" ]]; then
		sed -i -r -e "s/ssl_certificate .*/ssl_certificate $sed_nginx_dir\/certs\/rsa.crt;/" $nginx_config_file
		sed -i -r -e "s/ssl_certificate_key .*/ssl_certificate_key $sed_nginx_dir\/certs\/rsa.key;/" $nginx_config_file
	fi

	# print status
	echo -e "\nSettings for cipher suite: $cipher_suite"
	echo -e "\tssl_protocols:\t\t\t\t$(grep -Po 'ssl_protocols \K[\w\.]+' $nginx_config_file)"
	echo -e "\tssl_ciphers:\t\t\t\t$(grep -Po 'ssl_ciphers \K[\w-]+' $nginx_config_file)"
	echo -e "\tdefault_algorithms:\t\t\t$(grep -Po 'default_algorithms \K[\w,]+' $nginx_config_file)"
	echo -e "\tssl_ecdh_curve config:$(grep -P 'ssl_ecdh_curve' $nginx_config_file)"
	echo -e "\tssl_certificate:\t\t\t$(grep -Po 'ssl_certificate \K[\w\/\.]+' $nginx_config_file)"
	echo -e "\tssl_certificate_key:\t\t$(grep -Po 'ssl_certificate_key \K[\w\/\.]+' $nginx_config_file)\n"
}

function nginx_use_qat_engine_fn () {
	# get the current status
	cur_nginx_qat_engine=$(grep -Po '# nginx_use_qat_engine=\K.*' $nginx_config_file)

	if [[ "$nginx_qat_engine" -eq "1" ]] || $nginx_qat_engine 2> /dev/null; then
		echo -e "\nSetting NGINX conf file to use QAT_engine."
		if [[ "$cur_nginx_qat_engine" == "true" ]]; then
			echo -e "NGINX is already configured, current status = $cur_nginx_qat_engine"
		else
			sed -i -e 's/# nginx_use_qat_engine=.*/# nginx_use_qat_engine=true/' $nginx_config_file
			start_line=$(( $(grep -n '#start_qat_engine_block' $nginx_config_file | cut -d ':' -f 1) + 1 ))
			end_line=$(( $(grep -n '#end_qat_engine_block' $nginx_config_file | cut -d ':' -f 1) - 1 ))
			sed -i -e "$start_line,$end_line s/^# //" $nginx_config_file
		fi
	else
		echo -e "\nSetting NGINX conf file to not use QAT_engine."
		if [[ "$cur_nginx_qat_engine" == "false" ]]; then
			echo -e "NGINX is already configured, current status = $cur_nginx_qat_engine"
		else
			sed -i -e 's/# nginx_use_qat_engine=.*/# nginx_use_qat_engine=false/' $nginx_config_file
			start_line=$(( $(grep -n '#start_qat_engine_block' $nginx_config_file | cut -d ':' -f 1) + 1 ))
			end_line=$(( $(grep -n '#end_qat_engine_block' $nginx_config_file | cut -d ':' -f 1) - 1 ))
			sed -i -e "$start_line,$end_line s/^/# /" $nginx_config_file
		fi
	fi
}

function print_help_fn () {
	echo -e "\nNGINX helper script.\n\nAvailable Parameters:"
	echo -e "\n\t-h | --help\n\t\tPrint this help."
	echo -e "\n\t-k | --kill-nginx\n\t\tKill nginx server processes if any."
	echo -e "\n\t-s | --start-nginx\n\t\tStart NGINX server with the QAT configuration file specified by --nginx-config-file (see below)."
	echo -e "\n\t-l | --list-nginx\n\t\tList all the running NGINX processes."
	echo -e "\n\t-c | --check-errors\n\t\tCheck for errors after starting NGINX server."
	echo -e "\n\t-C | --clear-errors\n\t\tClear the errors file."
	echo -e "\n\t-t | --tune-network\n\t\tTune the network parameters for this system."
	echo -e "\n\t-u | --update-nginx-wp\n\t\tUpdate nginx worker processes in NGINX config file specified by --nginx-config-file (see below)."
	echo -e "\n\t-f | --nginx-config-file\n\t\tSpecified NGINX config file to use.\n\t\tDefault: /usr/local/nginx/conf/nginx-avg.conf"
	echo -e "\n\t-e | --nginx-qat-engine [true|false|0|1]\n\t\tUpdate NGINX config file to enable/disable use of QAT_Engine."
	echo -e "\n\t-X | --cipher-suite <OpenSSL cipher suite>.\n\t\tUpdate the NGINX config file to use the specified cipher suite. The provided cipher suite must be of the format: 'Cipher-Suite:Kx:Au:Curve'."
	echo -e "\t\t\tCipher-Suite:\tmust be one of the valid OpenSSL suites\n\t\t\tKx:\t\t\t\t RSA | ECDH\n\t\t\tAu:\t\t\t\t RSA | ECDSA\n\t\t\tCurve:\t\t\t optional (default: X25519)"
	echo -e ""
}

##################################################################################

TEMP=`getopt -o kslcCthu:f:e:vX:g --long kill-nginx,start-nginx,list-nginx,check-errors,clear-errors,tune-network,help,update-nginx-wp:,nginx-config-file:,nginx-qat-engine:,cipher-suite:,version,generate-certs -n 'Yikes' -- "$@"`
if [[ $? -ne 0 ]]; then
	echo -e "\nError parsing input parameters. Exiting"
	print_help_fn
	exit 1
fi

eval set -- "$TEMP"

while true; do
	case $1 in
		-f | --nginx-config-file ) nginx_config_file=$2; shift 2;;
		-u | --update-nginx-wp ) update_nginx_wp=$2; shift 2;;
		-e | --nginx-qat-engine ) nginx_qat_engine=$2; shift 2;;
		-X | --cipher-suite ) ssl_cipher=$2; shift 2;;
		-k | --kill-nginx ) kill_nginx=1; shift ;;
		-s | --start-nginx ) start_nginx=1; shift ;;
		-l | --list-nginx ) list_nginx=1; shift ;;
		-c | --check-errors ) check_errors=1; shift ;;
		-C | --clear-errors ) clear_errors=1; shift ;;
		-g | --generate-certs ) generate_certs=1; shift ;;
		-h | --help ) print_help_fn; shift; exit;;
		-v | --version ) echo "v0.103"; shift; exit;;
		-- ) shift ;;
		* ) break ;;
	esac
done

# Validate input parameters
if [[ "$nginx_qat_engine" -eq "-1" ]] && [[ "$update_nginx_wp" -eq "-1" ]] && [[ "$kill_nginx" -eq "0" ]] && [[ "$start_nginx" -eq "0" ]] && [[ "$list_nginx" -eq "0" ]] && [[ "$check_errors" -eq "0" ]] && [[ "$clear_errors" -eq "0" ]] && [[ "$tune_network" -eq "0" ]] && [[ -z "$ssl_cipher" ]] && [[ "$generate_certs" -eq "0" ]]; then
 	echo -e "\nYou've to select at least one of [--kill-nginx | --start-nginx | --list-nginx | --check-errors | --clear-errors | --tune-network | --update-nginx-wp | --nginx-qat-engine | --help | --version]"
 	print_help_fn
 	exit 0
fi

# check nginx config file
if [[ ! -f "$nginx_config_file" ]]; then
	echo -e "\nCould not find NGINX config file at: $nginx_config_file"
	return 1
fi

# check nginx-avg config file version
if ! grep -q nginx_avg_version $nginx_config_file; then
	echo -e "\nnginx_avg_version not found in config file. The script might severely alter "
	read -p "Do you wish to continue? (y|n): " confirm_var
	if [[ "${confirm_var,}" != "y" ]]; then
		echo -e "\nExiting\n"
		exit 1
	fi
fi

if [[ "$nginx_qat_engine" -ne "-1" ]]; then
	nginx_use_qat_engine_fn $nginx_qat_engine
fi

if [[ "$update_nginx_wp" -ne "-1" ]]; then
	update_nginx_wp_fn $update_nginx_wp
fi

if [[ "$kill_nginx" -eq "1" ]]; then
	kill_nginx_fn
fi

if [[ "$start_nginx" -eq "1" ]]; then
	kill_nginx_fn
	clear_errors_fn
	sleep 2
	start_nginx_fn
	check_errors_fn
	sleep 5
	list_nginx_fn
fi

if [[ "$list_nginx" -eq "1" ]]; then
	list_nginx_fn
fi

if [[ "$check_errors" -eq "1" ]]; then
	check_errors_fn
fi

if [[ "$clear_errors" -eq "1" ]]; then
	clear_errors_fn
fi

if [[ "$tune_network" -eq "1" ]]; then
	tune_network_fn
fi

if [[ ! -z "$ssl_cipher" ]]; then
	update_ssl_cipher_fn
fi

if [[ "$generate_certs" -eq "1" ]]; then
	generate_certs_fn
fi

