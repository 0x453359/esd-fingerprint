#!/bin/bash

mkdir -p /var/log/esd/
mkdir -p /usr/local/bin/esd/metadata/esd_hash
mkdir -p /usr/local/bin/esd/metadata/esd_hash/cert
mkdir -p /usr/local/bin/esd/metadata/esd_hash/ff
mkdir -p /usr/local/bin/esd/metadata/esd_hash/lf
mkdir -p /usr/local/bin/esd/metadata/esd_hash/tld
mkdir -p /usr/local/bin/esd/metadata/record
mkdir -p /usr/local/bin/esd/metadata/domain
touch /usr/local/bin/esd/metadata/domain/h2_domain
touch /usr/local/bin/esd/metadata/domain/http_domain


wget -P /usr/local/bin/esd/ https://github.com/0x453359/esd-fingerprint/raw/main/esd_fingerprint.tar.gz

tar -xzvf /usr/local/bin/esd/esd_fingerprint.tar.gz -C /usr/local/bin/esd/

rm -rf /usr/local/bin/esd/esd_fingerprint.tar.gz




