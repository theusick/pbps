#!/bin/bash

sudo systemctl stop slapd
sudo apt-get purge -y slapd ldap-utils
sudo rm -rf /etc/ldap /var/lib/ldap
