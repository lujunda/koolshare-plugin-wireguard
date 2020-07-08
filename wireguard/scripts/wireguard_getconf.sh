#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
basicconf=`ls /koolshare/wireguard/conf|grep .conf|grep -v "wireguard.conf"|cut -d " " -f1|sed ':a;N;$!ba;s#\n#>#g'`

http_response "$basicconf"
