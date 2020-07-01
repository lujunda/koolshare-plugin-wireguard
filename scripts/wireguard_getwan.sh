#!/bin/sh

export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
ispppoe=`ifconfig|grep pppoe|grep -v grep`
if [ -n "$ispppoe" ];then
	basicwan=`ifconfig|grep  "Link encap"|awk '{print $1}'|grep -v lo|grep -v "br-lan"|grep -v eth|grep -v wg0|sed ':a;N;$!ba;s#\n#>#g'`
else
	basicwan=`ifconfig|grep  "Link encap"|awk '{print $1}'|grep -v lo|grep -v "br-lan"|grep -v wg0|sed ':a;N;$!ba;s#\n#>#g'`
fi
http_response "$basicwan"
