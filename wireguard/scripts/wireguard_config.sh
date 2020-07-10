#!/bin/sh
export KSROOT=/koolshare
source $KSROOT/scripts/base.sh
eval `dbus export wireguard_`
alias echo_date='echo 【$(date +%Y年%m月%d日\ %X)】:'
LOCK_FILE=/var/lock/wireguard.lock
LOG_FILE=/tmp/upload/wireguard_log.txt
NEEDRESTARTDNS=0

ReadINI() {
	local INIFILE SECTION ITEM readIni
	INIFILE=$1; SECTION=$2; ITEM=$3
	readIni=`awk -F '=' '/['$SECTION']/{a=1}a==1&&$1~/'$ITEM'/{print $2;exit}' $INIFILE`
	echo ${readIni} 
}

WriteINIfile(){
	local INIFILE SECTION ITEM NEWVAL WriteINI
	INIFILE=$1; SECTION=$2; ITEM=$3; NEWVAL=$4
	WriteINI=`sed -i "/^\[$SECTION\]/,/^\[/ {/^\[$SECTION\]/b;/^\[/b;s/^$ITEM*=.*/$ITEM=$NEWVAL/g;}" $INIFILE`
	echo $WriteINI
}

update_opkg(){
	[ -f "/tmp/opkg-lists/openwrt_koolshare_mod_core" -a -f "/tmp/opkg-lists/openwrt_koolshare_mod_packages" ] || {
		echo_date "获取支持环境最新版本信息"
		opkg update
		if [ "$?" -eq 0 ] ; then
			echo_date "最新版本信息已成功获取，准备下载安装"
		else
			echo_date "获取最新版本信息失败，你的网络可能有问题，请重试！"
			unset_lock
			echo XU6J03M6 >> $logfile
			http_response "$1"
			exit 0
		fi
	}
}

check_opkg(){
	echo_date "开始检测固件内WireGuard支持环境"
	local hbipk ipknum
	ipknum="1"
	hbipk="wireguard"
	for hbipk in $hbipk
	do
		local ipkinstall=$(opkg list-installed | grep "$hbipk")
		if [ -z "$ipkinstall" ]; then
			update_opkg
			echo_date "安装支持环境-$ipknum"
			opkg install $hbipk >/dev/null 2>&1
			if [ "$?" -eq 0 ] ; then
				echo_date "支持环境-$ipknum已安装，检测通过"
			else
				echo_date "安装支持环境-$ipknum失败，请升级到2.25以后的版本！"
				rm -rf /tmp/opkg-lists
				unset_lock
				echo XU6J03M6 >> $logfile
				http_response "$1"
				exit 0
			fi
		else
			echo_date "支持环境-$ipknum已安装，检测通过"		
		fi
	ipknum=`expr $ipknum + 1`
	done			
}

create_dnsmasq_conf(){
	local wanwhitedomain wanblackdomain
	[ ! -f /tmp/dnsmasq.d/wireguardgfw.conf ] && {
		echo_date 创建国外GFW解析优化配置文件
		cat $KSROOT/wireguard/gfwlist | awk '{print "server=/"$1"/8.8.8.8\nipset=/"$1"/gfwlist"}' >> /tmp/dnsmasq.d/wireguardgfw.conf
	}
	# append white domain list,not through ss
	wanwhitedomain=$(echo $wireguard_wan_white_domain | base64_decode)
	if [ -n "$wireguard_wan_white_domain" ];then
		echo_date 应用域名白名单
		echo "#for white_domain" >> /tmp/dnsmasq.d/wireguardwblist.conf
		for wan_white_domain in $wanwhitedomain
		do
			echo "$wan_white_domain" | sed "s/^/ipset=&\/./g" | sed "s/$/\/white_list/g" >> /tmp/dnsmasq.d/wireguardwblist.conf
		done
	fi

	# append black domain list,through ss
	wanblackdomain=$(echo $wireguard_wan_black_domain | base64_decode)
	if [ -n "$wireguard_wan_black_domain" ];then
		echo_date 应用域名黑名单
		echo "#for black_domain" >> /tmp/dnsmasq.d/wireguardwblist.conf
		for wan_black_domain in $wanblackdomain
		do
			echo "$wan_black_domain" | sed "s/^/ipset=&\/./g" | sed "s/$/\/black_list/g" >> /tmp/dnsmasq.d/wireguardwblist.conf
		done
	fi

	echo "no-resolv" >> /tmp/dnsmasq.d/wireguard.conf
	echo "server=114.114.114.114" >> /tmp/dnsmasq.d/wireguard.conf
	echo "server=22.3.5.5" >> /tmp/dnsmasq.d/wireguard.conf
	NEEDRESTARTDNS=1
}

get_config_file(){
	if [ "$wireguard_basic_conf" == "0" ];then
		echo_date 使用自定义配置文件
		WIREGUARD_CONFIG="$KSROOT/wireguard/conf/wireguard.conf"
		echo "$wireguard_custom_config" | base64_decode > $WIREGUARD_CONFIG
	else
		echo_date 使用配置文件：$wireguard_basic_conf
		WIREGUARD_CONFIG="$KSROOT/wireguard/conf/$wireguard_basic_conf"
	fi
}

start_smartdns(){
	local SDNSPID
	echo_date 开启 SmartDNS ...
	cat > /var/etc/smartdns.conf <<-EOF
		server-name wireguarddns
		bind [::]:7923
		bind-tcp [::]:7923
		cache-size 10240
		log-size 128K
		log-num 3
		log-level error
		server 223.5.5.5:53
		server 223.6.6.6:53
		server 119.29.29.29:53
		server 114.114.114.114:53
		server 180.76.76.76:53
		server 101.226.4.6:53
		server 199.91.73.222:53
		server 9.9.9.9:53
		server 8.8.8.8:53
		server 208.67.222.222:53
		server 117.50.11.11:53
	EOF
	echo_date "生成 SmartDNS 配置文件"
	/koolshare/bin/smartdns -c /var/etc/smartdns.conf >/dev/null 2>&1 &
	local i=10
	until [ -n "$SDNSPID" ]
	do
		i=$(($i-1))
		SDNSPID=`pidof smartdns`
		if [ "$i" -lt 1 ];then
			echo_date "SmartDNS进程启动失败！"
		fi
		sleep 1
	done
	echo_date SmartDNS启动成功，pid：$SDNSPID
	sed -i '/wireguardchecksdns/d' /etc/crontabs/root >/dev/null 2>&1
	echo "*/1 * * * * /koolshare/scripts/wireguard_config.sh sdns" >> /etc/crontabs/root
}

check_smartdns(){
	if [ -z `pidof smartdns` ]; then
		/koolshare/bin/smartdns -c /var/etc/smartdns.conf >/dev/null 2>&1 &
		echo_date "SmartDNS 已崩溃，重启进程！" >> $LOG_FILE
	fi
}

restore_dnsmasq_conf(){
	if [ -n "`ls /tmp/dnsmasq.d/wireguard*.conf 2>/dev/null`" ];then
		echo_date 删除 wireguard 相关的名单配置文件.
		rm -rf /tmp/dnsmasq.d/wireguard*.conf
		NEEDRESTARTDNS=1
	fi
}

restore_start_file(){
	echo_date 清除firewall中相关的 wireguard 启动命令...
	uci -q batch <<-EOT
	  delete firewall.ks_wireguard
	  commit firewall
	EOT
}

restart_dnsmasq(){
	# Restart dnsmasq
	[ "$NEEDRESTARTDNS" == "1" ] && {
		echo_date 重启dnsmasq服务...
		/etc/init.d/dnsmasq restart >/dev/null 2>&1
	}
}

# creat ipset rules
creat_ipset(){
	echo_date 创建ipset名单
	ipset -! create white_list nethash && ipset flush white_list
	ipset -! create black_list nethash && ipset flush black_list
	ipset -! create gfwlist nethash && ipset flush gfwlist
}

add_white_black_ip(){
	# black ip/cidr
	local ip_tg ip ip_lan
	ip_tg="67.198.55.0/24 91.108.4.0/22 91.108.12.0/22 91.108.56.0/22 91.108.8.0/22 93.119.240.0/20 109.239.140.0/24 149.154.0.0/16 149.154.160.0/20"
	for ip in $ip_tg
	do
		ipset -! add black_list $ip >/dev/null 2>&1
	done
	
	if [ ! -z $wireguard_wan_black_ip ];then
		wireguard_wan_black_ip=`dbus get wireguard_wan_black_ip|base64_decode|sed '/\#/d'`
		echo_date 应用IP/CIDR黑名单
		for ip in $wireguard_wan_black_ip
		do
			ipset -! add black_list $ip >/dev/null 2>&1
		done
	fi
	
	# white ip/cidr
	ip_lan="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 $SERVERIP 223.5.5.5 223.6.6.6 114.114.114.114 114.114.115.115 1.2.4.8 210.2.4.8 112.124.47.27 114.215.126.16 180.76.76.76 119.29.29.29"
	for ip in $ip_lan
	do
		ipset -! add white_list $ip >/dev/null 2>&1
	done
	
	if [ ! -z $wireguard_wan_white_ip ];then
		wireguard_wan_white_ip=`echo $wireguard_wan_white_ip|base64_decode|sed '/\#/d'`
		echo_date 应用IP/CIDR白名单
		for ip in $wireguard_wan_white_ip
		do
			ipset -! add white_list $ip >/dev/null 2>&1
		done
	fi
}

get_action_chain() {
	case "$1" in
		0)
			echo "RETURN"
		;;
		1)
			echo "WIREGUARD_GFW"
		;;
		2)
			echo "WIREGUARD_CHN"
		;;
		3)
			echo "WIREGUARD_GLO"
		;;
	esac
}

get_mode_name() {
	case "$1" in
		0)
			echo "不通过代理"
		;;
		1)
			echo "gfwlist模式"
		;;
		2)
			echo "大陆白名单模式"
		;;
		3)
			echo "全局模式"
		;;
	esac
}

factor(){
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

get_jump_mode(){
	case "$1" in
		0)
			echo "j"
		;;
		*)
			echo "g"
		;;
	esac
}

lan_acess_control(){
	# lan access control
	local acl_nu ipaddr proxy_mode proxy_name mac
	acl_nu=`dbus list wireguard_acl_mode|sort -n -t "=" -k 2|cut -d "=" -f 1 | cut -d "_" -f 4`
	if [ -n "$acl_nu" ]; then
		for acl in $acl_nu
		do
			ipaddr=`dbus get wireguard_acl_ip_$acl`
			proxy_mode=`dbus get wireguard_acl_mode_$acl`
			proxy_name=`dbus get wireguard_acl_name_$acl`
			#mac=`dbus get wireguard_acl_mac_$acl`
			mac=""
			ports=`dbus get wireguard_acl_port_$acl`
			ports_user=`dbus get wireguard_acl_port_user_$acl`
			if [ "$ports" == "all" ]; then
				ports=""
				[ -n "$ipaddr" ] && [ -z "$mac" ] && echo_date 加载ACL规则：【$ipaddr】【全部端口】模式为：$(get_mode_name $proxy_mode)
				[ -z "$ipaddr" ] && [ -n "$mac" ] && echo_date 加载ACL规则：【$mac】【全部端口】模式为：$(get_mode_name $proxy_mode)
				[ -n "$ipaddr" ] && [ -n "$mac" ] && echo_date 加载ACL规则：【$ipaddr】【$mac】【全部端口】模式为：$(get_mode_name $proxy_mode)
			elif [ "$ports" == "0" ]; then
				ports=$ports_user
				[ -n "$ipaddr" ] && [ -z "$mac" ] && echo_date 加载ACL规则：【$ipaddr】【$ports】模式为：$(get_mode_name $proxy_mode)
				[ -z "$ipaddr" ] && [ -n "$mac" ] && echo_date 加载ACL规则：【$mac】【$ports】模式为：$(get_mode_name $proxy_mode)
				[ -n "$ipaddr" ] && [ -n "$mac" ] && echo_date 加载ACL规则：【$ipaddr】【$mac】【$ports】模式为：$(get_mode_name $proxy_mode)
			else
				[ -n "$ipaddr" ] && [ -z "$mac" ] && echo_date 加载ACL规则：【$ipaddr】【$ports】模式为：$(get_mode_name $proxy_mode)
				[ -z "$ipaddr" ] && [ -n "$mac" ] && echo_date 加载ACL规则：【$mac】【$ports】模式为：$(get_mode_name $proxy_mode)
				[ -n "$ipaddr" ] && [ -n "$mac" ] && echo_date 加载ACL规则：【$ipaddr】【$mac】【$ports】模式为：$(get_mode_name $proxy_mode)
			fi
			# acl in wireguard
			if [ -n "$ports" ]; then
				iptables -t mangle -A WIREGUARD $(factor $ipaddr "-s") $(factor $mac "-m mac --mac-source") -p tcp $(factor $ports "-m multiport --dport") -$(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
				iptables -t mangle -A WIREGUARD $(factor $ipaddr "-s") $(factor $mac "-m mac --mac-source") -p udp $(factor $ports "-m multiport --dport") -$(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
			else
				iptables -t mangle -A WIREGUARD $(factor $ipaddr "-s") $(factor $mac "-m mac --mac-source") -$(get_jump_mode $proxy_mode) $(get_action_chain $proxy_mode)
			fi
		done
		if [ "$wireguard_acl_default_port" == "all" ];then
			wireguard_acl_default_port="" 
		elif [ "$wireguard_acl_default_port" == "0" ];then
			wireguard_acl_default_port=$wireguard_acl_default_port_user 
		fi
		echo_date 加载ACL规则：【剩余主机】模式为：$(get_mode_name $wireguard_acl_default_mode)
	else
			wireguard_acl_default_port="" 
			echo_date 加载ACL规则：【全部主机】【全部端口】模式为：$(get_mode_name $wireguard_acl_default_mode)
	fi
}

check_route(){
	local RT
	echo_date 检查 routetable
	RT=`cat /etc/iproute2/rt_tables | grep wireguardtable`
    [ -z "$RT" ] && {
        echo "302 wireguardtable" >> /etc/iproute2/rt_tables
		echo_date "配置 routetable"
    }
}

apply_nat_rules(){
	local DNS_LIST DNSLIST
	#----------------------BASIC RULES---------------------
	echo_date 写入iptables规则到mangle表中...
	# 创建wireguard mangle rule
	iptables -t mangle -N WIREGUARD
	iptables -t mangle -A PREROUTING -j WIREGUARD
	# IP/cidr/白域名 白名单控制（不走代理） for wireguard
	iptables -t mangle -A WIREGUARD -m set --match-set white_list dst -j RETURN
	#-----------------------FOR GFWLIST---------------------
	# 创建gfwlist模式
	iptables -t mangle -N WIREGUARD_GFW
	# IP/CIDR/黑域名 黑名单控制（走代理）
	iptables -t mangle -A WIREGUARD_GFW -m set --match-set black_list dst -j MARK --set-mark 0x12e
	iptables -t mangle -A WIREGUARD_GFW -m set --match-set gfwlist dst -j MARK --set-mark 0x12e
	#-----------------------FOR CHNMODE---------------------
	# 创建大陆白名单模式
	iptables -t mangle -N WIREGUARD_CHN
	iptables -t mangle -A WIREGUARD_CHN -m set --match-set black_list dst -j MARK --set-mark 0x12e
	iptables -t mangle -A WIREGUARD_CHN -m geoip ! --destination-country CN -j MARK --set-mark 0x12e
	#-----------------------FOR GLOABLE---------------------
	# 创建全局模式
	iptables -t mangle -N WIREGUARD_GLO
	# 全局模式控制-全局（走代理）
	iptables -t mangle -A WIREGUARD_GLO -j MARK --set-mark 0x12e	
	#-------------------------------------------------------
	# 局域网黑名单（不走代理）/局域网黑名单（走代理）
	lan_acess_control
	# 把最后剩余流量重定向到相应模式的nat表中对对应的主模式的链
	iptables -t mangle -A WIREGUARD -j $(get_action_chain $wireguard_acl_default_mode)
	#-----------------------NAT表规则-----------------------
	iptables -t nat -I POSTROUTING -o wg0 -j MASQUERADE
	iptables -t nat -I POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	iptables -I FORWARD -o wg0 -j ACCEPT

	iptables -t mangle -A OUTPUT -j WIREGUARD
	#-----------------------FOR DNS---------------------
	DNS_LIST="8.8.8.8 9.9.9.9 208.67.222.222 199.91.73.222"
	for DNSLIST in $DNS_LIST
	do
		ip route add $DNSLIST dev wg0 >/dev/null 2>&1
	done
	#-----------------------FOR route---------------------
	ip rule add fwmark 0x12e table wireguardtable pref 791
	ip route add default dev wg0 table wireguardtable
}

# =======================================================================================================
flush_nat(){
	local ip_mangle_exist ip_rule_exist out_nu
	echo_date 尝试先清除已存在的iptables规则，防止重复添加
	# flush rules and set if any
	ip_mangle_exist=`iptables -t mangle -L PREROUTING | grep -c WIREGUARD`
	if [ "$ip_mangle_exist" -ne 0 ]; then
		for i in `seq $ip_mangle_exist`
		do
			iptables -t mangle -D PREROUTING -j WIREGUARD > /dev/null 2>&1
			iptables -t mangle -D OUTPUT -j WIREGUARD > /dev/null 2>&1
			iptables -D FORWARD -o wg0 -j ACCEPT > /dev/null 2>&1
			iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE > /dev/null 2>&1
			iptables -t nat -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu > /dev/null 2>&1
			echo_date 清除Mangle规则
		done
	fi
	sleep 1
	out_nu=`iptables -t mangle -L OUTPUT -v -n --line-numbers|grep "WIREGUARD"|awk '{print $1}'|head -1`
	[ -n "$out_nu" ] && iptables -t mangle -D OUTPUT $out_nu > /dev/null 2>&1
	iptables -t mangle -F WIREGUARD > /dev/null 2>&1 && iptables -t mangle -X WIREGUARD > /dev/null 2>&1
	iptables -t mangle -F WIREGUARD_GFW > /dev/null 2>&1 && iptables -t mangle -X WIREGUARD_GFW > /dev/null 2>&1
	iptables -t mangle -F WIREGUARD_CHN > /dev/null 2>&1 && iptables -t mangle -X WIREGUARD_CHN > /dev/null 2>&1
	iptables -t mangle -F WIREGUARD_GLO > /dev/null 2>&1 && iptables -t mangle -X WIREGUARD_GLO > /dev/null 2>&1
	
	#flush_ipset
	echo_date 先清空已存在的ipset名单，防止重复添加
	ipset -F white_list >/dev/null 2>&1 && ipset -X white_list >/dev/null 2>&1
	ipset -F black_list >/dev/null 2>&1 && ipset -X black_list >/dev/null 2>&1
	ipset -F gfwlist >/dev/null 2>&1 && ipset -X gfwlist >/dev/null 2>&1
	#remove_redundant_rule
	ip_rule_exist=`ip rule show | grep "fwmark 0x12e lookup wireguardtable" | grep -c wireguardtable`
	if [ ! -z "ip_rule_exist" ];then
		echo_date 清除重复的ip rule规则.
		until [ "$ip_rule_exist" = "0" ]
		do 
			#ip rule del fwmark 0x07 table 310
			ip rule del fwmark 0x12e table wireguardtable pref 791
			ip_rule_exist=`expr $ip_rule_exist - 1`
		done
	fi
	# remove_route_table
	echo_date 删除ip route规则.
	ip route del default dev wg0 table wireguardtable >/dev/null 2>&1
	[ -n "$wireguard_basic_serverip" ] && ip route del $wireguard_basic_serverip
}

detect_ss(){
	local SS_NU WIREGUARD_NU
	SS_NU=`iptables -nvL PREROUTING -t nat |sed 1,2d | sed -n '/SHADOWSOCKS/='` 2>/dev/null
	WIREGUARD_NU=`iptables -nvL PREROUTING -t nat |sed 1,2d | sed -n '/WIREGUARD/='` 2>/dev/null
	if [ -n "$SS_NU" ];then
		echo_date 检测到你开启了Shadowsocks！！！
		echo_date WireguardVPN代理不能和SS混用，请关闭SS后启用本插件！！
		echo_date 退出WireguardVPN启动...
		close_in_five
	elif [ -n "$WIREGUARD_NU" ];then
		echo_date 检测到你开启了WIREGUARD！！！
		echo_date WireguardVPN代理不能和WIREGUARD混用，请关闭WIREGUARD后启用本插件！！
		echo_date 退出WireguardVPN启动...
		close_in_five
	else
		echo_date WireguardVPN代理符合启动条件！~
	fi
}

load_nat(){
	echo_date "加载nat规则!"
	check_route
	creat_ipset
	add_white_black_ip
	apply_nat_rules
}


auto_start(){
	[ ! -f "/etc/hotplug.d/iface/98-wireguard" ] && {
		cat>/etc/hotplug.d/iface/98-wireguard<<-EOF
		#!/bin/sh

		[ "\$ACTION" = ifup ] || exit 0

		source /koolshare/scripts/base.sh
		eval \`dbus export wireguard_\`

		[ "\$wireguard_enable" == "1" ] && {
			/koolshare/scripts/wireguard_config.sh
			logger -t wireguard "Restart wireguard due to ifup of \$INTERFACE (\$DEVICE)"
		}
		EOF
	}
	# nat start
	echo_date 添加nat-start触发事件...
	uci -q batch <<-EOT
	  delete firewall.ks_wireguard
	  set firewall.ks_wireguard=include
	  set firewall.ks_wireguard.type=script
	  set firewall.ks_wireguard.path=/koolshare/scripts/wireguard_nat.sh
	  set firewall.ks_wireguard.family=any
	  set firewall.ks_wireguard.reload=1
	  commit firewall
	EOT
	# auto start
	[ ! -L "/etc/rc.d/S99wireguard.sh" ] && ln -sf $KSROOT/init.d/S99wireguard.sh /etc/rc.d/S99wireguard.sh
}

set_lock(){
	while [ -f "$LOCK_FILE" ]; do
		sleep 1
	done
	echo 1000 >$LOCK_FILE
}

unset_lock(){
	rm -rf "$LOCK_FILE"
}

close_in_five(){
	echo_date "插件将在5秒后自动关闭！！"
	sleep 1
	echo_date 5
	sleep 1
	echo_date 4
	sleep 1
	echo_date 3
	sleep 1
	echo_date 2
	sleep 1
	echo_date 1
	sleep 1
	echo_date 0
	dbus set wireguard_basic_enable="0"
	stop_wireguard >/dev/null
	echo_date "插件已关闭！！"
	echo_date ------------------------- wireguard 成功关闭 -------------------------
	echo XU6J03M6
	http_response "233"
	unset_lock
	exit
}

start_wireguard(){
	local KDF PRIVATEKEY IPADDRESS PUBLICKEY ENDPOINT LOCALIP MASKIP ALIVES ALIVECMD IFIP_VS VPN_GATEWAY
	check_opkg
	get_config_file
	echo_date 读取 wireguard 配置...
	PRIVATEKEY=`ReadINI $WIREGUARD_CONFIG Interface PrivateKey`
	IPADDRESS=`ReadINI $WIREGUARD_CONFIG Interface Address`
	PUBLICKEY=`ReadINI $WIREGUARD_CONFIG Peer PublicKey`
	ENDPOINT=`ReadINI $WIREGUARD_CONFIG Peer Endpoint`
	LOCALIP=`echo $IPADDRESS | cut -d "/" -f1`
	MASKIP=`netmask -c $IPADDRESS`
	VPNGATEWAY="$(echo $MASKIP| cut -d "/" -f1|cut -d "." -f1,2,3).1"
	SERVERIP=`echo $ENDPOINT|cut -d ":" -f1`
	[ "$wireguard_basic_keepalive" == "1" ] && {
		ALIVES=`ReadINI $WIREGUARD_CONFIG Peer PersistentKeepalive`
		[ -n "$ALIVES" ] && ALIVECMD=" persistent-keepalive $ALIVES"
	}
	echo_date 开启 wireguard 服务...
	ip link add wg0 type wireguard
	echo "$PRIVATEKEY=" >/tmp/wgkey
	#wg set wg0 private-key /tmp/wgkey
	wg set wg0 private-key /tmp/wgkey peer "$PUBLICKEY=" allowed-ips 0.0.0.0/0 endpoint $ENDPOINT$ALIVECMD
	if [ "$?" -eq 0 ] ; then
		echo_date 已成功设置 wireguard 服务器配置
		IFIP_VS=`echo $SERVERIP|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}|:"`
		if [ -n "$IFIP_VS" ];then
			echo_date "检测到你的服务器是：$SERVERIP"
		else
			echo_date "检测到你配置的服务器：$SERVERIP不是ip格式！"
			echo_date "尝试解析服务器的ip地址..."
			echo "server=/$SERVERIP/114.114.114.114#53" > /tmp/dnsmasq.d/wireguard_server.conf
			SERVERIP=`nslookup "$SERVERIP" 114.114.114.114 | sed '1,4d' | awk '{print $3}' | grep -v :|awk 'NR==1{print}'`
			if [ "$?" == "0" ]; then
				SERVERIP=`echo $SERVERIP|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}|:"`
			else
				echo_date 服务器域名解析失败！
				echo_date 尝试用resolveip方式解析...
				SERVERIP=`resolveip -4 -t 2 $SERVERIP|awk 'NR==1{print}'`
				if [ "$?" == "0" ];then
					SERVERIP=`echo $SERVERIP|grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}|:"`
				fi
			fi
		fi
		dbus set wireguard_basic_serverip="$SERVERIP"
		VPN_GATEWAY=`ifconfig $wireguard_basic_vpn|awk '/P-t-P:/{ print $3 }'|awk -F: '{print $2 }'`
		[ -n "$VPN_GATEWAY" ] || VPN_GATEWAY="$(ifconfig $wireguard_basic_vpn|awk '/inet addr:/{ print $2 }'|awk -F: '{print $2 }'|cut -d "." -f1,2,3).1"
		if [ -n "$VPN_GATEWAY" ]; then			
			ip route add $SERVERIP via $VPN_GATEWAY dev $wireguard_basic_vpn
			echo_date 设置VPN服务器：$SERVERIP 网关：$VPN_GATEWAY 出口：$wireguard_basic_vpn
			rm /tmp/wgkey
			echo_date 设置VPN接口IP：$IPADDRESS
			ip addr add dev wg0 $IPADDRESS
			ip link set dev wg0 up
		else
			echo_date 无法获取到WAN口网关，wireguard将会无法连通，请重新配置VPN出口！	
			close_in_five
		fi
	else
		echo_date 无法连接到 wireguard 服务器，请检查配置！
		rm /tmp/wgkey
		close_in_five
	fi
}

conf_upload(){
	local uploadfile conffile
	echo_date 开始搜索已上传的配置文件
	uploadfile=$(ls /tmp/upload|grep wireguardconfig) 
	if [ -n "$uploadfile" ]; then
		conffile=`basename $uploadfile .wireguardconfig`
		echo_date 已找到上传的配置文件 $conffile
		echo_date 确认配置文件
		mkdir -p /koolshare/wireguard/conf
		mv /tmp/upload/$uploadfile /koolshare/wireguard/conf/$conffile
		echo_date 配置文件已成功上传
		echo XU6J03M6
	else
		echo_date 未找到上传的配置文件，请检查！
		sleep 3
		echo XU6J03M6
	fi	
}

#====================================================================

restart_wireguard(){
	stop_wireguard
	detect_ss
	start_wireguard
	auto_start
	load_nat
	#start_smartdns
	create_dnsmasq_conf
	restart_dnsmasq
	echo_date ============================ WireGuard 启动完毕 ============================
	echo_date 根据你的网络情况，可能需要10-30秒完全连通服务器，请耐心等待！
}

stop_wireguard(){
	echo_date ============================================================================
	flush_nat
	rm -rf /etc/hotplug.d/iface/98-wireguard >/dev/null 2>&1
	restore_start_file
	killall smartdns >/dev/null 2>&1
	sed -i '/wireguard/d' /etc/crontabs/root >/dev/null 2>&1
	restore_dnsmasq_conf
	restart_dnsmasq
	ip link del wg0 >/dev/null 2>&1
	sleep 3
	echo_date ============================ WireGuard 成功关闭 ============================
}

# used by rc.d
case $1 in
start)
	set_lock
	if [ "$wireguard_basic_enable" == "1" ];then
		restart_wireguard
	else
		stop_wireguard
    fi
	unset_lock
	;;
stop)
	set_lock
	stop_wireguard
	unset_lock
	;;
sdns)
	check_smartdns
	;;
*)
	set_lock
	[ -z "$2" ] && restart_wireguard
	unset_lock
	;;
esac

# used by httpdb
case $2 in
1)
	if [ "$wireguard_basic_enable" == "1" ];then
		restart_wireguard > $LOG_FILE
	else
		stop_wireguard > $LOG_FILE
	fi
	echo XU6J03M6 >> $LOG_FILE
	http_response $1
	;;
2)
	# remove all wireguard config in skipd
	echo_date 尝试关闭 wireguard... > $LOG_FILE
	sh $KSROOT/scripts/wireguard_config.sh stop
	echo_date 开始清理 wireguard 配置... >> $LOG_FILE
	confs=`dbus list wireguard | cut -d "=" -f 1 | grep -v "version"`
	for conf in $confs
	do
		echo_date 移除$conf >> $LOG_FILE
		dbus remove $conf
	done
	echo_date 设置一些默认参数... >> $LOG_FILE
	dbus set wireguard_basic_enable="0"
	echo_date 完成！ >> $LOG_FILE
	http_response $1
	;;
3)
	#备份配置
	echo "" > $LOG_FILE
	mkdir -p $KSROOT/webs/files
	dbus list wireguard | grep -v "status" | grep -v "enable" | grep -v "version" | sed 's/=/=\"/' | sed 's/$/\"/g'|sed 's/^/dbus set /' | sed '1 i\\n' | sed '1 isource /koolshare/scripts/base.sh' |sed '1 i#!/bin/sh' > $KSROOT/webs/files/wireguard_conf_backup.sh
	http_response "$1"
	echo XU6J03M6 >> $LOG_FILE
	;;
4)
	#用备份的wireguard_conf_backup.sh 去恢复配置
	echo_date "开始恢复wireguard配置..." > $LOG_FILE
	file_nu=`ls /tmp/upload/wireguard_conf_backup | wc -l`
	i=20
	until [ -n "$file_nu" ]
	do
		i=$(($i-1))
		if [ "$i" -lt 1 ];then
			echo_date "错误：没有找到恢复文件!"
			echo XU6J03M6
			exit
		fi
		sleep 1
		file_nu=`ls /tmp/upload/wireguard_conf_backup | wc -l`
	done
	format=`cat /tmp/upload/wireguard_conf_backup.sh |grep dbus`
	if [ -n "format" ];then
		echo_date "检测到正确格式的配置文件！" >> $LOG_FILE
		cd /tmp/upload
		chmod +x wireguard_conf_backup.sh
		echo_date "恢复中..." >> $LOG_FILE
		sh wireguard_conf_backup.sh
		sleep 1
		rm -rf /tmp/upload/wireguard_conf_backup.sh
		echo_date "恢复完毕！" >> $LOG_FILE
	else
		echo_date "配置文件格式错误！" >> $LOG_FILE
	fi
	http_response "$1"
	echo XU6J03M6 >> $LOG_FILE
	;;
5)
	# 删除wireguard配置文件
	echo =================================删除配置文件==================================================== > $LOG_FILE
	if [ "$wireguard_basic_conf" == "0" ];then
		echo_date "自定义配置无需删除" >> $LOG_FILE
	else
		rm /koolshare/wireguard/conf/$wireguard_basic_conf
		if [ "$?" -eq 0 ] ; then
			echo_date "配置文件删除成功" >> $LOG_FILE
		else
			echo_date "配置文件删除失败，请检查文件是否存在！" >> $LOG_FILE
		fi
	fi
	http_response "$1"
	;;
9)
	# 上传配置
	conf_upload > $LOG_FILE
	http_response "$1"
	;;
esac
