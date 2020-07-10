# koolshare-plugin-wireguard
对koolshare x86的wireguard插件进行改进

# 原版插件存在的问题
1. 部分网站如```netflix.com```、```yahoo.tw```由于mtu问题无法正常访问。
2. 程序逻辑上存在死锁造成系统重启后程序无法启动。
3. gfwlist无定时更新。
4. 国内ip库无定时更新。

# 改进
1. 通过增加iptables规则```iptables -t nat -I POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu```修复mtu无法正常协商的问题。
2. 解决死锁问题，路由重启后wireguard自动生效。
3. 自动定时更新gfwlist。<sub>[todo]</sub>
4. 通过apnic.net自动定时更新国内ip库。<sub>[todo]</sub>
