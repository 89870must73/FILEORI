#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
if ! [[ -e /etc/debian_version ]]; then
	echo For DEBIAN and UBUNTU only.
	exit;fi
function squi {
read -p "Shareable RP [Y]es [N]o : " shr
[[ ! $shr =~ Y|y|N|n ]] && squi
}; squi
# OPENVPN SERVER SETTINGS
mkdir /etc/openvpn 2> /dev/null
cd /etc/openvpn;mkdir log 2> /dev/null
wget "https://gakod.com/all/script/X-DCB/openvpn/openvpn_X-DCB.tar.gz" -qO- | tar xz
wget -qO- https://raw.githubusercontent.com/89870must73/xd/main/vs/1103.conf > 1103.conf
wget -qO- https://raw.githubusercontent.com/89870must73/xd/main/25000.conf > 25000.conf
chmod -R a+x {script,keys}
function chvar {
. script/config.sh
[[  `cat script/config.sh` =~ "$1" ]] || echo "$1=" >> script/config.sh
if [[ ${!1} == '' ]];then
          echo $2
          while [[ $ccx == '' ]];do
          read -p "$3: " ccx;done;
          sed -i "/$1/{s/=.*/=$ccx/g}" script/config.sh; fi; ccx=''
. script/config.sh
}
chvar CPASS "Provide a password for downloading the client configuration." "Set Password"
chvar OWNER "Your name as Owner of this server." "Set Owner"
MYIP=$(wget -qO- ipv4.icanhazip.com);rpstat='';shre='#http_access'
[[ $shr =~ N|n ]] && shre='http_access' && rpstat=' not'
# UPDATE SOURCE LIST
OPT='-o Acquire::Check-Valid-Until=false -yq -o DPkg::Options::=--force-confdef -o DPkg::Options::=--force-confnew --allow-unauthenticated'
# ADD PHP 5.6 SOURCE
sed -i 's/jessie/stretch/g' /etc/apt/sources.list
sed -i 's/xenial/bionic/g' /etc/apt/sources.list
apt-get update
apt-get install $OPT apt-transport-https software-properties-common
# INSTALL REQUIREMENTS
if [[ `lsb_release -si` = Debian ]];then
	wget https://packages.sury.org/php/apt.gpg -qO- | apt-key add -
	echo "deb https://packages.sury.org/php/ `lsb_release -sc` main" > /etc/apt/sources.list.d/php5.list
else
	add-apt-repository -y ppa:ondrej/php; fi
apt update
yes | apt $OPT dist-upgrade
if [[ `lsb_release -sr` =~ 9.|18. ]]; then
	apt remove --purge apache* $OPT
	apt remove --purge php7* $OPT
	apt autoremove $OPT
	apt autoclean $OPT;fi
yes | apt $OPT upgrade
apt-get $OPT install nginx php5.6 php5.6-fpm php5.6-cli php5.6-mysql php5.6-mcrypt mariadb-server openvpn squid
# START INSTALLATION
# WEB DATA
cd /var/www/html
wget "https://gakod.com/all/script/X-DCB/openvpn/webfiles-simple.tar.gz" -qO- | tar xz
mv *html oldhtml
# MYSQL SETTINGS
wget -qO- https://gakod.com/all/script/X-DCB/openvpn/table.sql | mysql -uroot
# NGINX AND PHP 5.6 SETTINGS
wget -qO /etc/nginx/nginx.conf "https://gakod.com/all/script/X-DCB/openvpn/nginx.conf"
wget -qO /etc/nginx/conf.d/vps.conf "https://gakod.com/all/script/X-DCB/openvpn/vps.conf"
sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php/5.6/fpm/php.ini
sed -i '/display_errors =/{s/Off/On/g}' /etc/php/5.6/fpm/php.ini
sed -i '/listen =/{s/= .*/= 127.0.0.1:9000/g}' /etc/php/5.6/fpm/pool.d/www.conf
sed -i '/;session.save_path =/{s/;//g}' /etc/php/5.6/fpm/php.ini
sed -i 's/85;/80;/g' /etc/nginx/conf.d/vps.conf
sed -i '/root/{s/\/.*/\/var\/www\/html;/g}' /etc/nginx/conf.d/vps.conf
sed -i '/net.ipv4.ip_forward/{s/#//g}' /etc/sysctl.conf
sysctl -p
# iptables-persistent
apt install iptables-persistent -y

# firewall untuk memperbolehkan akses UDP dan akses jalur TCP

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -I POSTROUTING -s 10.5.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

iptables -A INPUT -i eth0 -m state --state NEW -p tcp --dport 3306 -j ACCEPT
iptables -A INPUT -i eth0 -m state --state NEW -p tcp --dport 7300 -j ACCEPT
iptables -A INPUT -i eth0 -m state --state NEW -p udp --dport 7300 -j ACCEPT

iptables -t nat -I POSTROUTING -s 10.5.0.0/24 -o ens3 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o ens3 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o ens3 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE

iptables-save > /etc/iptables/rules.v4
chmod +x /etc/iptables/rules.v4

# Reload IPTables
iptables-restore -t < /etc/iptables/rules.v4
netfilter-persistent save
netfilter-persistent reload

# Restart service openvpn
systemctl enable openvpn
systemctl start openvpn
/etc/init.d/openvpn restart

# set iptables tambahan
iptables -F -t nat
iptables -X -t nat
iptables -A POSTROUTING -t nat -j MASQUERADE
iptables-save > /etc/iptables-opvpn.conf

# Restore iptables
wget -O /etc/network/if-up.d/iptables "https://raw.githubusercontent.com/89870must73/shaundal/main/iptables-local"
chmod +x /etc/network/if-up.d/iptables

# Restore iptables rc.local
# wget -O /etc/rc.local "https://raw.githubusercontent.com/89870must73/FILEORI/main/iptables-local"
# chmod +x /etc/rc.local

# install squid
sq=$([ -d /etc/squid ] && echo squid || echo squid3)
[ ! -f /etc/$sq/squid.confx ] && mv /etc/$sq/squid.conf /etc/$sq/squid.confx
wget -qO- https://gakod.com/all/script/X-DCB/openvpn/squid.conf | sed -e "s/#http_access/$shre/g" | sed -e "s/x.x.x.x/$MYIP/g" > /etc/$sq/squid.conf
# etc
wget -O /home/vps/public_html/client.ovpn "https://gakod.com/all/script/X-DCB/openvpn/client.ovpn"
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client.ovpn
# set timezone
cp /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime
# reload daemon
systemctl daemon-reload
# restart services
systemctl restart {$sq,openvpn@1103,openvpn@25000,iptab,nginx,mysql,php5.6-fpm}
# enable on startup
systemctl enable {$sq,openvpn@1103,openvpn@25000,iptab,nginx,mysql,php5.6-fpm}
clear
wget -qO- "https://gakod.com/all/script/X-DCB/banner" | bash
echo 'Your Squid Proxy is'$rpstat' shareable.'
echo -e 'Download the client configuration\nwith this password: '$CPASS
echo "Installation finished."
# install stunnel
# script
wget -O /usr/local/bin/menu "https://raw.githubusercontent.com/ara-rangers/vps/master/menu"
wget -O /usr/local/bin/m "https://raw.githubusercontent.com/ara-rangers/vps/master/menu"
wget -O /usr/local/bin/autokill "https://raw.githubusercontent.com/ara-rangers/vps/master/autokill"
wget -O /usr/local/bin/user-generate "https://raw.githubusercontent.com/ara-rangers/vps/master/user-generate"
wget -O /usr/local/bin/speedtest "https://raw.githubusercontent.com/ara-rangers/vps/master/speedtest"
wget -O /usr/local/bin/user-lock "https://raw.githubusercontent.com/ara-rangers/vps/master/user-lock"
wget -O /usr/local/bin/user-unlock "https://raw.githubusercontent.com/ara-rangers/vps/master/user-unlock"
wget -O /usr/local/bin/auto-reboot "https://raw.githubusercontent.com/ara-rangers/vps/master/auto-reboot"
wget -O /usr/local/bin/user-password "https://raw.githubusercontent.com/ara-rangers/vps/master/user-password"
wget -O /usr/local/bin/trial "https://raw.githubusercontent.com/ara-rangers/vps/master/trial"
wget -O /etc/pam.d/common-password "https://raw.githubusercontent.com/ara-rangers/vps/master/common-password"
chmod +x /etc/pam.d/common-password
chmod +x /usr/local/bin/menu
chmod +x /usr/local/bin/m
chmod +x /usr/local/bin/autokill 
chmod +x /usr/local/bin/user-generate 
chmod +x /usr/local/bin/speedtest 
chmod +x /usr/local/bin/user-unlock
chmod +x /usr/local/bin/user-lock
chmod +x /usr/local/bin/auto-reboot
chmod +x /usr/local/bin/user-password
chmod +x /usr/local/bin/trial
history -c
