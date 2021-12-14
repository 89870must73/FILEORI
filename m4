#!/bin/bash
#Created by Korn

# initializing var
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
sleep 1

#Essential needs
apt-get update; apt-get -y upgrade;
apt-get -y install nginx php5-fpm php5-cli
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections

apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter libnet-ssleay-perl

apt-get -y install build-essential
apt-get -y install libio-pty-perl libauthen-pam-perl apt-show-versions
apt-file update
vnstat -u -i eth0
service vnstat restart

#Screen Design
cd
wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/blackestsaint/Korn/master/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

#iptables 
apt-get update
sudo apt update 
sudo apt-get install iptables-persistent


#ADM-Free Framework
apt-get update; apt-get upgrade -y; wget https://raw.githubusercontent.com/blackestsaint/Korn/master/instala.sh; chmod +x ./instala.sh; ./instala.sh

#Time Zone
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime
sleep 1


#Auto Reboot Script
cd
wget -O /usr/local/bin/auto-reboot "https://raw.githubusercontent.com/blackestsaint/Korn/master/auto-reboot"
chmod +x /usr/local/bin/auto-reboot
sleep 1

# Fix 1
wget -O /usr/local/bin/fix "https://raw.githubusercontent.com/blackestsaint/Korn/master/fix"
chmod +x /usr/local/bin/fix
sleep 1

# Fix 2
wget -O /usr/local/bin/fix2 "https://raw.githubusercontent.com/blackestsaint/Korn/master/fix2"
chmod +x /usr/local/bin/fix2
sleep 1

#OHP Over-HTTP-Puncher
cd
wget https://github.com/lfasmpao/open-http-puncher/releases/download/0.1/ohpserver-linux32.zip 
unzip ohpserver-linux32.zip 
chmod +x ohpserver
sleep 1

#OHP Set-UP +badvpn
cd
cat > /etc/adm-lite/ohp.sh <<END
#!/bin/bash
sleep 5
screen -dm bash -c "./ohpserver -port 8899 -proxy $MYIP:61790 -tunnel $MYIP:22"
screen -dm bash -c "./ohpserver -port 8898 -proxy $MYIP:3993 -tunnel $MYIP:333"
screen -dm bash -c "./ohpserver -port 7799 -proxy $MYIP:7190 -tunnel $MYIP:22"
screen -dm bash -c "./ohpserver -port 7798 -proxy $MYIP:2256 -tunnel $MYIP:333"
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
END
sleep 1
chmod +x /etc/adm-lite/ohp.sh

#lander-reboot
cd
cat > /usr/local/bin/lander-reboot <<-END
#!/bin/bash
sudo reboot
END
chmod +x /usr/local/bin/lander-reboot

#alias lolcat
cd
cat > /usr/local/bin/aliasme <<-END
#!/bin/bash
source ~/.bashrc
END
chmod +x /usr/local/bin/aliasme

#auto-delete
cd
cat > /usr/local/bin/auto-delete <<-END
#!/bin/bash
/etc/adm-lite/usercodes 6
END
chmod +x /usr/local/bin/auto-delete


#caches
cd
cat > /etc/adm-lite/caches.sh <<-END
#!/bin/bash
echo 3 > /proc/sys/vm/drop_caches
sysctl -w vm.drop_caches=3 > /dev/null 2>&1
rm -rf /tmp/*
END
sleep 1
chmod +x /etc/adm-lite/caches.sh


#ADM Limiter On after reboot
cd
wget -O /etc/adm-lite/lim.sh "https://raw.githubusercontent.com/blackestsaint/Korn/master/lim.sh"
chmod +x /etc/adm-lite/lim.sh
sleep 1

#timer.ni.gwapong.lander
cd
cat > /etc/adm-lite/timer.sh <<-END
#!/bin/bash
#Created by Korn
while true ; do service privoxy force-reload & sleep 57; done 
END
sleep 1
chmod +x /etc/adm-lite/timer.sh

#Start Up Command v2 (crontab)
cd
echo "@reboot root /etc/adm-lite/lim.sh 
@reboot root /etc/adm-lite/ohp.sh
@reboot root /etc/adm-lite/caches.sh
@reboot root /etc/adm-lite/timer.sh
@reboot root /usr/local/bin/auto-delete
10 4 * * * root /usr/local/bin/lander-reboot
@reboot root /usr/local/bin/aliasme
@reboot root /bin/sleep 5 && sudo iptables-restore < /etc/iptables/rules.v4" >> /etc/crontab

#add protection
cd
wget -O /usr/local/bin/protection.sh "https://raw.githubusercontent.com/blackestsaint/Korn/master/protection.sh"
chmod +x /usr/local/bin/protection.sh
protection.sh
sleep 1

#alias
cd
wget -O /root/.bashrc "https://raw.githubusercontent.com/blackestsaint/Korn/master/.bashrc"


#Translate to English 1
cd
wget -O /etc/adm-lite/idioma "https://raw.githubusercontent.com/blackestsaint/Korn/master/idioma"
chmod +x /etc/adm-lite/idioma
 sleep 1

#Translate to English 2
cd
wget -O /etc/adm-lite/idioma_geral "https://raw.githubusercontent.com/blackestsaint/Korn/master/idioma_geral"
chmod +x /etc/adm-lite/idioma_geral
sleep 1
cd

# modified installation menu_inst
cd
wget -O /etc/adm-lite/menu_inst "https://raw.githubusercontent.com/blackestsaint/Korn/master/menu_inst"
chmod +x /etc/adm-lite/menu_inst
sleep 1

# modified menu
cd
wget -O /etc/adm-lite/menu "https://raw.githubusercontent.com/blackestsaint/Korn/master/menu"
chmod +x /etc/adm-lite/lmenu
sleep 1

# modified menu text
cd
wget -O /etc/adm-lite/menu-txt "https://raw.githubusercontent.com/blackestsaint/Korn/master/menu-txt"
chmod +x /etc/adm-lite/menu-txt
sleep 1

# modified cabecalho
cd
wget -O /etc/adm-lite/cabecalho "https://raw.githubusercontent.com/blackestsaint/Korn/master/cabecalho"
chmod +x /etc/adm-lite/cabecalho
sleep 1

# modified user
cd
wget -O /etc/adm-lite/user "https://raw.githubusercontent.com/blackestsaint/Korn/master/user"
chmod +x /etc/adm-lite/user
sleep 1

# modified user-txt
cd
wget -O /etc/adm-lite/user-txt "https://raw.githubusercontent.com/blackestsaint/Korn/master/user-txt"
chmod +x /etc/adm-lite/user-txt
sleep 1


#privoxy
apt-get update -y && apt-get upgrade -y && apt autoclean -y && apt autoremove
apt-get install privoxy
cat > /etc/privoxy/config <<-END
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:7190
listen-address 0.0.0.0:2256
toggle  1
enable-remote-toggle  0
enable-remote-http-toggle  0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries  1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 $MYIP
END

#loli 
cd
sleep 1
apt-get install ruby
wget https://github.com/busyloop/lolcat/archive/master.zip
unzip master.zip
cd lolcat-master/bin
gem install lolcat
cd
sleep 1

#install squid
apt-get install -y wget && wget https://raw.githubusercontent.com/blackestsaint/Korn/master/squideb.sh && chmod +x squideb.sh && ./squideb.sh


# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300


# install dropbear
cd
apt-get install dropbear
sleep 1


#TCP SPEED ON
cd
echo "net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_slow_start_after_idle = 0" >> /etc/sysctl.conf
sleep 1

# setting vnstat
vnstat -u -i eth0
service vnstat restart


#m4 updates """"%%&&-++&%&-+-&&-+++-&--+&&-+-&

#openvpn


#fail2ban #m3
cd
wget -O /usr/local/bin/fai2ban "https://raw.githubusercontent.com/blackestsaint/Korn/master/fai2ban"
chmod +x /usr/local/bin/fai2ban
fai2ban
read -p " Fail2ban successfully install"
cd



# Setting USW
apt-get install ufw
ufw allow ssh
ufw allow 1194/tcp
ufw allow 2500/udp
sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
cd /etc/ufw/
wget "https://raw.githubusercontent.com/blackestsaint/Korn/master/before.rules"
cd
ufw enable
ufw status
ufw disable

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# Install Stunnel #m4
apt-get -y install stunnel4
wget -O /etc/stunnel/stunnel.pem "https://raw.githubusercontent.com/blackestsaint/Korn/master/stunnel.pem"
wget -O /etc/stunnel/stunnel.conf "https://raw.githubusercontent.com/blackestsaint/Korn/master/stunnel.conf"
read -p " SSL successfully instal"
cd


# Install DDOS Deflate #m4
cd
apt-get -y install dnsutils dsniff
wget "https://github.com/blackestsaint/Korn/raw/master/ddos-deflate-master.zip"
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
cd
rm -rf ddos-deflate-master.zip
read -p " DDOS deflate successfully install"
cd


#antiddos #m4
wget -q -O /usr/local/ddos/ddos.conf https://raw.githubusercontent.com/CarlosPBric005/ADM-ULTIMATE/master/DDOS/ddos.conf -o /dev/null
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE -o /dev/null
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list -o /dev/null
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh -o /dev/null
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
sleep 2s
read -p " antiddos successfully install"


# XML Parser #m4
cd
apt-get -y --force-yes -f install libxml-parser-perl
read -p " parser successfully install"






#banner
sleep 2
cd
cat > /etc/issue.net <<END
<br><font>
<br><font>
<br><font color='green'> <b>░▒▓█ gωαρσиg ℓαи∂єя νρи █▓▒░</b> </br></font>
<br><font>
<br><font color='#32CD32'>: : : ★  TEST SERVER </br></font>
<br><font color='#32CD32'>: : : ★ NOT RECOMMENDED FOR GAMING</br></font>
<br><font color='#FDD017'>: : : ★ EXCLUSIVE FOR ADMIN ONLY</br></font>
<br><font>
<br><font color='#32CD32'>: : : ★ STRICTLY NO ACCOUNT SHARING</br></font>
<br><font color='#32CD32'>: : : ★ STRICTLY NO MULTI-LOGIN</br></font>
<br><font color='#32CD32'>: : : ★ STRICTLY NO TORRENT</br></font>
<br><font>
<br><font color='#FF00FF'>░▒▓█ VIOLATORS WILL BE BAN!!!</br></font>
<br><font>
<br><font>
END


# fix bugs
cd
sleep 1
fix2


clear
echo " "
echo "Installation has been completed!!" | lolcat
echo " "
echo ""
echo "--------------------------- Configuration Setup Server -------------------------" | lolcat
echo "                         Credits to: ADM-MANAGER                          " | lolcat
echo "                        Modified by Gwapong Lander                      " | lolcat
echo "--------------------------------------------------------------------------------" | lolcat

echo ""
echo "Server Information: " | tee -a log-install.txt | lolcat
echo "   • Timezone: Asia/Manila [GMT +8] " tee -a log-install.txt | lolcat
echo "   • Server Auto-Reboot: [ON] Every 04:10 am" | tee -a log-install.txt | lolcat
echo "   • Auto Delete Expire User Account: [ON] Every 04:10 am" | tee -a log-install.txt | lolcat
echo "   • IPv6 : [OFF]" | tee -a log-install.txt | lolcat
echo "   • Webmin : [ON]" | tee -a log-install.txt | lolcat
echo "   • TCP tweak for Speed : [ON]" | tee -a log-install.txt | lolcat
echo "   • Squid Cache : [ON]" | tee -a log-install.txt | lolcat
echo "   • Multi-login Auto Disconnect : [ON] " | tee -a log-install.txt | lolcat
echo "   • Server Auto Clear Cache : [ON] | Every restart" | tee -a log-install.txt | lolcat

echo ""
echo "Application & Port Information:" | tee -a log-install.txt | lolcat
echo "   • OpenVPN     : [OFF] " | tee -a log-install.txt | lolcat
echo "   • Dropbear    : [ON] :  9933 | 9870 |2110" | tee -a log-install.txt | lolcat
echo "   • Squid Proxy : [ON] : 61790 | 8000 |3993 | limit to IP Server" | tee -a log-install.txt | lolcat
echo "   • Privoxy         : [ON] :  7190 | 2256 | limit to IP Server" | tee -a log-install.txt | lolcat
echo "   • OHP             : [ON] : 8899 | 8898 | Auto Reconnect [OFF] " | tee -a log-install.txt | lolcat
echo "   • OHP             : [ON]: 7799 | 7798 | Auto Reconnect [ON]" | tee -a log-install.txt | lolcat
echo "   • BADVPN       : [ON] : 7300 " | tee -a log-install.txt | lolcat
echo "   • Additional SSHD Port : [ON] :  333" | tee -a log-install.txt | lolcat

echo ""
echo "Notes:" | tee -a log-install.txt | lolcat
echo "  ★ Fix Dropbear eating SSHD Port" | tee -a log-install.txt | lolcat
echo "  ★ Torrent Protection [ algoritem based on common torrent keywords. additional newest torrent port] " | tee -a log-install.txt | lolcat
echo "  ★ Port Scanner Simple Protection  " | tee -a log-install.txt | lolcat
echo "  ★ Brute Force Attack Simple Protection  " | tee -a log-install.txt | lolcat
echo "  ★ Optimize Squid Connection" | tee -a log-install.txt | lolcat
echo "  ★ Update Squid Version to Squid 4.9-2 " | tee -a log-install.txt | lolcat
echo "   ★ To display list of commands: " menu "" | tee -a log-install.txt | lolcat
echo "   ★ Privoxy auto reconnect every 57 seconds. " | tee -a log-install.txt | lolcat
echo "   ★ For Globe No Load, use OHP Port. " | tee -a log-install.txt | lolcat
echo "   ★ Payload for Globe using OHP? same payload with SocksIP." | tee -a log-install.txt | lolcat
echo "   ★ This is modified ADM-MANAGER." | tee -a log-install.txt | lolcat

echo ""
echo "   ★ Other concern and questions of these auto-scripts?" | tee -a log-install.txt | lolcat
echo "      Direct Messege : www.facebook.com/kornips" | tee -a log-install.txt | lolcat
echo ""
echo ""
read -p " After you read installation log. Press Enter to "Restart" "
sudo reboot
