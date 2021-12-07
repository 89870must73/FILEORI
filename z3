#!/bin/bash
# O C S P A N E L ™
MYIP=$(wget -qO- ipv4.icanhazip.com);
OCSPANEL="https://api-connect.ml/20_script";
MYIP2="s/xxxxxxxxx/$MYIP/g";
clear
cd
apt-get --purge remove samba* -y
apt-get --purge remove apache2* -y
apt-get --purge remove sendmail* -y
apt-get --purge remove bind9* -y
apt-get update
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "BASH SCRIPT"
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "SORRY NO USER ROOT"
	exit 2
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "TUN NO SUPPORT."
	exit 3
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS NO SUPPORT."
	exit 4
fi
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo " "
	exit 5
fi

newclient () {
	cp /etc/openvpn/client.ovpn ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -4qO- "http://whatismyip.akamai.com/")
fi

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
		clear
		echo -e "\033[38;5;255m\033[48;5;234m\033[1m   L O W C L A S S - V P N  \033[0m\n"
		echo "   O P E N V P N > O P T I O N S"
		echo ""
		echo "   1) CREATE CONFIG VPN "
		echo "   2) REMOVE OPENVPN "
		echo "   3) EXIT "
		echo ""
		read -p "   S E L E C T  [ 1 - 3 ] : " option
		case $option in
			1) 
			echo ""
			cp /etc/openvpn/client.ovpn /home/ocspanel/public_html/
			echo ""
			echo ""
			echo -e "\033[38;5;255m\033[48;5;234m\033[1m   C O N F I G > http://$MYIP/client.ovpn\033[0m\n"
			echo "===================================== "
			echo ""
			echo ""
			exit
			;;
			2) 
			echo ""
			REMOVE=y
			if [[ "$REMOVE" = 'y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 11)
				if pgrep firewalld; then
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
				fi
				if iptables -L -n | grep -qE 'REJECT|DROP|ACCEPT'; then
					iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
					iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
					iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
					sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
				fi
				iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
				sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
							semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
						fi
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn openvpn-blacklist
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				clear
				echo ""
				echo ""
				echo ""
				echo "       O P E N V P N > R E M O V E > S U C C E S S !!!!"
				echo ""
				sleep 3
				echo "     ..."
				sleep 2
				echo "     .."
				sleep 1
				echo "     ."
				cd /root
				bash script.sh
			else
				echo ""
				echo "   C A N C E L > R E M O V E !"
				echo ""
			fi
			exit
			;;
			3) exit;;
		esac
	done
else
	clear
	echo ""
	echo "   Y O U > I P > A D D R E S S E S "
	echo ""
	echo ""
	read -p "    C O N F I R M > I P " -e -i $IP IP
	echo ""
	PROTOCOL=2
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo ""
	PORT=1194
	echo ""
	DNS=1
	echo ""
	CLIENT=client
	clear
	echo ""
	echo ""
echo -e "                  \033[38;5;255m\033[48;5;234m\033[1m > O C S P A N E L - V P N ™ <   \033[0m"
echo -e "              \033[1;38;48m ======================================= \033[0m"
echo ""
echo -e "                      \033[38;5;255m\033[48;5;234m\033[1m > O P E N - V P N <    \033[0m"
echo ""
echo -e "                 \033[38;5;255m\033[48;5;234m\033[1m > P O R T < T C P > 1 1 9 4 <     \033[0m"
echo ""
echo -e "              \033[1;38;48m ======================================= \033[0m"
echo ""
read -n1 -r -p "                     > E N T E R - รีบกดให้ไว <     "
echo ""
sleep 2
clear
echo ""
echo "           เดี๋ยว !! "
echo ""
sleep 2
clear
echo ""
echo "           ก่อน !! "
echo ""
sleep 2
clear
echo ""
echo "           รอแปป !! "
echo ""
sleep 2
clear
echo ""
echo "        > ใจเยด ๆ กำลัง ติดตั้ง "
echo ""
sleep 3
echo "          ..."
sleep 2
echo "          .."
sleep 1
clear
echo "          มันขึ้นไรมาก็ตอบ Y เยดดดนะ !!!"
sleep 3
clear
sleep 5
	if [[ "$OS" = 'debian' ]]; then
		apt-get upgrade
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		yum install epel-release -y
		yum install openvpn iptables openssl wget ca-certificates -y
	fi
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	apt-get install tar gzip
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 393216
rcvbuf 393216
push sndbuf 393216
push rcvbuf 393216
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	case $DNS in
		1) 
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2) 
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		4) 
		echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/server.conf
		;;
		5) 
		echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/server.conf
		;;
		6) 
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
		;;
		7)
		echo 'push "dhcp-option DNS 189.38.95.95"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 216.146.36.36"' >> /etc/openvpn/server.conf
	esac
	echo "keepalive 10 20
float
cipher AES-256-CBC
comp-lzo yes
user nobody
group $GROUPNAME
persist-key
persist-tun
status server-vpn.log
verb 3
crl-verify crl.pem
client-to-client
client-cert-not-required
username-as-common-name
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login" >> /etc/openvpn/server.conf
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
		echo '#!/bin/sh -e
exit 0' > $RCLOCAL
	fi
	chmod +x $RCLOCAL
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
	sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
	if pgrep firewalld; then
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
	fi
	if iptables -L -n | grep -qE 'REJECT|DROP'; then
		iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
          iptables -F
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
	fi
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
			fi
		fi
	fi
	if [[ "$OS" = 'debian' ]]; then
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	EXTERNALIP=$(wget -4qO- "http://whatismyip.akamai.com/")
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		read -p "External IP: " -e USEREXTERNALIP
		echo ""
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	echo "client
dev tun
proto $PROTOCOL
sndbuf 393216
rcvbuf 393216
<connection>
remote OCSPANEL-INFO 9999 udp
</connection>
http-proxy-retry
http-proxy $IP 8080
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
comp-lzo yes
setenv opt block-outside-dns
key-direction 1
verb 3
auth-user-pass
keepalive 10 20
<connection>
remote $IP:$PORT@@cv.truevisions.tv.cv.line.naver.jp
</connection>
float
<ca>
-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIJAJYzZuOdoFSHMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCENoYW5nZU1lMB4XDTE4MDIwNDA1NDkyNloXDTI4MDIwMjA1NDkyNlowEzER
MA8GA1UEAwwIQ2hhbmdlTWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDDcCiL7pifpjGrV/ihoE9tXX8XUWe9z7K6hIlU5llExhWrVOy3DJhT66VnfhSI
yWVwMvY4wdvmczWvqVvG8v4EFgRTT1tE/E5pdcbZINtZF7/0H+BLIzVbj6zFk2uL
wAtb2tUchbJiLJjr214Y6q/c3ypwq9jSym5n2xnn8OdnYVZAJDpTabPY7TZr0Haz
QCYtzQFhpY+sNu23ZP1PxJ9u5NBS3n3qM5EkHbO7ev8IFNJ95fPbpt0+ILwqdYv2
KiIwshbJm55N6rBxKWJDOV1O6qWn7BDg7dyQwCuXZTVDpHlpYtiUYVs+yRnRsz4v
5qSzmU0aA75aI/O4gdOrnU1tAgMBAAGjgYEwfzAdBgNVHQ4EFgQUVRlXKQlqFJ4u
AigK1zFNunIPCKowQwYDVR0jBDwwOoAUVRlXKQlqFJ4uAigK1zFNunIPCKqhF6QV
MBMxETAPBgNVBAMMCENoYW5nZU1lggkAljNm452gVIcwDAYDVR0TBAUwAwEB/zAL
BgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAAXfKKoOFFzSAyUB0a+Zupll
AJtxCAmdZzlNoAMVPVSO4xf1JzgIyACBb9OPxs7byj30kCB6t8vABQpBYTuxF9Vw
NBECk/3eh826OihVQVpA3Iv5ngL3DhJcaSDj0M6bGE7NbxRtuMKolxOCjv9o3Ot6
BEQdTEPHh9PkBJ7nj55l/VmSZFMI9/7TiJwHHrfGGKfWAXjaA5gjbtHBf6zVyJSn
BU2EuM1nil0Oz9km/2RhBXApsSLvuYokqPBYl0Od8aDVJFA6oKZU5xYmMuvEAxvh
WV2gzhjxcReV4jNVPURvaXhjSzX6Vac2pTwi7zYZvpMUFWH17PGavDw6xHp/z9Y=
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ChangeMe
        Validity
            Not Before: Feb  4 05:52:10 2018 GMT
            Not After : Feb  2 05:52:10 2028 GMT
        Subject: CN=client
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c1:23:4e:9e:04:e7:29:88:4e:e1:38:69:d8:83:
                    03:28:12:79:a8:65:e4:2d:98:eb:62:e2:96:16:02:
                    6a:7f:95:41:f8:4a:97:e3:cb:83:eb:e4:45:39:ce:
                    c0:8b:96:56:9c:b1:5c:45:0a:05:c7:14:2e:86:48:
                    0f:33:4a:a4:9c:05:8c:3b:5a:96:76:6c:c6:71:00:
                    26:b7:a3:03:69:09:18:f6:88:0f:06:a5:1a:a3:ec:
                    50:f2:d6:5f:63:3c:bf:90:47:d1:74:c2:00:78:51:
                    6d:1c:d0:0b:94:df:78:3d:cb:e1:01:23:03:96:cc:
                    d0:1e:bb:53:c1:33:bf:7d:0d:aa:2c:90:20:cf:47:
                    8c:78:fd:8c:da:94:db:96:6c:28:07:03:6c:26:a4:
                    bd:df:4c:da:c0:8d:3b:d8:04:61:2e:a0:61:f1:d4:
                    30:90:04:fb:0d:99:00:6a:94:18:c4:71:11:d1:98:
                    4d:bf:21:a8:fe:7d:c0:36:d5:1e:b0:41:bc:fd:1d:
                    ff:a7:cd:37:54:6a:e8:89:11:31:94:07:f9:a7:4f:
                    4b:f6:cf:a2:0f:28:53:88:cb:df:03:4b:01:4b:a5:
                    09:17:3e:f6:30:d3:89:0a:ec:a3:82:c4:2c:9c:47:
                    a7:5c:32:a8:e0:14:d0:21:ab:0d:91:b7:55:74:d3:
                    ac:a3
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                20:AD:12:F2:89:04:56:14:06:6E:C1:6C:A7:31:05:12:27:90:B4:B2
            X509v3 Authority Key Identifier: 
                keyid:55:19:57:29:09:6A:14:9E:2E:02:28:0A:D7:31:4D:BA:72:0F:08:AA
                DirName:/CN=ChangeMe
                serial:96:33:66:E3:9D:A0:54:87

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         bb:7c:15:67:0b:1a:98:c1:40:cd:2b:90:64:11:64:7b:c4:03:
         05:c1:80:36:bd:e1:80:f7:3b:fb:ef:5b:fa:dc:ca:65:e7:78:
         f1:f7:1c:30:5d:48:30:ae:11:27:2b:13:ab:6f:a2:88:9b:18:
         1b:de:ad:89:9f:18:45:32:13:f9:d1:85:78:10:38:60:3a:64:
         b5:ed:a3:15:c1:b8:de:e5:1e:b5:d4:41:b9:d8:1e:91:5f:5f:
         11:da:14:f5:0a:d6:39:92:61:28:c3:87:6e:f1:e4:5e:c1:3c:
         3f:bb:af:e4:9e:b3:2c:15:93:ab:d0:5b:d1:20:c5:46:73:63:
         34:7d:ae:6d:e6:12:ce:d3:f3:50:b9:7f:52:a1:cf:ea:b0:99:
         9d:8f:a1:a6:ac:16:57:49:14:da:ae:4e:13:2a:a3:9e:f3:73:
         0b:eb:74:e2:7d:0e:a9:42:1c:0d:5b:ec:92:b0:02:74:b4:e8:
         04:63:09:1e:4c:fd:3c:15:44:b5:47:9a:3b:1e:dc:7f:d2:a8:
         a0:2e:a3:0a:ae:73:b0:52:bb:66:83:4c:14:83:ed:6c:ca:8f:
         b2:c8:78:5a:c6:81:f6:18:72:bd:7d:da:2c:5f:89:a7:02:22:
         2d:7a:ed:06:32:c4:63:57:19:3f:e2:e8:e6:34:97:fc:90:60:
         65:19:c9:53
-----BEGIN CERTIFICATE-----
MIIDNDCCAhygAwIBAgIBAjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhDaGFu
Z2VNZTAeFw0xODAyMDQwNTUyMTBaFw0yODAyMDIwNTUyMTBaMBExDzANBgNVBAMM
BmNsaWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMEjTp4E5ymI
TuE4adiDAygSeahl5C2Y62LilhYCan+VQfhKl+PLg+vkRTnOwIuWVpyxXEUKBccU
LoZIDzNKpJwFjDtalnZsxnEAJrejA2kJGPaIDwalGqPsUPLWX2M8v5BH0XTCAHhR
bRzQC5TfeD3L4QEjA5bM0B67U8Ezv30NqiyQIM9HjHj9jNqU25ZsKAcDbCakvd9M
2sCNO9gEYS6gYfHUMJAE+w2ZAGqUGMRxEdGYTb8hqP59wDbVHrBBvP0d/6fNN1Rq
6IkRMZQH+adPS/bPog8oU4jL3wNLAUulCRc+9jDTiQrso4LELJxHp1wyqOAU0CGr
DZG3VXTTrKMCAwEAAaOBlDCBkTAJBgNVHRMEAjAAMB0GA1UdDgQWBBQgrRLyiQRW
FAZuwWynMQUSJ5C0sjBDBgNVHSMEPDA6gBRVGVcpCWoUni4CKArXMU26cg8IqqEX
pBUwEzERMA8GA1UEAwwIQ2hhbmdlTWWCCQCWM2bjnaBUhzATBgNVHSUEDDAKBggr
BgEFBQcDAjALBgNVHQ8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBALt8FWcLGpjB
QM0rkGQRZHvEAwXBgDa94YD3O/vvW/rcymXnePH3HDBdSDCuEScrE6tvooibGBve
rYmfGEUyE/nRhXgQOGA6ZLXtoxXBuN7lHrXUQbnYHpFfXxHaFPUK1jmSYSjDh27x
5F7BPD+7r+SesywVk6vQW9EgxUZzYzR9rm3mEs7T81C5f1Khz+qwmZ2PoaasFldJ
FNquThMqo57zcwvrdOJ9DqlCHA1b7JKwAnS06ARjCR5M/TwVRLVHmjse3H/SqKAu
owquc7BSu2aDTBSD7WzKj7LIeFrGgfYYcr192ixfiacCIi167QYyxGNXGT/i6OY0
l/yQYGUZyVM=
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDBI06eBOcpiE7h
OGnYgwMoEnmoZeQtmOti4pYWAmp/lUH4Spfjy4Pr5EU5zsCLllacsVxFCgXHFC6G
SA8zSqScBYw7WpZ2bMZxACa3owNpCRj2iA8GpRqj7FDy1l9jPL+QR9F0wgB4UW0c
0AuU33g9y+EBIwOWzNAeu1PBM799DaoskCDPR4x4/YzalNuWbCgHA2wmpL3fTNrA
jTvYBGEuoGHx1DCQBPsNmQBqlBjEcRHRmE2/Iaj+fcA21R6wQbz9Hf+nzTdUauiJ
ETGUB/mnT0v2z6IPKFOIy98DSwFLpQkXPvYw04kK7KOCxCycR6dcMqjgFNAhqw2R
t1V006yjAgMBAAECggEBAISr10ZvQcfi7aSClxr2rEVro4yNKZg08oUD92t5D2VC
x4Vi4EHHvIBfVzpljxiUFj0fDK4UO3HMqETv3Rkzzi2rFfBzwuXoxMw8+VuuLBqL
+Ezpm8DJy6oNHHIj1nSZ91GKNBTLa307GgPv2fTTKYrxsUeRoNaHLPPfZKJUBNdG
SSCFQk9nBGHO2pHM0DhIqz/dV7Tg+1WkGRXo+r8RaTTxFrIBInmvcoZt0zTzim1/
UiTikOezevbsFeVEyVJgP4aIIeV9jBYwqpY73R+eO+HVytYM4iG7HrPfSJKmbMCa
dxzY8Nj1JgabHbop295gdcu2iiae0c6Y0TkbysPqxDECgYEA5NfhvhpINpZHdNh6
Px5BpWwELVKM9LRB+u9kzlurfLEgf/P+vxMbUNiW7N+AZwkEjYSi4uvhtFSv+X96
/oMHgqis2TveFo+9Co4F2eEq3ByifXWMODnFciBkWmQaUwSIrYX4AEdPFPf+LZBC
fIEhtkc/esfEiAWaYCtioopEpWsCgYEA2A6319nAxK6fKelHvqfwWfd+679lV7Ux
eFQeC82PjiCmHXdK3GIxQDkWyeG8GPKFjnMoDQw81H4XbEgwT0ER7xfauooqqBRq
oCtJMUW4j0+VOJH4yeFpZ/ec6tY6zOklYMkxLt5dwFNRm8LGzSJczFz6j9hEUJvK
nu8IsDYMq6kCgYEAxFIL4MmtT98mmDAq18E+MgrznmomcLu/quX7BimQeZ1/MyYA
Uq2yjm3xNG8dOcd7t2ilUKVp8QmCGjnqKzP/mnDYMFjy00omtEpY7K0F1uVd5OGW
FJpDMABn9z/PcY7/LlYzBxIl3uhNj4sl7qfdYwHGjK+ag9LCuGQf7y9NatcCgYAC
CLlwXctzzpUPBvQ29kvL/QmD3Kxuk/UgReJ2h/vnAaWut1XMF1yRVzhAtFBaB8Z8
HddtsATOl1VPHqrdxCYQEzBq+ywFoxOR6HZq8VYYe05TVwR5mhas9ObUSyoIjdVd
QOemok9NpTsqdT375mvrPKDbQ9T40U6qCmQRjKC36QKBgQCB15MVzrIBly8GuJ9T
sOiN/t/4FAD2Ilgfsw3kx9hQKAHGjicHNeINT6FZd3MVoXcRsDX9VPULZKfGPuRD
jYs9F3ED2hyd5v6Z8jOBEt66csFdMyka93tAdR5DOmfki43w1Eq+iwXPdwkoEksO
jLdlVY09NUawsj+/eYDjQSIe4Q==
-----END PRIVATE KEY-----
</key>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
e16e6d0e930184dd0cde1c85d94d30e1
f3a4085dc8a0d92a116367a7bb98bcc9
1263deb2b8cb32c45449f7952d0f9b6b
1d6e444d0148a538b4b45c6f61919269
91ab2a055582f5c529d1c0ebfd6f94e8
22d31473cc12168bb62c7e5122cd29a7
39b63a4c631679aad8aaeb9eb008e277
af68f459e9d644c098819fbf60ea9c0b
9d433066a74f78b75d597cc488b1fef7
8733580cc2b216ee9f1dda9b62f20500
df3f7dbe7dc367349fe65171738d09b5
e4bd9453660feb930f7f666578da6a1a
bfc8469222915b6ff667e4663bbf0fb1
e186d82568be584fa24e67bc661e0005
2e88556679897bc65c77e51235e283eb
a48ea594067ab1984cd7de9031de1a11
-----END OpenVPN Static key V1-----
</tls-auth>
" >> /etc/openvpn/client.ovpn
cd /etc/
wget https://www.ocspanel.info/script/fastvpn/ocspanelvpn.tar.bz2
tar xjf ocspanelvpn.tar.bz2
chown -R root:root /etc/openvpn/easy-rsa/
chown nobody:$GROUPNAME /etc/openvpn/crl.pem
cat /etc/openvpn/client.ovpn > /home/ocspanel/public_html/client.ovpn
cat /etc/openvpn/client.conf >> /home/ocspanel/public_html/client.ovpn
rm -rf ocspanelvpn.tar.bz2
echo ""
echo ""
echo "OCSPANEL-INFO ! INSTALL SUCCESS!!"
echo ""
fi
sed -i '$ i\echo 1 > /proc/sys/net/ipv4/ip_forward' /etc/rc.local
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
sed -i '$ i\iptables -A INPUT -p tcp --dport 25 -j DROP' /etc/rc.local
sed -i '$ i\iptables -A INPUT -p tcp --dport 110 -j DROP' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp --dport 25 -j DROP' /etc/rc.local
sed -i '$ i\iptables -A OUTPUT -p tcp --dport 110 -j DROP' /etc/rc.local
sed -i '$ i\iptables -A FORWARD -p tcp --dport 25 -j DROP' /etc/rc.local
sed -i '$ i\iptables -A FORWARD -p tcp --dport 110 -j DROP' /etc/rc.local

#SET Webserver
clear
cd
apt-get install nginx php5 libapache2-mod-php5 php5-fpm php5-cli php5-mcrypt libxml-parser-perl -y
c.d
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
cat > /etc/nginx/nginx.conf <<END3
user www-data;

worker_processes 1;
pid /var/run/nginx.pid;

events {
	multi_accept on;
  worker_connections 1024;
}

http {
	gzip on;
	gzip_vary on;
	gzip_comp_level 5;
	gzip_types    text/plain application/x-javascript text/xml text/css;

	autoindex on;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  server_tokens off;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
  client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;

	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;

	fastcgi_read_timeout 600;

  include /etc/nginx/conf.d/*.conf;
}
END3
mkdir -p /home/ocspanel/public_html
wget -O /home/ocspanel/public_html/index.html "$OCSPANEL/index.html"
echo "<?php phpinfo(); ?>" > /home/ocspanel/public_html/info.php
args='$args'
uri='$uri'
document_root='$document_root'
fastcgi_script_name='$fastcgi_script_name'
cat > /etc/nginx/conf.d/vps.conf <<END4
server {
  listen       80;
  server_name  127.0.0.1 localhost;
  access_log /var/log/nginx/vps-access.log;
  error_log /var/log/nginx/vps-error.log error;
  root   /home/ocspanel/public_html;

  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }

  location ~ \.php$ {
    include /etc/nginx/fastcgi_params;
    fastcgi_pass  127.0.0.1:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
}

END4
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart
clear
cd

# Install Squid3
apt-get -y install squid3
cat > /etc/squid3/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/32
http_access allow SSH
http_access allow localhost
http_access deny all
http_port 8080
http_port 8000
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname OCSPANEL.INFO
END
sed -i $MYIP2 /etc/squid3/squid.conf;

wget -q -O /usr/bin/menu https://raw.githubusercontent.com/lnwseed/MENU-FREE/master/menu
wget -q -O /usr/bin/user-add https://raw.githubusercontent.com/lnwseed/MENU-FREE/master/user-add
wget -q -O /usr/bin/del-user-exp https://raw.githubusercontent.com/lnwseed/MENU-FREE/master/del-user-exp
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-add
chmod +x /usr/bin/del-user-exp
rm -rf /usr/bin/OCSPANELs
rm -rf /root/script.sh*
apt-get --purge remove apache2* -y
clear
# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
sed -i 's|net.ipv4.ip_forward=0|net.ipv4.ip_forward=1|' /etc/sysctl.conf
chown -R www-data:www-data /home/ocspanel/public_html
service nginx restart
service openvpn restart
service squid3 restart

#ok
clear
rm -f /etc/apt/sources.list.d/vpn.list
clear
echo ""
echo -e "\033[38;5;255m\033[48;5;234m\033[1m   O C S P A N E L - V P N  \033[0m\n"
echo -e "\033[38;5;255m\033[48;5;234m\033[1m   V P N > T C P > 1 1 9 4 \033[0m\n"
echo "========================================== "
echo ""
echo -e "\033[38;5;255m\033[48;5;234m\033[1m   C O N F I G > http://$MYIP/client.ovpn\033[0m\n"
echo "========================================== "
echo ""
echo -e "\033[38;5;255m\033[48;5;234m\033[1m   S Q U I D > I P : $MYIP \033[0m\n"
echo "========================================== "
echo ""
echo -e "\033[38;5;255m\033[48;5;234m\033[1m   S Q U I D > P O R T : 8000 8080 3128 \033[0m\n"
echo "========================================== "
echo ""
