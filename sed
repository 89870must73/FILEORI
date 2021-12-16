#!/bin/bash
# Debian 9 and 10 VPS Installer
# Script by Bonveio Abitona
# 
# Illegal selling and redistribution of this script is strictly prohibited
# Please respect author's Property
# Binigay sainyo ng libre, ipamahagi nyo rin ng libre.
#
#

#############################
#############################

#L2TP SCRIPT DEBIAN 9 10 & UBUNTU 16 17 18 19
###wget -q 'https://raw.githubusercontent.com/Barts-23/L2tp-ipsec/master/l2tp_debuntu.sh' && chmod +x l2tp_debuntu.sh && ./l2tp_debuntu.sh
###wget -q 'https://raw.githubusercontent.com/Barts-23/L2tp-ipsec/master/add_vpn_user.sh' && chmod +x add_vpn_user.sh && ./add_vpn_user.sh
###wget -q 'https://raw.githubusercontent.com/Barts-23/L2tp-ipsec/master/update_vpn_users.sh' && chmod +x update_vpn_users.sh && ./update_vpn_users.sh

# Variables (Can be changed depends on your preferred values)
# Script name
MyScriptName='XAMJYSScript'

# Your SSH Banner
SSH_Banner='https://raw.githubusercontent.com/itsgelogomayee/dpndncy/master/banner'

# OpenVPN Ports
OpenVPN_Port1='1103'
OpenVPN_Port2='25222' # take note when you change this port, openvpn sun noload config will not work

# OpenVPN Config Download Port
OvpnDownload_Port='81' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Asia/Kuala_Lumpur'
#############################

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 
 # Removing some firewall tools that may affect other services
 #apt-get remove --purge ufw firewalld -y

 
 # Installing some important machine essentials
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
 
 # Now installing all our wanted services
 apt-get install nginx ruby apt-transport-https lsb-release squid screenfetch -y

 # Installing all required packages to install Webmin
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq -y
 
 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y

 # Installing OpenVPN by pulling its repository inside sources.list file 
 #rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" >/etc/apt/sources.list.d/openvpn.list && apt-key del E158C569 && wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
 wget -qO security-openvpn-net.asc "https://keys.openpgp.org/vks/v1/by-fingerprint/F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7" && gpg --import security-openvpn-net.asc
 apt-get update -y
 apt-get install openvpn -y

 # Checking if openvpn folder is accidentally deleted or purged
 if [[ ! -e /etc/openvpn ]]; then
  mkdir -p /etc/openvpn
 fi

 # Removing all existing openvpn server files
 rm -rf /etc/openvpn/*

 # Creating server.conf, ca.crt, server.crt and server.key
 cat <<'myOpenVPNconf1' > /etc/openvpn/server_tcp.conf
# LODIxyrussScript
port MyOvpnPort1
proto tcp
dev tun
dev-type tun
sndbuf 100000
rcvbuf 100000
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
tls-auth ta.key 0
dh dh.pem
topology subnet
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
auth SHA256
comp-lzo
user nobody
group nogroup
persist-tun
status openvpn-status.log
verb 2
mute 3
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
myOpenVPNconf1
cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# LODIxyrussScript
port MyOvpnPort2
proto udp
dev tun
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "redirect-gateway def1 bypass-dhcp" 
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
tls-auth tls-auth.key 0
dh dh.pem
auth SHA256
cipher AES-128-CBC
tls-server
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
status openvpn.log
verb 3
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
myOpenVPNconf2
 cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIJAP8GMzx/MU1MMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMTCENoYW5nZU1lMB4XDTE4MDUwNjEyMTU0MFoXDTI4MDUwMzEyMTU0MFowEzER
MA8GA1UEAxMIQ2hhbmdlTWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDZMG0zKbAdPzblhslK88dJYToBV1aMxmCjHw51+W8z1rZBYD9c6/DZBPoLxtT/
BlNolMAdukrXU6uXNoHcbyqxb5tIISxBJmzI4L1eD3323knhx28NoyQ+tUWy1GYL
b1Y53/OAdedYE2Zus+HFyJzdZ2vNm+Y4C95tbWfeA2eixSU92M/gpY+onr9qbT/p
ipf7OJ31NTQD7Jzlh8f9l0axx+8SoR9o+Iy9UZrWvhKPKTtWGUaKdSCjR7+coZsM
Jrm7jfw9X0hfebOa4+ATZEvluKHh1DJZYRg2bMfkmt8ZoJEuns7IKzMZzKDGlcIq
4DSIOzxySWx0gQhzlPnSQhhRAgMBAAGjgYEwfzAdBgNVHQ4EFgQUHw+YguqaY/wt
mS3Rn0X2SL3GOtkwQwYDVR0jBDwwOoAUHw+YguqaY/wtmS3Rn0X2SL3GOtmhF6QV
MBMxETAPBgNVBAMTCENoYW5nZU1lggkA/wYzPH8xTUwwDAYDVR0TBAUwAwEB/zAL
BgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAMSacdQtfZuGlJPppREHVWLU
uQEOOR5Zx5+JKfm0mLIX3D1YwoXP2X01F9YntTDWlTTz4aHvn7XkBu6Wxl4F71dB
BxSrmUDN/toDWBagujPS5lEablqXTyrn8pB5jXcHeU61sqGkMg9/T+AChtVXyKCW
3C16igi4U5GF1siGpyLpLvBh6IV7d/eBWIrSDRmlsDwyrFulH7ug1OedNumwfHP/
CMX9rK+OyIRZNO9nbkwSiFvZmRq7pCd0dT5yT6nt59DzyyDPwbF4qoGZC4Ki+hnq
JdxqZ+1W048IZpY8MR73Ejg1Xj82iSdzujCtbT2lS3UwDJDQDMSXub8G0y6XA9E=
-----END CERTIFICATE-----
EOF7
 cat <<'EOF9'> /etc/openvpn/client.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=CN, ST=CA, L=SanFrancisco, O=Fort-Funston, OU=www.dingd.cn, CN=Fort-Funston CA/name=EasyRSA/emailAddress=admin@dingd.cn
        Validity
            Not Before: Feb 21 03:48:14 2017 GMT
            Not After : Feb 19 03:48:14 2027 GMT
        Subject: C=CN, ST=CA, L=SanFrancisco, O=Fort-Funston, OU=www.dingd.cn, CN=client/name=EasyRSA/emailAddress=admin@dingd.cn
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:cd:9a:05:ff:c5:58:cf:49:fb:6c:5b:9b:54:da:
                    b1:6b:52:48:9d:09:1e:53:a7:ca:14:03:31:ff:76:
                    0a:d7:a7:e9:7a:b1:a6:b4:ad:a4:35:a2:b5:62:ee:
                    b0:75:02:8e:6b:93:e5:96:d7:c1:49:04:82:73:0c:
                    7e:11:dc:92:25:3b:7f:0c:30:2b:4c:dd:c0:e1:fb:
                    c8:31:3c:4c:39:eb:1c:1a:8b:28:69:e0:de:3a:02:
                    8b:50:97:71:4e:ea:0a:28:a0:5f:ee:10:d2:39:be:
                    bb:0e:2a:69:ed:f9:f0:ab:6f:e9:9c:e9:fa:83:64:
                    45:22:ac:71:89:b6:70:ab:42:32:22:23:28:cf:b7:
                    b8:2c:04:f9:56:60:2c:45:66:89:c5:1b:4e:55:35:
                    e7:d6:86:92:bd:95:f0:eb:36:53:4c:95:e7:6f:b0:
                    83:e6:20:4d:9c:fc:6b:85:af:50:e4:41:8d:af:7b:
                    fb:f2:c8:af:b8:e2:84:9b:26:99:2a:ed:62:23:76:
                    78:6f:ce:de:2d:6c:08:a0:1e:de:94:50:12:f4:be:
                    20:ee:69:a5:ac:ac:c6:38:2f:13:f3:82:6f:83:62:
                    2e:f6:5c:59:d8:35:10:00:31:a8:38:39:c2:3f:0b:
                    30:dc:9a:05:c5:65:ea:2c:6d:22:67:07:a7:58:29:
                    90:4d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                Easy-RSA Generated Certificate
            X509v3 Subject Key Identifier: 
                C0:A0:80:CC:C7:DB:49:6D:20:18:68:A1:A8:28:A6:52:B4:93:ED:2E
            X509v3 Authority Key Identifier: 
                keyid:20:5C:38:CF:25:8D:B7:7C:07:E2:7A:5E:3C:23:D7:78:8A:ED:F0:71
                DirName:/C=CN/ST=CA/L=SanFrancisco/O=Fort-Funston/OU=www.dingd.cn/CN=Fort-Funston CA/name=EasyRSA/emailAddress=admin@dingd.cn
                serial:92:F3:B8:59:84:A3:0C:8C

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         0e:5b:ef:08:87:05:29:b8:58:a9:2e:4f:70:62:fb:a2:f0:0c:
         ef:55:7d:2a:78:77:9f:f9:74:18:b0:7c:a4:58:2a:20:d8:66:
         39:e0:5b:34:af:e1:7c:ab:97:dc:70:40:d2:bc:3a:9e:82:98:
         a0:00:ce:d8:eb:aa:70:e3:be:f6:08:13:75:43:05:bf:2f:58:
         2a:34:d5:6c:2a:b9:c2:65:47:92:ec:03:df:71:57:ba:0e:5f:
         65:a7:52:b6:bb:21:9c:ff:e9:f7:e0:fd:96:ab:1a:66:ed:c8:
         93:3a:ca:e4:8f:d9:86:21:fa:cb:68:34:46:cb:66:11:6b:0f:
         d8:ca:6b:2f:ba:6e:5d:16:1b:ab:ae:fe:e8:36:94:d2:e0:e0:
         19:08:6c:0e:f7:34:ae:8d:7e:af:0b:92:c8:bc:70:d1:ef:e5:
         16:41:90:eb:ea:eb:4a:03:d5:33:ac:63:34:e6:5f:ae:80:30:
         3d:e7:8c:24:2e:82:d0:7c:84:e0:56:e9:22:f0:ea:9a:03:0c:
         2a:41:71:74:44:84:63:18:e0:7d:60:b1:fc:44:15:83:d2:1a:
         48:8b:06:0b:fc:e8:e9:39:49:75:bb:23:cb:7f:e2:5d:13:f5:
         51:3c:f1:42:44:d6:2f:00:6d:18:38:e2:67:d5:a0:54:08:49:
         55:1f:21:a9
-----BEGIN CERTIFICATE-----
MIIFKzCCBBOgAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBqjELMAkGA1UEBhMCQ04x
CzAJBgNVBAgTAkNBMRUwEwYDVQQHEwxTYW5GcmFuY2lzY28xFTATBgNVBAoTDEZv
cnQtRnVuc3RvbjEVMBMGA1UECxMMd3d3LmRpbmdkLmNuMRgwFgYDVQQDEw9Gb3J0
LUZ1bnN0b24gQ0ExEDAOBgNVBCkTB0Vhc3lSU0ExHTAbBgkqhkiG9w0BCQEWDmFk
bWluQGRpbmdkLmNuMB4XDTE3MDIyMTAzNDgxNFoXDTI3MDIxOTAzNDgxNFowgaEx
CzAJBgNVBAYTAkNOMQswCQYDVQQIEwJDQTEVMBMGA1UEBxMMU2FuRnJhbmNpc2Nv
MRUwEwYDVQQKEwxGb3J0LUZ1bnN0b24xFTATBgNVBAsTDHd3dy5kaW5nZC5jbjEP
MA0GA1UEAxMGY2xpZW50MRAwDgYDVQQpEwdFYXN5UlNBMR0wGwYJKoZIhvcNAQkB
Fg5hZG1pbkBkaW5nZC5jbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AM2aBf/FWM9J+2xbm1TasWtSSJ0JHlOnyhQDMf92Cten6XqxprStpDWitWLusHUC
jmuT5ZbXwUkEgnMMfhHckiU7fwwwK0zdwOH7yDE8TDnrHBqLKGng3joCi1CXcU7q
CiigX+4Q0jm+uw4qae358Ktv6Zzp+oNkRSKscYm2cKtCMiIjKM+3uCwE+VZgLEVm
icUbTlU159aGkr2V8Os2U0yV52+wg+YgTZz8a4WvUORBja97+/LIr7jihJsmmSrt
YiN2eG/O3i1sCKAe3pRQEvS+IO5ppaysxjgvE/OCb4NiLvZcWdg1EAAxqDg5wj8L
MNyaBcVl6ixtImcHp1gpkE0CAwEAAaOCAWEwggFdMAkGA1UdEwQCMAAwLQYJYIZI
AYb4QgENBCAWHkVhc3ktUlNBIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4E
FgQUwKCAzMfbSW0gGGihqCimUrST7S4wgd8GA1UdIwSB1zCB1IAUIFw4zyWNt3wH
4npePCPXeIrt8HGhgbCkga0wgaoxCzAJBgNVBAYTAkNOMQswCQYDVQQIEwJDQTEV
MBMGA1UEBxMMU2FuRnJhbmNpc2NvMRUwEwYDVQQKEwxGb3J0LUZ1bnN0b24xFTAT
BgNVBAsTDHd3dy5kaW5nZC5jbjEYMBYGA1UEAxMPRm9ydC1GdW5zdG9uIENBMRAw
DgYDVQQpEwdFYXN5UlNBMR0wGwYJKoZIhvcNAQkBFg5hZG1pbkBkaW5nZC5jboIJ
AJLzuFmEowyMMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAsGA1UdDwQEAwIHgDANBgkq
hkiG9w0BAQsFAAOCAQEADlvvCIcFKbhYqS5PcGL7ovAM71V9Knh3n/l0GLB8pFgq
INhmOeBbNK/hfKuX3HBA0rw6noKYoADO2OuqcOO+9ggTdUMFvy9YKjTVbCq5wmVH
kuwD33FXug5fZadStrshnP/p9+D9lqsaZu3IkzrK5I/ZhiH6y2g0RstmEWsP2Mpr
L7puXRYbq67+6DaU0uDgGQhsDvc0ro1+rwuSyLxw0e/lFkGQ6+rrSgPVM6xjNOZf
roAwPeeMJC6C0HyE4FbpIvDqmgMMKkFxdESEYxjgfWCx/EQVg9IaSIsGC/zo6TlJ
dbsjy3/iXRP1UTzxQkTWLwBtGDjiZ9WgVAhJVR8hqQ==
-----END CERTIFICATE-----
EOF9
 cat <<'EOF10'> /etc/openvpn/client.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNmgX/xVjPSfts
W5tU2rFrUkidCR5Tp8oUAzH/dgrXp+l6saa0raQ1orVi7rB1Ao5rk+WW18FJBIJz
DH4R3JIlO38MMCtM3cDh+8gxPEw56xwaiyhp4N46AotQl3FO6goooF/uENI5vrsO
Kmnt+fCrb+mc6fqDZEUirHGJtnCrQjIiIyjPt7gsBPlWYCxFZonFG05VNefWhpK9
lfDrNlNMledvsIPmIE2c/GuFr1DkQY2ve/vyyK+44oSbJpkq7WIjdnhvzt4tbAig
Ht6UUBL0viDuaaWsrMY4LxPzgm+DYi72XFnYNRAAMag4OcI/CzDcmgXFZeosbSJn
B6dYKZBNAgMBAAECggEAW8Gha8RnHhumWXWInRX8mCjgvzSSlEMNrGDAr4G+1P/a
8ybVf0z/O/ChgsWDerTpWplmnSss16lrjmzE1rPZhURILuhQar2Ml04GyfJfEnoa
0L3KC3aPttPr2Mu9hbptTjREm7pmF99HG8tR+yLQhbIsUBsb8geN0yuigBMrtUHI
1wgP1C0gpbfPWExq7kTTclnHFjDRn2SuAXGRKNrCkMI+3r17TPooq0Tf/3wHxE6o
a3d1eMuVdX50pDJNV7vfkSm4FrJXWaXhj5s7lj5PLsqE9NXA9RWuL73awCjM9PL3
b7HWLi5GGqucvxya8W6S/YZcNFNmhxi/dH+xQuv3AQKBgQDmEOWc9oZrQuxep6qS
TkScfkntAo/F5SeD2fg2NX5hgQAkdFaGcIEqcp49bSb2N/AS8xO5Dowld7AcX6X0
YZYTSWBb4YhcFs2acZDlSJ0EILOabjeX26IAYPt0M83rccy6/+WNq8gydSzzlKOf
MsIEEdikppBe4CXGxfHX6zFNOwKBgQDkxyY9LT7Xq0NF9Hz+1+enVPySMsoyC8jQ
YEJCCnsQyL31G9+k3DnWGAss7/Rnjd9fVryPNpKuqBhFMsJPjVJXs1pfNoRI2Haz
LObxlJNcTED4ONHLD5VjM84j97EKQBQ5ZrKvUwnRJBI5ljNRa26rAW4/jnPWsI5x
XDDtpvjgFwKBgFDSWMeWd0xRG1Z5UlvJcSME3pWLk9RylzojpaXtjvNT7SfhUtAx
z76Iu3xazxgqOIV/rUsSiDtVW6HsHBHJAn7OBTLh/RRU0m/SO5PAuaBMmKvE0nTf
rH6zk0KUPF/c/44l/Y+SbGcFcQA1FHIF09C4MEJPXWJnHf5BZZ9zuUMnAoGAMi1T
v7s6u0a+3IsBF0v3bQYA13f4TP20r69NGPr/fvDoaOgSJzB+JuzjFpoSetvtEBYQ
CUEo7tHDcPnvEE+orb+SpKtqXCfN8QJ6LKYvo+C9pzOfH/BtDXMBVXYwCFWBmg1i
R33o+0v0C1lcLBFqFmub6Kiv03ip5UcZHCaxE0UCgYEAlHzk63DYXtgC6AK47auk
sqfz6c2/6OpvDL3ez9T/RqiLxpdBNjh1zQ9gNwtRC7ijS6DUkvdcXbeweXTT+gXQ
bskMRq1YeuijP9+eVoX4dye92nXLO7cRLUvJINS/VJTQFcfFMWlvc2P5i3FVsvxD
l2Zif9fCaYAfPcUAEazdLjw=
-----END PRIVATE KEY-----
EOF10
 cat <<'EOF18'> /etc/openvpn/tls-auth.key
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
bdcfd0846a6e313b81166314b6b3837c
b4860c3d84ac2f17fcf26a7ca090974c
97ec8395c67b98090560e82120b16eb0
d3f237fb7d5033985db907a3e3fce5ab
ee5bad86b77a36166f80b594aa3b53db
87863f3250e931d37a1b66703d7691b7
88c4e0e648fa278da3c883247daa3c38
379a26c262ed37a6ee1ec7ba826e703b
e9f4a494f89b253499e0b64f20250157
cb182c932bdd916de5aef07ff6e5a4ee
b3eb7aec6a058785ff771d2c18432790
195eae67a96f383be5931c1356734a6b
f4c619cb97094fd337f971b340bad41b
bb774d630c2eb24fd0057785d505afee
6a2749f79febf7bdb1e5a6c62f250c55
2f2448e5be01abb287151073d53f3996
-----END OpenVPN Static key V1-----
EOF18
 cat <<'EOF107'> /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1b:3f:6f:da:75:60:5a:53:ec:da:fc:89:c8:5c:2d:80
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ChangeMe
        Validity
            Not Before: May  6 12:16:42 2018 GMT
            Not After : May  3 12:16:42 2028 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:f1:06:d5:b1:fd:e3:ec:27:0e:fc:c4:ed:05:5d:
                    0d:cf:a0:5e:9d:d8:ab:d1:84:7a:1a:ab:ec:09:74:
                    68:90:4d:b1:70:77:8c:c3:08:62:25:63:ad:8d:d1:
                    be:f8:86:11:55:b3:ce:dd:d7:f6:78:cf:73:2b:4c:
                    0e:b7:2f:0e:78:6f:13:da:7a:25:f0:66:22:09:5f:
                    1e:4d:91:3f:7f:8b:3f:b3:3b:3d:46:ef:61:11:a6:
                    2f:92:a5:b6:9b:26:40:60:2e:8d:e9:a2:7d:97:d9:
                    0d:17:05:68:5d:f9:92:c2:7e:c5:96:36:e8:ac:63:
                    2b:58:6e:dd:7b:cb:c7:e8:a3:c8:e0:33:2c:63:74:
                    f6:f4:e4:47:eb:5c:b2:cc:03:b7:83:65:d9:73:a4:
                    7b:89:c0:f9:d0:9e:e6:1d:39:b4:b4:21:7f:0b:20:
                    b4:f9:6f:61:9f:35:e3:ca:fe:44:db:24:12:b8:6e:
                    dd:f3:ab:ed:36:d6:fe:4b:17:cb:9e:6a:a6:58:77:
                    14:14:0c:18:76:77:be:74:62:f3:8a:ab:f1:a0:01:
                    7d:87:75:30:28:ed:c9:86:73:c5:69:08:33:65:da:
                    3e:2b:0c:38:37:09:40:da:d7:fb:32:86:80:b0:63:
                    f8:f5:02:58:57:e6:f3:44:12:13:e6:dd:b1:a8:a6:
                    29:7f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                0C:55:A9:EA:EB:15:D7:EC:36:12:7E:A0:76:F8:9E:FA:D1:F8:FE:4D
            X509v3 Authority Key Identifier: 
                keyid:1F:0F:98:82:EA:9A:63:FC:2D:99:2D:D1:9F:45:F6:48:BD:C6:3A:D9
                DirName:/CN=ChangeMe
                serial:FF:06:33:3C:7F:31:4D:4C

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         79:61:47:4e:ca:e3:8a:c0:7c:69:ba:8f:a1:fb:8f:34:47:ab:
         7b:7f:d4:e4:84:38:3f:ca:b9:dc:7a:3f:fb:80:d9:24:5f:8e:
         13:dd:e2:5e:82:76:8e:94:f4:5a:f8:b8:b5:59:f1:04:42:6b:
         59:c2:eb:43:6a:c8:fb:35:7b:31:5a:70:e6:16:6a:0a:45:4d:
         59:f5:a6:1a:09:94:b3:1c:b7:f8:18:a6:2b:43:86:be:72:7c:
         e3:7d:ea:7e:45:7a:24:ed:83:5b:cd:a8:a4:8e:f1:10:07:8f:
         85:77:5a:50:aa:ff:8e:65:83:66:09:d9:a6:d2:50:fe:62:02:
         a6:93:70:1c:9c:45:35:d7:d9:a5:09:b0:69:38:17:0b:1b:9f:
         22:e2:85:2f:1f:a7:74:d0:db:37:8e:d2:61:bf:cc:da:5a:78:
         b1:7d:2e:9e:10:92:94:4c:dd:cb:a2:74:c8:49:1b:fa:01:62:
         e8:1e:71:e1:0b:fc:77:ab:24:52:82:91:98:76:63:2f:b2:98:
         d1:73:a2:08:22:0b:bd:60:2b:cf:cc:4e:91:47:d9:b1:c1:a6:
         a6:5e:ec:b6:1b:3d:29:57:09:1b:66:bf:e5:62:0c:74:05:6e:
         85:fd:eb:7a:a0:b8:44:15:65:81:e9:82:29:d6:a4:b3:46:5b:
         a0:2d:e3:7c
-----BEGIN CERTIFICATE-----
MIIDVjCCAj6gAwIBAgIQGz9v2nVgWlPs2vyJyFwtgDANBgkqhkiG9w0BAQsFADAT
MREwDwYDVQQDEwhDaGFuZ2VNZTAeFw0xODA1MDYxMjE2NDJaFw0yODA1MDMxMjE2
NDJaMBExDzANBgNVBAMTBnNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAPEG1bH94+wnDvzE7QVdDc+gXp3Yq9GEehqr7Al0aJBNsXB3jMMIYiVj
rY3RvviGEVWzzt3X9njPcytMDrcvDnhvE9p6JfBmIglfHk2RP3+LP7M7PUbvYRGm
L5KltpsmQGAujemifZfZDRcFaF35ksJ+xZY26KxjK1hu3XvLx+ijyOAzLGN09vTk
R+tcsswDt4Nl2XOke4nA+dCe5h05tLQhfwsgtPlvYZ8148r+RNskErhu3fOr7TbW
/ksXy55qplh3FBQMGHZ3vnRi84qr8aABfYd1MCjtyYZzxWkIM2XaPisMODcJQNrX
+zKGgLBj+PUCWFfm80QSE+bdsaimKX8CAwEAAaOBpzCBpDAJBgNVHRMEAjAAMB0G
A1UdDgQWBBQMVanq6xXX7DYSfqB2+J760fj+TTBDBgNVHSMEPDA6gBQfD5iC6ppj
/C2ZLdGfRfZIvcY62aEXpBUwEzERMA8GA1UEAxMIQ2hhbmdlTWWCCQD/BjM8fzFN
TDATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAwEQYDVR0RBAowCIIG
c2VydmVyMA0GCSqGSIb3DQEBCwUAA4IBAQB5YUdOyuOKwHxpuo+h+480R6t7f9Tk
hDg/yrncej/7gNkkX44T3eJegnaOlPRa+Li1WfEEQmtZwutDasj7NXsxWnDmFmoK
RU1Z9aYaCZSzHLf4GKYrQ4a+cnzjfep+RXok7YNbzaikjvEQB4+Fd1pQqv+OZYNm
Cdmm0lD+YgKmk3AcnEU119mlCbBpOBcLG58i4oUvH6d00Ns3jtJhv8zaWnixfS6e
EJKUTN3LonTISRv6AWLoHnHhC/x3qyRSgpGYdmMvspjRc6IIIgu9YCvPzE6RR9mx
waamXuy2Gz0pVwkbZr/lYgx0BW6F/et6oLhEFWWB6YIp1qSzRlugLeN8
-----END CERTIFICATE-----
EOF107
 cat <<'EOF113'> /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDxBtWx/ePsJw78
xO0FXQ3PoF6d2KvRhHoaq+wJdGiQTbFwd4zDCGIlY62N0b74hhFVs87d1/Z4z3Mr
TA63Lw54bxPaeiXwZiIJXx5NkT9/iz+zOz1G72ERpi+SpbabJkBgLo3pon2X2Q0X
BWhd+ZLCfsWWNuisYytYbt17y8foo8jgMyxjdPb05EfrXLLMA7eDZdlzpHuJwPnQ
nuYdObS0IX8LILT5b2GfNePK/kTbJBK4bt3zq+021v5LF8ueaqZYdxQUDBh2d750
YvOKq/GgAX2HdTAo7cmGc8VpCDNl2j4rDDg3CUDa1/syhoCwY/j1AlhX5vNEEhPm
3bGopil/AgMBAAECggEATOxVfzz8ZP4CNoHS84dDRSR1jgL8sx2IqsJ7znisdoGV
Q8Oj1Qrz5+LsHPr36/E9zxBX0U1/iAcNRqA7ghMulxk8SNn7CcJO0pbc4PyeO2KB
rf4WDHGRlURoonDo2pNWsFurRwlo8/F9z/8V1Ag24oP7I3nawEnWJ58aaMwcvQ4K
F7ZPP3X+4k3rP4KnlejwQinbgdwKp7DW2rXL+wepX/3TNnJVCafUSsY71c8Gjv8U
OPEr9pIRJI8QAOMkLSB6OuPAW1w986QpE6TvyUP5kYmZIYMhZbXWER1MmxyCDMGV
UsuI4Kdh6Dk9q99VhU2AJMc8FiQpqPaGHRXmdTS3wQKBgQD8AqX+iLcBEVACAba6
hBEWXuUNJ9g351VtC1osEV0C1lcWgDHIls5XwY/C5GGuPxorFoY9XKzg09Eueo5R
NQkJImc8GYRj5fS5K7ULWquu9FN86vIbQwjezkN+mz6z9Vn3yhHHYkHbYMoGCJMQ
sC/4jNAnQixZS/+1I4UNSifvSQKBgQD016vv80Ev/4Y0Bo8eHlPItiBhOp6ICByM
xq4mFgAvJ0k3+SrOFKD3OuHsRU9UGaTqIQjtpweSDukqJGl+6Zf3Dm5K2CeJSYvT
AbcFJL5gqcfRxQu8a82RFzkqc8oFqoU+P0jsi4jxpcjB17CLT7jz/ilFVid8YoDt
k9tp7K0qhwKBgQDOAkQ77Prc7pAe89OyaR+mz/Aibv37xSo6N9uAxrjoBtuuUyFf
PphzeJHS2etYC9GSg5k9NDNGnyETA7CvhdFbHDqUEK//Eg6aCLa5D2flX2mYZl+A
Fa58pNTb/ICnj9v6Cb+65AG+GkNL51qBe+XbIxFN5nRmkw/3vY+Yq5Q1sQKBgQDw
1mjROZVIsm9/I2iJ9sjxaH0HRtMD+f6jVxecbQ23VEyIW3cIiXAgYHI0p6S1lBgN
GXuf0Sn4OOSPyIthBEOwCCjjRCX3vDlm0IwH6jG+AaOFKu81Y1EsxAw+PvFci3RP
W47O5x5InIuSaSjGkB/dGYfdJTbn+jjZ+RPd6KoZZwKBgE9ptBSZ30iIIU6R3S+p
PZ3+U+AxkosNT4N7OEp1VXQy6Ri5FbrcVTFE74ySRHV3FAB5TS5Hfxv7CchLHnfW
4PU+h0zbEgRz+dMkFoezCrXk0/77NLZUItBR3s1btyW+j8mx10KVv83vkuAoep9D
C6H4CuZhRVY/RKZj8X6GpOkK
-----END PRIVATE KEY-----
EOF113
 cat <<'EOF13'> /etc/openvpn/dh.pem
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAwhvQ8aHfvN8h+V9o4DulbJGE2CJRpDUnFxZnOODP+dwRYaiqqxns
C2FxvXc87jmHl8N1uV1OFoDH7xuoeavwtYjyp4lIPJd2b8ZHBfVQXpEMgWBK6enx
b0RTDaRVpoUPaSuTDfRJR+YE1WfHIm6dk3x/wF8AmhG9JZNBbKTQkaXH8wWXWwdM
XmSwb4vD/b0BdGdlmmGB5kyFfiv0y29AA73aStJUM8PX+1WHMHJE7ns87EyWhtQx
28epsWsGudfpMxXgt+5+m+pUcNkGXldYRefY/fxxbGpNUh26GPfpCrt9n0K/bOlD
7LTsKhSqd/v9nD0YRte+3x+MxEbeqF4PwwQhn/ZiC0zLgbls9aEcHBidDU/B1P/Y
61MsyTgfnKDlO0OeyI2+GLuxIXdIVDTrzkWKZ5f9F4C88X7wxm17c++JlsJ0hhc7
PZns5mcgNsOOzQ4RTzAR2vZ61gNj64N2b1BGyZxTClzB0PzbMDqblObf71f/0AYf
zUS7S9ZRPlAMJ4Hdmwwponi+j5iJ5s+BchSNwK+7HLfjysCxrtlxM9KUpwLtMFah
806QY6ck0+f5GeR194m+Gp0k0L+1wvxWPHH7Jwr9R9TN1R8DXdQH2VT8wwKSE2sM
5e30/2I+Q/MJXGvtdUMC6eWtDgQvUHl57IJVTzQAwzpY+13h5hIjEnsCAQI=
-----END DH PARAMETERS-----
EOF13
 cat <<'EOF103'> /etc/openvpn/crl.pem
-----BEGIN X509 CRL-----
MIIBvDCBpQIBATANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA52cG4uZjVsYWJz
LmRldhcNMjEwMTE0MDI1MTIzWhcNMzEwMTEyMDI1MTIzWqBYMFYwVAYDVR0jBE0w
S4AU/Ga3V1iPk7I6YR5DeNQuQ+9e5DWhHaQbMBkxFzAVBgNVBAMMDnZwbi5mNWxh
YnMuZGV2ghRRnHaHIWPU0/8eVLJ7jd8THvVqrDANBgkqhkiG9w0BAQsFAAOCAQEA
qv7+B4WNPqRI4WAiTnCtE/vQlQeKnn39NvDEbjfpJjNZAadQxaTeYtO58TOCu5R4
qwF42g0E2mUQvwUEmUeVulnDjEz5e6KOkgllWsrZGwlUObuKNNKrCHqvXxbH/rHk
76/4Jfu7IvqTk4a9c+MV5r5eSA7plRzdJhqgkBWCmD/46UlP2imkgNGg4FeAamuc
kiLEVXPwjRK30L3uUcWXzvXmXtLlvaadPHKPS5YA41WKS0xZ9iELIz0eUHXl8pgd
jrZFH4tMHWZ+mBTRA/76xsbBGWtkxND932g1vAc281EHv9+4iyW1SdvUTJNzZObh
6GJJ6ESQE6h3vJJpVeoFCg==
-----END X509 CRL-----
EOF103
 cat <<'EOF122'> /etc/openvpn/ta.key
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
bc9d409e9a4df82007b978554f6bc974
b360b2ff4f6d00ab0756b5df091d59e2
f349b570c670b618755d8afeb54bbb6e
2b9c78c08e2eb77d7d14a445d90cb59c
ecd86a1c0c37c065cd88116a482310d8
443fd165fe89ce0632823a09e6eb601b
58144f16288426c10790d23f2a64c704
7a3d935e5d72c9cc0e8ae9dfe8d6aba7
9e14e8852757410836d05adaa82c227c
3bf1a2e3f81fbcb7cae591c43ddd4f55
3a2531faff9826fabb658fe9f4932857
ad8a3fb591b103280dab6de8700810b6
1f02645ae953b08e5f6c8fe107ac84ad
fdd665b9706c06d6f053bbb68cfcef55
afb0eff582231b8d7c640d85b6981b1f
f9ad3c476af859c708825b5212cc94df
-----END OpenVPN Static key V1-----
EOF122

 # Getting all dns inside resolv.conf then use as Default DNS for our openvpn server
 #grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	#echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_tcp.conf
#done
 #grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
	#echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server_udp.conf
#done

 # setting openvpn server port
 sed -i "s|MyOvpnPort1|$OpenVPN_Port1|g" /etc/openvpn/server_tcp.conf
 sed -i "s|MyOvpnPort2|$OpenVPN_Port2|g" /etc/openvpn/server_udp.conf
 
 # Generating openvpn dh.pem file using openssl
 #openssl dhparam -out /etc/openvpn/dh.pem 1024
 
 # Getting some OpenVPN plugins for unix authentication
 wget -qO /etc/openvpn/b.zip 'https://raw.githubusercontent.com/Bonveio/BonvScripts/master/openvpn_plugin64'
 unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
 rm -f /etc/openvpn/b.zip
 
 # Some workaround for OpenVZ machines for "Startup error" openvpn service
 if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

 # Allow IPv4 Forwarding
 echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf && sysctl --system &> /dev/null && echo 1 > /proc/sys/net/ipv4/ip_forward

 # Iptables Rule for OpenVPN server
 #PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
 #IPCIDR='10.200.0.0/16'
 #iptables -I FORWARD -s $IPCIDR -j ACCEPT
 #iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
 #iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
 
 # Installing Firewalld
 apt install firewalld -y
 systemctl start firewalld
 systemctl enable firewalld
 firewall-cmd --quiet --set-default-zone=public
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/tcp
 firewall-cmd --quiet --zone=public --permanent --add-port=1-65534/udp
 firewall-cmd --quiet --reload
 firewall-cmd --quiet --add-masquerade
 firewall-cmd --quiet --permanent --add-masquerade
 firewall-cmd --quiet --permanent --add-service=ssh
 firewall-cmd --quiet --permanent --add-service=openvpn
 firewall-cmd --quiet --permanent --add-service=http
 firewall-cmd --quiet --permanent --add-service=https
 firewall-cmd --quiet --permanent --add-service=privoxy
 firewall-cmd --quiet --permanent --add-service=squid
 firewall-cmd --quiet --reload
 
 # Enabling IPv4 Forwarding
 echo 1 > /proc/sys/net/ipv4/ip_forward
 
 # Starting OpenVPN server
 systemctl start openvpn@server_tcp
 systemctl start openvpn@server_udp
 systemctl enable openvpn@server_tcp
 systemctl enable openvpn@server_udp
 systemctl restart openvpn@server_tcp
 systemctl restart openvpn@server_udp

 
 # I'm setting Some Squid workarounds to prevent Privoxy's overflowing file descriptors that causing 50X error when clients trying to connect to your proxy server(thanks for this trick @homer_simpsons)
 apt remove --purge squid -y
 rm -rf /etc/squid/sq*
 apt install squid -y
 
# Squid Ports (must be 1024 or higher)
 Proxy_Port='8000'
 cat <<mySquid > /etc/squid/squid.conf
acl VPN dst $(wget -4qO- http://ipinfo.io/ip)/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:$Proxy_Port
coredump_dir /var/spool/squid
dns_nameservers 1.1.1.1 1.0.0.1
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
mySquid

 sed -i "s|SquidCacheHelper|$Privoxy_Port1|g" /etc/squid/squid.conf

 # Starting Proxy server
 echo -e "Restarting proxy server.."
 systemctl restart privoxy
 systemctl restart squid
}

 function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/bonveio-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/bonveio-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn
 # Now creating all of our OpenVPN Configs 
cat <<EOF152> /var/www/openvpn/GTMConfig.ovpn
# Credits to GakodX
client
dev tun
remote $IPADDR $OpenVPN_Port1 tcp
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Proxy_Port
resolv-retry infinite
route-method exe
resolv-retry infinite
nobind
persist-key
persist-tun
comp-lzo
cipher AES-256-CBC
auth SHA256
push "redirect-gateway def1 bypass-dhcp"
verb 3
push-peer-info
ping 10
ping-restart 60
hand-window 70
server-poll-timeout 4
reneg-sec 2592000
sndbuf 100000
rcvbuf 100000
remote-cert-tls server
key-direction 1
<auth-user-pass>
sam
sam
</auth-user-pass>
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/client.crt)
</cert>
<key>
$(cat /etc/openvpn/client.key)
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF152

cat <<EOF16> /var/www/openvpn/SunConfig.ovpn
# Credits to GakodX
client
dev tun
proto udp
remote $IPADDR $OpenVPN_Port2
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server_ADBtkp0yL46HLXPb name
auth SHA256
auth-nocache
cipher AES-128-CBC
tls-client
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
setenv opt block-outside-dns
verb 3
auth-user-pass
key-direction 1
<auth-user-pass>
sam
sam
</auth-user-pass>
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server.crt)
</cert>
<key>
$(cat /etc/openvpn/server.key)
</key>
<tls-auth>
$(cat /etc/openvpn/tls-auth.key)
</tls-auth>
EOF16

cat <<EOF160> /var/www/openvpn/ssl.ovpn
# Credits to GakodX
client
dev tun
proto tcp
remote 127.0.0.1 $OpenVPN_Port1
route $IPADDR 255.255.255.255 net_gateway 
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
comp-lzo
cipher AES-256-CBC
auth SHA256
push "redirect-gateway def1 bypass-dhcp"
verb 3
push-peer-info
ping 10
ping-restart 60
hand-window 70
server-poll-timeout 4
reneg-sec 2592000
sndbuf 0
rcvbuf 0
remote-cert-tls server
key-direction 1
<auth-user-pass>
sam
sam
</auth-user-pass>
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/server.crt)
</cert>
<key>
$(cat /etc/openvpn/server.key)
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF160

cat <<EOF17> /var/www/openvpn/ohp.ovpn
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_Port1
http-proxy $(curl -s http://ipinfo.io/ip || wget -q http://ipinfo.io/ip) $Ohp_Port
resolv-retry infinite
route-method exe
resolv-retry infinite
nobind
persist-key
persist-tun
comp-lzo
cipher AES-256-CBC
auth SHA256
push "redirect-gateway def1 bypass-dhcp"
verb 3
push-peer-info
ping 10
ping-restart 60
hand-window 70
server-poll-timeout 4
reneg-sec 2592000
sndbuf 100000
rcvbuf 100000
remote-cert-tls server
key-direction 1
<auth-user-pass>
sam
sam
</auth-user-pass>
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/client.crt)
</cert>
<key>
$(cat /etc/openvpn/client.key)
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF17

 wget https://raw.githubusercontent.com/89870must73/DEB/main/index.html
 cp index.html /var/www/html

 # Setting template's correct name,IP address and nginx Port
 sed -i "s|MyScriptName|$MyScriptName|g" /var/www/openvpn/index.html
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r Configs.zip *.ovpn
 cd
}

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

function ConfMenu(){
echo -e " Creating Menu scripts.."

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://raw.githubusercontent.com/Barts-23/menu1/master/menu.zip'
unzip -qq menu.zip
rm -f menu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~

echo 'clear' > /etc/profile.d/barts.sh
echo 'echo '' > /var/log/syslog' >> /etc/profile.d/barts.sh
echo 'screenfetch -p -A Android' >> /etc/profile.d/barts.sh
chmod +x /etc/profile.d/barts.sh
}

function ScriptMessage(){
 echo -e ""
 echo -e ""
 echo -e " Script created by Bonveio"
 echo -e " Edited by XAMJYSS"
}


#############################
#############################
## Installation Process
#############################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################
#############################

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31mÃƒÆ’Ã¢â‚¬â€\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure Webmin
 echo -e "Configuring webmin..."
 InstWebmin
 

 # Configure OpenVPN
 echo -e "Configuring OpenVPN..."
 InsOpenVPN
 
 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 clear
 cd ~

 # Running sysinfo 
 bash /etc/profile.d/barts.sh
 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
 echo -e ""
 echo -e " Success Installation"
 echo -e ""
 echo -e " Service Ports: "
 echo -e " OpenSSH: $SSH_Port1, $SSH_Port2"
 echo -e " Stunnel: $Stunnel_Port1, $Stunnel_Port2"
 echo -e " DropbearSSH: $Dropbear_Port1, $Dropbear_Port2"
 echo -e " Privoxy: $Privoxy_Port1, $Privoxy_Port2"
 echo -e " Squid: $Proxy_Port"
 echo -e " OpenVPN: $OpenVPN_Port1, $OpenVPN_Port2"
 echo -e " NGiNX: $OvpnDownload_Port"
 echo -e " Webmin: 10000"
 #echo -e " L2tp IPSec Key: xjvpn13"
 echo -e ""
 echo -e ""
 echo -e " OpenVPN Configs Download site"
 echo -e " http://$IPADDR:$OvpnDownload_Port"
 echo -e ""
 echo -e " All OpenVPN Configs Archive"
 echo -e " http://$IPADDR:$OvpnDownload_Port/Configs.zip"
 echo -e ""
 echo -e ""
 echo -e " [Note] DO NOT RESELL THIS SCRIPT"

 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog

rm -f 443all*
exit 1
