# OpenVPN Tunnelblick XOR Patch

# Создание и подписание ключа и сертификата клиента
CLIENT_NAME="debian10"
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

# Копирование ключей и сертификатов в директорию OpenVPN
cp pki/private/$CLIENT_NAME.key /etc/openvpn/client
cp pki/issued/$CLIENT_NAME.crt /etc/openvpn/client

## 1. Set Up Server
### 1.1. Choose Port for OpenVPN
On your server, choose a random port number between 10,000 and 50,000 for OpenVPN.

```bash
awk -v min=10000 -v max=50000 'BEGIN{srand(); print int(min+rand()*(max-min+1))}'
```
The example result that we will use in the rest of this article: 16273

### 1.2. Install and Configure Firewall
There are multiple ways to implement a firewall: nftables, iptables, ufw, and firewalld. The modern way is nftables, and that is what we will use here. Issue each of these commands in turn to install and start nftables:

```bash
apt update && apt upgrade -y
apt install nftables -y
systemctl enable nftables
systemctl start nftables
```

Configure the firewall to accept related traffic and internal traffic:

```bash
nft add rule inet filter input ct state related,established counter accept
nft add rule inet filter input iif lo counter accept
```

Open port 22 for SSH. If you can restrict the port 22 rule so that only certain source IP addresses are whitelisted for SSH access, then so much the better.

```bash
nft add rule inet filter input tcp dport 22 counter accept
```

Add a rule to open the OpenVPN port that you chose at random:

```bash
nft add rule inet filter input udp dport 16273 counter accept
```

Drop all unexpected input:

```bash
nft add rule inet filter input counter drop
```

Now add the table for Network Address Translation (NAT) and masquerading the outgoing IP adddress:

```bash
nft add table nat
nft add chain nat prerouting { type nat hook prerouting priority 0 \; }
nft add chain nat postrouting { type nat hook postrouting priority 100 \; }
nft add rule nat postrouting masquerade
```

Save the rules:

```bash
nft list ruleset > /etc/nftables.conf
```

### 1.3. Allow Forwarding
Enable IPv4 forwarding in the Linux kernel. Edit the system control configuration file:

```bash
nano /etc/sysctl.conf
```

Uncomment the line:

```bash
net.ipv4.ip_forward=1
```

Save the file. Apply the new settings by issuing the command:

```bash
sysctl -p
```

### 1.4. Get OpenVPN and XOR Patch Source
You must use matching versions of OpenVPN and the XOR patch.

Open a browser and visit the GitHub releases page for OpenVPN. Determine the latest release number. At the time of writing, it is version v2.5_beta3. It may be a later version at the time you read this article. We will use v2.5_beta3 in our examples, though you may need to replace this.

Download the OpenVPN tarball for your version:

```bash
wget https://github.com/TheHavlok/Openvpn-XOR-Patch/releases/download/files/openvpn-2.6.8.tar.gz
tar -xvf openvpn-2.6.8.tar.gz
```

Download and extract the Tunnelblick repository:

```bash
wget https://github.com/TheHavlok/Openvpn-XOR-Patch/releases/download/files/Tunnelblick-master.zip
apt install unzip -y
unzip Tunnelblick-master.zip
```

### 1.5. Apply Patches
Copy the patch files into the OpenVPN directory, replacing openvpn-2.5_beta3 by the current version at the time you run this:

```bash
cp Tunnelblick-master/third_party/sources/openvpn/openvpn-2.6.8/patches/*.diff openvpn-2.6.8
```

Apply the patches to the OpenVPN source:

```bash
cd openvpn-2.6.8
apt install patch -y
patch -p1 < 02-tunnelblick-openvpn_xorpatch-a.diff
patch -p1 < 03-tunnelblick-openvpn_xorpatch-b.diff
patch -p1 < 04-tunnelblick-openvpn_xorpatch-c.diff
patch -p1 < 05-tunnelblick-openvpn_xorpatch-d.diff
patch -p1 < 06-tunnelblick-openvpn_xorpatch-e.diff
patch -p1 < 10-route-gateway-dhcp.diff
```

### 1.6. Build OpenVPN with XOR Patch
Install the prerequisites for the build:

```bash
apt install build-essential libssl-dev iproute2 liblz4-dev liblzo2-dev libpam0g-dev libpkcs11-helper1-dev libsystemd-dev resolvconf pkg-config autoconf automake libtool libcap-ng-dev liblz4-dev libsystemd-dev liblzo2-dev libpam0g libpam0g-dev -y
```

Compile and install OpenVPN with the XOR patch:

```bash
autoreconf -i -v -f
./configure --enable-systemd --enable-async-push --enable-iproute2
make
make install
```

The program is installed to /usr/local/sbin/openvpn.

### 1.7. Create Configuration Directories
Create directories that will store your OpenVPN key, certificate, and configuration files:

```bash
mkdir -p /etc/openvpn/{server,client}
```

### 1.8. Create Keys and Certificates with EasyRSA
Install the EasyRSA package:

```bash
apt install easy-rsa -y
```

On Debian 10 and Ubuntu 20.04, this installs EasyRSA 3.0.6.

Make a copy of the EasyRSA scripts and configuration files:

```bash

cp -r /usr/share/easy-rsa ~
cd ~/easy-rsa
```

Make a copy of the example variables:

```bash
cp vars.example vars
```

You can edit the vars file if you wish, but we will just use the defaults. Initialize the public key infrastructure:

```bash
./easyrsa init-pki
```

Build your Certificate Authority (CA):

```bash
./easyrsa build-ca nopass
```

Give the CA a common name of your choosing, or just press Enter to accept the default name of Easy-RSA CA.

Generate and sign your server key and certificate. We use the example server name of server in the example below:

```bash
./easyrsa gen-req server nopass
./easyrsa sign-req server server
yes
```

Generate and sign your client key and certificate. We use the example name debian10 in the example below. You can change this to a name of your own choosing.

```bash
./easyrsa gen-req client_name nopass
./easyrsa sign-req client client_name
yes
```

Generate the Diffie-Hellman parameters. This can take a long time.

```bash
./easyrsa gen-dh
```

Generate a preshared key to encrypt the initial exchange:

```bash
openvpn --genkey secret pki/tls-crypt.key
```

Copy all the keys and certificates into position in the OpenVPN directory:

```bash
cp pki/ca.crt /etc/openvpn
cp pki/private/server.key /etc/openvpn/server
cp pki/issued/server.crt /etc/openvpn/server
cp pki/private/client_name.key /etc/openvpn/client_name.key
cp pki/issued/client_name.crt /etc/openvpn/client_name.crt
cp pki/tls-crypt.key /etc/openvpn
cp pki/dh.pem /etc/openvpn
```

### 1.9. Generate Scramble Obfuscation Code
For the scrambling obfuscation, generate a 192-bit (24-byte) code, expressed as 32 base-64 characters:

```bash
openssl rand -base64 24
```

The example result that we will use in the rest of this article:

```bash
r7EaFR2DshpQT+QMfQGYO5BXC2BAV8JG
```

### 1.10. Configure OpenVPN Server
Edit the OpenVPN configuration file:

```bash
nano /etc/openvpn/server.conf
```

The model for you to adapt to your situation is as follows.

Change the random port number 16273 in the example to your own random port number
Change the sample obfuscation code r7EaFR2DshpQT+QMfQGYO5BXC2BAV8JGto your own random code.

```bash
port 16273
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-128-GCM
tls-crypt /etc/openvpn/tls-crypt.key
persist-key
persist-tun
status openvpn-status.log
verb 3
scramble obfuscate r7EaFR2DshpQT+QMfQGYO5BXC2BAV8JG
```

Save the file.

### 1.11. Configure Systemd
Create a systemd service file for OpenVPN:

```bash
nano /lib/systemd/system/openvpn@.service
```

Insert contents like this:

```bash
[Unit]
Description=OpenVPN connection to %i
PartOf=openvpn.service
ReloadPropagatedFrom=openvpn.service
Before=systemd-user-sessions.service
After=network-online.target
Wants=network-online.target
Documentation=man:openvpn(8)
Documentation=https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
Documentation=https://community.openvpn.net/openvpn/wiki/HOWTO

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn
ExecStart=/usr/local/sbin/openvpn --daemon ovpn-%i --status /run/openvpn/%i.status 10 --cd /etc/openvpn --config /etc/openvpn/%i.conf --writepid /run/openvpn/%i.pid
PIDFile=/run/openvpn/%i.pid
KillMode=process
ExecReload=/bin/kill -HUP $MAINPID
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
LimitNPROC=100
DeviceAllow=/dev/null rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=true
ProtectHome=true
RestartSec=5s
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Save the file.

Create the directory for the process identification (pid) file:

```bash
mkdir /run/openvpn
```

### 1.12. Start OpenVPN
Start OpenVPN on the server:

```bash
systemctl enable openvpn@server
systemctl start openvpn@server
```

Check that it is active and listening on the expected port:

```bash
systemctl status openvpn@server
ss -tulpn | grep openvpn
```

Server work is done:

## 2. Set Up Client
### 2.1. Download Keys and Certificates
Now go to work on your PC. Assuming that your server has IP address yy.yy.yy.yy and that you named the client key and certificate debian10.*, copy the required files down from the server to the client like this:

```bash
scp root@yy.yy.yy.yy:/etc/openvpn/client/client_name.key ~/Downloads/client_name.key
scp root@yy.yy.yy.yy:/etc/openvpn/client/client_name.crt ~/Downloads/client_name.crt
scp root@yy.yy.yy.yy:/etc/openvpn/ca.crt ~/Downloads/ca.crt
scp root@yy.yy.yy.yy:/etc/openvpn/tls-crypt.key ~/Downloads/tls-crypt.key
```

### 2.2. Get OpenVPN and XOR Patch Source
For a Debian/Ubuntu client, this is the pretty much same process as on the server. The version number of OpenVPN and the XOR patch will be the same as on the server. We will use v2.5_beta3 in our examples, though you may need to replace this.

Download the OpenVPN tarball for your version:

```bash
cd ~/Downloads
wget https://github.com/TheHavlok/Openvpn-XOR-Patch/releases/download/files/openvpn-2.6.8.tar.gz
tar -xvf openvpn-2.6.8.tar.gz
```

Download the Tunnelblick repository:

```bash
wget https://github.com/TheHavlok/Openvpn-XOR-Patch/releases/download/files/Tunnelblick-master.zip
sudo apt install unzip -y
unzip Tunnelblick-master.zip
```

### 2.3. Apply Patches
Copy the patch files into the OpenVPN directory, replacing openvpn-2.5_beta3 by the current version:

```bash
cp Tunnelblick-master/third_party/sources/openvpn/openvpn-2.6.8/patches/*.diff openvpn-2.6.8
```

Apply the patches to the OpenVPN source:

```bash
cd openvpn-2.6.8
sudo apt install patch -y
patch -p1 < 02-tunnelblick-openvpn_xorpatch-a.diff
patch -p1 < 03-tunnelblick-openvpn_xorpatch-b.diff
patch -p1 < 04-tunnelblick-openvpn_xorpatch-c.diff
patch -p1 < 05-tunnelblick-openvpn_xorpatch-d.diff
patch -p1 < 06-tunnelblick-openvpn_xorpatch-e.diff
patch -p1 < 10-route-gateway-dhcp.diff
```

### 2.4. Build OpenVPN with XOR Patch
Install the prerequisites for the build:

```bash
apt install build-essential libssl-dev iproute2 liblz4-dev liblzo2-dev libpam0g-dev libpkcs11-helper1-dev libsystemd-dev resolvconf pkg-config autoconf automake libtool libcap-ng-dev liblz4-dev libsystemd-dev liblzo2-dev libpam0g libpam0g-dev -y
```

Compile and install OpenVPN with the XOR patch:

```bash
autoreconf -i -v -f
./configure --enable-systemd --enable-async-push --enable-iproute2
make
sudo make install
```

The program is installed to /usr/local/sbin/openvpn.

### 2.5. Fix DNS Resolution
There is a problem with the pushed DNS servers being ignored in OpenVPN on Linux. The solution depends on what is managing the nameservers. Here is a solution that worked on a Debian 10 client with NetworkManager. There is an alternative solution for Ubuntu with Systemd.

Edit the NetworkManager configuration:

```bash
sudo nano /etc/NetworkManager/NetworkManager.conf
```

In the [main] section, insert a line:

```bash
dns=none
```

Save the file. Then edit the /etc/resolv.conf file:

```bash
sudo nano /etc/resolv.conf
```

Change the contents of the file to specify nameservers that will be accessible while the VPN is on, e.g.:

```bash
nameserver 8.8.8.8
nameserver 8.8.4.4
```

Save the file. Restart NetworkManager:

sudo systemctl restart NetworkManager

### 2.6. Create OpenVPN Client Configuration File
Create a client configuration file for OpenVPN:

```bash
cd ~/Downloads
nano debian10.conf
```

Insert the configuration details below, tailoring them to your situation:

Replace yy.yy.yy.yy by the public IP address of your server
Replace 16273 by your random port
Replace r7EaFR2DshpQT+QMfQGYO5BXC2BAV8JG by your random obfuscation code

```bash
client
dev tun
proto udp
remote yy.yy.yy.yy 16273
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert debian10.crt
key debian10.key
remote-cert-tls server
cipher AES-128-GCM
tls-crypt tls-crypt.key
verb 3
scramble obfuscate r7EaFR2DshpQT+QMfQGYO5BXC2BAV8JG
```

Save the file.

### 2.7. Start OpenVPN Client
Open a terminal on your client PC, and start OpenVPN running:

```bash
cd ~/Downloads
sudo /usr/local/sbin/openvpn --config debian10.conf
```

Leave the terminal open with OpenVPN running in it.

### 2.8. Test End-to-End
Open Firefox.

Visit IP Chicken.

You should see the IP address of your remote server, not your local client.
