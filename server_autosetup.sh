#!/bin/bash

# Шаг 1.1: Выбор случайного порта для OpenVPN
PORT=$(awk -v min=10000 -v max=50000 'BEGIN{srand(); print int(min+rand()*(max-min+1))}')
echo "Используемый порт OpenVPN: $PORT"

# Шаг 1.2: Установка и настройка брандмауэра nftables
apt update && apt upgrade -y
apt install nftables -y
systemctl enable nftables
systemctl start nftables

# Настройка правил брандмауэра
nft add rule inet filter input ct state related,established counter accept
nft add rule inet filter input iif lo counter accept
nft add rule inet filter input tcp dport 22 counter accept
nft add rule inet filter input udp dport "$PORT" counter accept
nft add rule inet filter input counter drop

# Правила NAT
nft add table nat
nft add chain nat prerouting { type nat hook prerouting priority 0 \; }
nft add chain nat postrouting { type nat hook postrouting priority 100 \; }
nft add rule nat postrouting masquerade

# Сохранение правил
nft list ruleset > /etc/nftables.conf

# Шаг 1.3: Разрешение пересылки трафика
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Шаг 1.4: Получение исходного кода OpenVPN и XOR патча
apt install wget tar unzip patch -y
wget https://github.com/OpenVPN/openvpn/archive/v2.5_beta3.tar.gz
tar -xvf v2.5_beta3.tar.gz

wget https://github.com/Tunnelblick/Tunnelblick/archive/master.zip
unzip master.zip

# Шаг 1.5: Применение патчей
OPENVPN_DIR="openvpn-2.5_beta3"
cp Tunnelblick-master/third_party/sources/openvpn/$OPENVPN_DIR/patches/*.diff $OPENVPN_DIR
cd $OPENVPN_DIR

for patchfile in ../*.diff; do
    patch -p1 < "$patchfile"
done

# Шаг 1.6: Сборка OpenVPN с XOR патчем
apt install build-essential libssl-dev iproute2 liblz4-dev liblzo2-dev libpam0g-dev libpkcs11-helper1-dev libsystemd-dev resolvconf pkg-config autoconf automake libtool -y
autoreconf -i -v -f
./configure --enable-systemd --enable-async-push --enable-iproute2
make
make install

# Шаг 1.7: Создание директорий конфигурации
mkdir -p /etc/openvpn/{server,client}

# Шаг 1.8: Создание ключей и сертификатов с EasyRSA
apt install easy-rsa -y
make-cadir ~/easy-rsa
cd ~/easy-rsa

# Инициализация PKI и создание CA
./easyrsa init-pki
./easyrsa build-ca nopass

# Создание и подписание ключа и сертификата сервера
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Создание и подписание ключа и сертификата клиента
CLIENT_NAME="debian10"
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

# Генерация параметров Diffie-Hellman
./easyrsa gen-dh

# Генерация ключа TLS-аутентификации
openvpn --genkey secret pki/tls-crypt.key

# Копирование ключей и сертификатов в директорию OpenVPN
cp pki/ca.crt /etc/openvpn
cp pki/private/server.key /etc/openvpn/server
cp pki/issued/server.crt /etc/openvpn/server
cp pki/private/$CLIENT_NAME.key /etc/openvpn/client
cp pki/issued/$CLIENT_NAME.crt /etc/openvpn/client
cp pki/tls-crypt.key /etc/openvpn
cp pki/dh.pem /etc/openvpn

# Шаг 1.9: Генерация кода обфускации Scramble
SCRAMBLE_CODE=$(openssl rand -base64 24)
echo "Код обфускации Scramble: $SCRAMBLE_CODE"

# Шаг 1.10: Настройка сервера OpenVPN
SERVER_CONF="/etc/openvpn/server.conf"
echo "port $PORT" > $SERVER_CONF
echo 'proto udp' >> $SERVER_CONF
# ... и так далее для каждой строки конфигурации
echo "scramble obfuscate $SCRAMBLE_CODE" >> $SERVER_CONF

# Шаг 1.11: Настройка Systemd для OpenVPN
SYSTEMD_SERVICE="/lib/systemd/system/openvpn@.service"
cat > $SYSTEMD_SERVICE <<- EOM
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
EOM

mkdir /run/openvpn

# Шаг 1.12: Запуск OpenVPN
systemctl enable openvpn@server
systemctl start openvpn@server

# Проверка статуса службы OpenVPN
systemctl status openvpn@server
# Проверка, что OpenVPN слушает нужный порт
ss -tulpn | grep openvpn

# Если все в порядке, выход из сервера
exit

# Теперь переход к настройке клиента
