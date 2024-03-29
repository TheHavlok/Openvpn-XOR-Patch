#!/bin/bash

# Функции для каждого пункта меню
auto_install() {
echo ""
echo "Auto-installation and configuration..."
echo ""
# Шаг 1.2: Установка и настройка брандмауэра nftables
read -p "Do you want to update the system? (Y/N): " -n 1 -r
echo    # Для новой строки
if [[ $REPLY =~ ^[Yy]$ ]]; then
	DEBIAN_FRONTEND=noninteractive apt-get update -y
	DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq --with-new-pkgs --allow-change-held-packages
fi

# Шаг 1.1: Выбор случайного порта для OpenVPN
PORT=$(awk -v min=10000 -v max=50000 'BEGIN{srand(); print int(min+rand()*(max-min+1))}')
echo "Используемый порт OpenVPN: $PORT"

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
wget https://github.com/TheHavlok/Openvpn-XOR-Patch/releases/download/files/openvpn-2.6.8.tar.gz
tar -xvf openvpn-2.6.8.tar.gz

wget https://github.com/TheHavlok/Openvpn-XOR-Patch/releases/download/files/Tunnelblick-master.zip
unzip Tunnelblick-master.zip

# Шаг 1.5: Применение патчей
OPENVPN_DIR="openvpn-2.6.8"
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

# Генерация параметров Diffie-Hellman
./easyrsa gen-dh

# Генерация ключа TLS-аутентификации
openvpn --genkey secret pki/tls-crypt.key

# Копирование ключей и сертификатов в директорию OpenVPN
cp pki/ca.crt /etc/openvpn
cp pki/private/server.key /etc/openvpn/server
cp pki/issued/server.crt /etc/openvpn/server
cp pki/tls-crypt.key /etc/openvpn
cp pki/dh.pem /etc/openvpn

# Шаг 1.9: Генерация кода обфускации Scramble
SCRAMBLE_CODE=$(openssl rand -base64 24)
echo "Код обфускации Scramble: $SCRAMBLE_CODE"

# Шаг 1.10: Настройка сервера OpenVPN
SERVER_CONF="/etc/openvpn/server.conf"

# Инициализация файла конфигурации
echo "port $PORT" > $SERVER_CONF
echo 'proto udp' >> $SERVER_CONF
echo 'dev tun' >> $SERVER_CONF
echo "ca /etc/openvpn/ca.crt" >> $SERVER_CONF
echo "cert /etc/openvpn/server/server.crt" >> $SERVER_CONF
echo "key /etc/openvpn/server/server.key" >> $SERVER_CONF
echo "dh /etc/openvpn/dh.pem" >> $SERVER_CONF
echo "server 10.8.0.0 255.255.255.0" >> $SERVER_CONF
echo "ifconfig-pool-persist /etc/openvpn/ipp.txt" >> $SERVER_CONF
echo 'push "redirect-gateway def1 bypass-dhcp"' >> $SERVER_CONF
echo 'push "dhcp-option DNS 8.8.8.8"' >> $SERVER_CONF
echo 'push "dhcp-option DNS 8.8.4.4"' >> $SERVER_CONF
echo "keepalive 10 120" >> $SERVER_CONF
echo "cipher AES-128-GCM" >> $SERVER_CONF
echo "tls-crypt /etc/openvpn/tls-crypt.key" >> $SERVER_CONF
echo 'persist-key' >> $SERVER_CONF
echo 'persist-tun' >> $SERVER_CONF
echo "status openvpn-status.log" >> $SERVER_CONF
echo "verb 3" >> $SERVER_CONF
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

echo ""
read -n 1 -s -r -p "Press any key to return to the main menu..."
echo ""
tput cup 0 0
tput ed
display_logo
}

add_new_client() {
    echo "Add a new client..."
    # Здесь ваш код для добавления нового клиента
}

list_clients() {
	tput cup 0 0
	tput ed
	display_logo
    echo "List of clients..."
    # Здесь ваш код для вывода списка всех клиентов
	echo ""
 # Получение списка клиентов
    clients=()
    while IFS= read -r line; do
        if [[ $line == "V"* ]]; then
            status="\e[42m\e[97m[Valid]\e[0m"
        elif [[ $line == "R"* ]]; then
            status="\e[41m\e[97m[Revoked]\e[0m"
        else
            continue
        fi
        cn=$(echo $line | awk -F '/CN=' '{print $2}')
        clients+=("$cn $status")
	done < ~/easy-rsa/pki/index.txt
# Вывод списка клиентов с номерами
echo "Список клиентов:"
for i in "${!clients[@]}"; do
    echo -e "$((i+1)): ${clients[i]}"
done
	echo ""
    read -n 1 -s -r -p "Press any key to return to the main menu..."
    echo ""
	tput cup 0 0
    tput ed
    display_logo
}

delete_client() {
    echo "Delete a client..."
    # Здесь ваш код для удаления клиента
	OPENVPN_PATH="/etc/openvpn"
	EASY_RSA_PATH=~/easy-rsa

	# Получение списка клиентов
	clients=()
	while IFS= read -r line; do
    	if [[ $line == "V"* ]]; then
    	    status="\e[42m\e[97m[Valid]\e[0m"
    	elif [[ $line == "R"* ]]; then
    	    status="\e[41m\e[97m[Revoked]\e[0m"
    	else
        	continue
    	fi
    	cn=$(echo $line | awk -F '/CN=' '{print $2}')
    	clients+=("$cn $status")
	done < "$EASY_RSA_PATH/pki/index.txt"

# Вывод списка клиентов с номерами
echo "Список клиентов:"
for i in "${!clients[@]}"; do
    echo -e "$((i+1)): ${clients[i]}"
done

# Выбор клиента пользователем
read -p "Введите номер клиента для удаления: " client_number

# Получение имени клиента и проверка ввода
selected_client="${clients[$((client_number-1))]% [*}"  # Удаляем статус из имени
if [ -z "$selected_client" ]; then
    echo "Неверный выбор."
    exit 1
fi

cd "$EASY_RSA_PATH" || exit

# Отзыв сертификата
./easyrsa --batch revoke "$selected_client"
./easyrsa gen-crl

# Копирование CRL в директорию OpenVPN
cp "$EASY_RSA_PATH/pki/crl.pem" "$OPENVPN_PATH"

echo "Сертификат для клиента $selected_client отозван."	
}

display_logo() {
	echo " _   _       _            _  _____                    "
    echo "| | | |     | |          | ||_   _|                   "
    echo "| | | |_ __ | |_   _  ___| | _| | ___  __ _ _ __ ___  "
    echo "| | | | '_ \| | | | |/ __| |/ / |/ _ \/ _\` | '_ \` _ \ "
    echo "| |_| | | | | | |_| | (__|   <| |  __/ (_| | | | | | |"
    echo " \___/|_| |_|_|\__,_|\___|_|\_\_/\___|\__,_|_| |_| |_|"
    echo "                                                      "
    echo "                                                      "
}

# Проверка на наличие прав суперпользователя
if [[ $EUID -ne 0 ]]; then
	echo -e "\e[42m\e[97mRequesting elevation of privileges...\e[0m"
    # Перезапуск скрипта с sudo
    sudo bash "$0" "$@"
    exit $?
fi

tput cup 0 0
tput ed

display_logo

# Основной цикл меню
while true; do
    echo "Select options:"
    echo "1) Auto-installation and configuration"
    echo "2) Add a new client"
    echo "3) List of clients"
    echo "4) Delete a client"
    echo "5) Exit"
    read -p "Enter the option number: " option
    case $option in
        1) auto_install ;;
        2) add_new_client ;;
        3) list_clients ;;
        4) delete_client ;;
        5) break ;;
        *) tput cup 0 0; tput ed; display_logo; echo -e "\033[31mIncorrect selection. Please try again.\033[0m\n";;	
    esac
done
