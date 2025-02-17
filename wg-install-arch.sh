#!/bin/bash
###
#
# Author: Crashatina
# Date: 2025/02/18
###
OS_DETECTED="$(awk '/^ID=/' /etc/*-release | awk -F'=' '{ print tolower($2) }')"
CONTINUE_ON_UNDETECTED_OS=false                                                                                         # Set true to continue if OS is not detected properly (not recommended)
WGUI_LINK="https://github.com/crashatina/Wireguard-UI/raw/refs/heads/main/wireguard-ui-v0.6.2-linux-386.tar.gz"         # Link to the last release
WGUI_PATH="/opt/wgui"                                                                                                   # Where Wireguard-ui will be install
WGUI_BIN_PATH="/usr/local/bin"                                                                                          # Where the symbolic link will be make
SYSTEMCTL_PATH="/usr/bin/systemctl"
SYS_INTERFACE_GUESS=$(ip route show default | awk '/default/ {print $5}')
PUBLIC_IP="$(curl -s icanhazip.com)"

function main() {
  cat <<EOM

###########################################################################
  - Please make sure that your system is fully up to date and rebooted
      - The current running kernel must be the same as installed
      - No pending reboot
      - You can run the command below and then run again this script
          pacman -Syu --noconfirm && reboot

  - Press Ctrl^C to exit or ignore this message and continue.
###########################################################################

EOM

  while [[ -z $ENDPOINT ]]; do
    echo "---"
    read -p "Enpoint [$PUBLIC_IP](fqdn possible as well): " ENDPOINT
    ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
  done
  while ! [[ $WG_PORT =~ ^[0-9]+$ ]]; do
    echo "---"
    read -p "Wireguard port ? [51820]: " WG_PORT
    WG_PORT=${WG_PORT:-"51820"}
  done
  while ! [[ $WG_NETWORK =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; do
    echo "---"
    read -p "Wireguard network ? [10.252.1.0/24]: " WG_NETWORK
    WG_NETWORK=${WG_NETWORK:-"10.252.1.0/24"}
  done
  while [[ -z $WG_INTERFACE ]]; do
    echo "---"
    read -p "Wireguard interface ? [wg0]: " WG_INTERFACE
    WG_INTERFACE=${WG_INTERFACE:-"wg0"}
  done
  while [[ -z $SYS_INTERFACE ]]; do
    echo "---"
    read -p "System network interface ? [$SYS_INTERFACE_GUESS]: " SYS_INTERFACE
    SYS_INTERFACE=${SYS_INTERFACE:-$SYS_INTERFACE_GUESS}
  done
  while ! [[ $STRICT_FIREWALL =~ ^(y|n)$ ]]; do
    echo "---"
    read -p "Set the strict firewall ? [y/N]: " STRICT_FIREWALL
    STRICT_FIREWALL=${STRICT_FIREWALL:-"n"}
  done
  if [ "$STRICT_FIREWALL" == "y" ]; then
    while ! [[ $SSH_PORT =~ ^[0-9]+$ ]]; do
      echo "---"
      read -p "SSH port ? [22]: " SSH_PORT
      SSH_PORT=${SSH_PORT:-"22"}
    done
  fi

  install
  network_conf
  firewall_conf
  wg_conf
  wgui_conf

  cat <<EOM

##################################################################################
                            Setup done.

  - Your iptables rules have been saved just in case in:
      - /etc/iptables/rules.v4.bak
      - /etc/iptables/rules.v6.bak


  - To access your wireguard-ui please open a new ssh connexion
      - ssh -L 5000:${ENDPOINT:-$PUBLIC_IP}:5000 user@myserver.domain.tld
      - And browse to http:/${ENDPOINT:-$PUBLIC_IP}/:5000

##################################################################################"

EOM
}

function install() {

  echo ""
  echo "### Update & Upgrade"
  pacman -Syu --noconfirm
  echo ""
  echo "### Installing wget"
  pacman -S wget --noconfirm
  echo ""
  echo "### Installing which"
  pacman -S which --noconfirm
  echo ""
  echo "### Installing WireGuard"
  pacman -S wireguard-tools --noconfirm

  echo ""
  echo "### Installing Wireguard-UI"
  if [ ! -d $WGUI_PATH ]; then
    mkdir -m 077 $WGUI_PATH
  fi

  wget -qO - $WGUI_LINK | tar xzf - -C $WGUI_PATH

  if [ -f $WGUI_BIN_PATH/wireguard-ui ]; then
    rm $WGUI_BIN_PATH/wireguard-ui
  fi
  ln -s $WGUI_PATH/wireguard-ui $WGUI_BIN_PATH/wireguard-ui
}

function network_conf() {
  echo ""
  echo "### Enable ipv4 Forwarding"

  # Create or update the sysctl configuration file
  echo "net.ipv4.ip_forward=1" | tee /etc/sysctl.d/99-sysctl.conf > /dev/null

  # Apply the changes
  sysctl --system
}

function firewall_conf() {
  echo ""
  echo "### Firewall configuration"

  if [ ! $(which iptables) ]; then
    echo ""
    msg info "iptables is required. Let's install it."
    pacman -S iptables --noconfirm
  fi

  if [ ! -d /etc/iptables ]; then
    mkdir -m 755 /etc/iptables
  fi

  # Удаляем старые резервные файлы, если они существуют
  if [ -f /etc/iptables/iptables.rules.bak ]; then
    rm /etc/iptables/iptables.rules.bak
  fi
  if [ -f /etc/iptables/ip6tables.rules.bak ]; then
    rm /etc/iptables/ip6tables.rules.bak
  fi

  if [ "$STRICT_FIREWALL" == "n" ]; then
    RULES_4=(
    "INPUT -i $WG_INTERFACE -m comment --comment wireguard-network -j ACCEPT"
    "INPUT -p udp -m udp --dport $WG_PORT -i $SYS_INTERFACE -m comment --comment external-port-wireguard -j ACCEPT"
    "FORWARD -s $WG_NETWORK -i $WG_INTERFACE -o $SYS_INTERFACE -m comment --comment Wireguard-traffic-from-$WG_INTERFACE-to-$SYS_INTERFACE -j ACCEPT"
    "FORWARD -d $WG_NETWORK -i $SYS_INTERFACE -o $WG_INTERFACE -m comment --comment Wireguard-traffic-from-$SYS_INTERFACE-to-$WG_INTERFACE -j ACCEPT"
    "POSTROUTING -t nat -s $WG_NETWORK -o $SYS_INTERFACE -m comment --comment wireguard-nat-rule -j MASQUERADE"
    )
  elif [ "$STRICT_FIREWALL" == "y" ]; then
    RULES_4=(
    "INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
    "INPUT -i lo -m comment --comment localhost-network -j ACCEPT"
    "INPUT -i $WG_INTERFACE -m comment --comment wireguard-network -j ACCEPT"
    "INPUT -p tcp -m tcp --dport $SSH_PORT -j ACCEPT"
    "INPUT -p tcp -m tcp --dport 5000 -j ACCEPT"
    "INPUT -p udp -m udp --dport $WG_PORT -i $SYS_INTERFACE -m comment --comment external-port-wireguard -j ACCEPT"
    "INPUT -i eth0 -p icmp -m icmp --icmp-type 8 -m comment --comment Deny-ping-on-eth0 -j DROP"  # Запрет пинга на eth0
    "FORWARD -s $WG_NETWORK -i $WG_INTERFACE -o $SYS_INTERFACE -m comment --comment Wireguard-traffic-from-$WG_INTERFACE-to-$SYS_INTERFACE -j ACCEPT"
    "FORWARD -d $WG_NETWORK -i $SYS_INTERFACE -o $WG_INTERFACE -m comment --comment Wireguard-traffic-from-$SYS_INTERFACE-to-$WG_INTERFACE -j ACCEPT"
    "FORWARD -p tcp --syn -m limit --limit 1/second -m comment --comment Flood-&-DoS -j ACCEPT"
    "FORWARD -p udp -m limit --limit 1/second -m comment --comment Flood-&-DoS -j ACCEPT"
    "FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/second -m comment --comment Flood-&-DoS -j ACCEPT"
    "FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -m comment --comment Port-Scan -j ACCEPT"
    "OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
    "OUTPUT -o lo -m comment --comment localhost-network -j ACCEPT"
    "OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT"
    "OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT"
    "OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT"
    "OUTPUT -p udp -m udp --dport 53 -j ACCEPT"
    "OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT"
    "OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT"
    "POSTROUTING -t nat -s $WG_NETWORK -o $SYS_INTERFACE -m comment --comment wireguard-nat-rule -j MASQUERADE"
    )

    RULES_6=(
    "INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
    "INPUT -i lo -m comment --comment localhost-network -j ACCEPT"
    "OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT"
    "OUTPUT -o lo -m comment --comment localhost-network -j ACCEPT"
    )

    # Change default policy to DROP instead ACCEPT
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
  fi

  # Apply rules only if they are not already present
  if [ ! -z "$RULES_4" ]; then
    for e in "${RULES_4[@]}"; do
      iptables -C $e > /dev/null 2>&1 || iptables -A $e
    done
  fi

  if [ ! -z "$RULES_6" ]; then
    for e in "${RULES_6[@]}"; do
      ip6tables -C $e > /dev/null 2>&1 || ip6tables -A $e
    done
  fi

  # Сохраняем только основные файлы правил
  /sbin/iptables-save > /etc/iptables/iptables.rules
  /sbin/ip6tables-save > /etc/iptables/ip6tables.rules

  # Ensure iptables service is enabled and running
  if systemctl is-enabled iptables.service > /dev/null 2>&1; then
    echo ""
    msg info "iptables service is already enabled."
  else
    echo ""
    msg info "Enabling iptables service..."
    systemctl enable iptables.service
  fi

  if systemctl is-active iptables.service > /dev/null 2>&1; then
    echo ""
    msg info "iptables service is already running."
  else
    echo ""
    msg info "Starting iptables service..."
    systemctl start iptables.service
  fi
}

function wg_conf() {
  echo ""
  echo "### Making default Wireguard conf"
  umask 077 /etc/wireguard/
  touch /etc/wireguard/$WG_INTERFACE.conf
  $SYSTEMCTL_PATH enable wg-quick@$WG_INTERFACE.service
}

function wgui_conf() {

  echo ""
  echo "### Wiregard-ui Services"
  echo "[Unit]
  Description=Wireguard UI
  After=network.target

  [Service]
  Type=simple
  WorkingDirectory=$WGUI_PATH
  ExecStart=$WGUI_BIN_PATH/wireguard-ui -bind-address 0.0.0.0:5000

  [Install]
  WantedBy=multi-user.target" > /etc/systemd/system/wgui_http.service

  $SYSTEMCTL_PATH enable wgui_http.service
  $SYSTEMCTL_PATH start wgui_http.service

  echo "[Unit]
  Description=Restart WireGuard
  After=network.target

  [Service]
  Type=oneshot
  ExecStart=$SYSTEMCTL_PATH restart wg-quick@$WG_INTERFACE.service" > /etc/systemd/system/wgui.service

  echo "[Unit]
  Description=Watch /etc/wireguard/$WG_INTERFACE.conf for changes

  [Path]
  PathModified=/etc/wireguard/$WG_INTERFACE.conf

  [Install]
  WantedBy=multi-user.target" > /etc/systemd/system/wgui.path

  $SYSTEMCTL_PATH enable wgui.{path,service}
  $SYSTEMCTL_PATH start wgui.{path,service}
}

function msg(){

  local GREEN="\\033[1;32m"
  local NORMAL="\\033[0;39m"
  local RED="\\033[1;31m"
  local PINK="\\033[1;35m"
  local BLUE="\\033[1;34m"
  local WHITE="\\033[0;02m"
  local YELLOW="\\033[1;33m"

  if [ "$1" == "ok" ]; then
    echo -e "[$GREEN  OK  $NORMAL] $2"
  elif [ "$1" == "ko" ]; then
    echo -e "[$RED ERROR $NORMAL] $2"
  elif [ "$1" == "warn" ]; then
    echo -e "[$YELLOW WARN $NORMAL] $2"
  elif [ "$1" == "info" ]; then
    echo -e "[$BLUE INFO $NORMAL] $2"
  fi
}

function not_supported_os(){
  msg ko "Oops This OS is not supported yet !"
  echo "    Do not hesitate to contribute for a better compatibility
            https://gitlab.com/snax44/wireguard-ui-setup"
}

function detect_os(){
  if [[ "$OS_DETECTED" == "arch" ]]; then
    msg info "OS detected : Archlinux"
    main
  else
    if $CONTINUE_ON_UNDETECTED_OS; then
      msg warn "Unable to detect os. Keep going anyway in 5s"
      sleep 5
      main
    else
      msg ko "Unable to detect os and CONTINUE_ON_UNDETECTED_OS is set to false"
      exit 1
    fi
  fi
}

if ! [ $(id -nu) == "root" ]; then
  msg ko "Oops ! Please run this script as root"
  exit 1
fi
detect_os