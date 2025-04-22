#!/bin/bash
set -e

# Initial configuration only on first run
if [ ! -f /root/.first_run ]; then
    echo -n
    mkdir -p /root/htb_machines/
    echo "✨ All the necessary packages will be installed. Please be patient."
    echo -n
    touch /root/.first_run
    echo "kali-htb" > /etc/hostname
    
    echo "🧩 Updating and installing packages..."
    export DEBIAN_FRONTEND=noninteractive

    apt update
    apt install -y git wget vim jq curl procps netcat-openbsd iproute2 telnet wfuzz \
        iputils-ping git nmap cmseek jq gobuster whatweb seclists socat python3-setuptools \
        nikto openvpn bind9-dnsutils vim bsdmainutils exploitdb hydra medusa
    echo -n
    echo "🧩 Packages installed"
    echo -n

    echo "cd /root/htb_machines/" >> /root/.bashrc
    echo 'PS1='\''\[\e]0;\u@\h: \w\a\]\[\033[38;5;33m\]┌─(\[\033[38;5;148m\]\u㉿HTB\[\033[38;5;33m\])-[\[\033[1;37m\]\w\[\033[38;5;33m\]]\n\[\033[38;5;33m\]└─▣ \[\033[0m\]'\''' >> /root/.bashrc
    echo "clear" >> /root/.bashrc

fi

echo "Finalizado"

echo "🧩 Conecting HTB VPN..."
openvpn --config /root/htb_machines/*.ovpn &

# Execute main command (bash by default)
exec "$@"