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
    apt install -y git wget vim jq curl procps netcat-openbsd iproute2 telnet wfuzz sqlmap binutils \
        iputils-ping git nmap cmseek jq gobuster whatweb seclists socat python3-setuptools tcpdump snmp \
        nikto openvpn bind9-dnsutils vim bsdmainutils exploitdb hydra dotdotpwn exiftool html2text build-essential
    echo -n
    echo "🧩 All basic packages are installed"
    echo -n

    cd /usr/share/seclists/Passwords/Leaked-Databases/ && gunzip rockyou.txt.tar.gz && tar xvf rockyou.txt.tar
    
    echo -n
    echo "🧩 Set up prompt, alias and variables"
    echo -n
    echo "cd /root/htb_machines/" >> /root/.bashrc
    echo 'PS1='\''\[\e]0;\u@\h: \w\a\]\[\033[38;5;33m\]┌─(\[\033[38;5;148m\]\u㉿HTB\[\033[38;5;33m\])-[\[\033[1;37m\]\w\[\033[38;5;33m\]]$(vpn_htb)\n\[\033[38;5;33m\]└─▣ \[\033[0m\]'\''' >> /root/.bashrc
    echo "clear" >> /root/.bashrc
    echo 'export wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"' >> /root/.bashrc
    echo 'export rockyou="/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"' >> /root/.bashrc
    echo 'PROMPT_COMMAND="history -a; history -n"' >> /root/.bashrc
    echo 'alias vpnOff="pkill -f openvpn"' >> /root/.bashrc
    echo 'alias vpnOn="openvpn --config /root/htb_machines/*.ovpn"' >> /root/.bashrc
    echo "vpn_htb() { ip link show tun0 &>/dev/null && echo '🔒' || echo ''; }" >> ~/.bashrc
fi

echo "🧩 Conecting HTB openVPN..."
openvpn --config /root/htb_machines/*.ovpn --daemon

# Execute main command (bash by default)
exec "$@"