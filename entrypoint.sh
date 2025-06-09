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
    apt install -y git wget vim jq curl procps netcat-openbsd iproute2 telnet wfuzz sqlmap binutils httrack python3-pip hashid strace wpscan\
        iputils-ping nmap cmseek jq gobuster whatweb seclists socat python3-setuptools tcpdump snmp sqlite john python3.13-venv ltrace ftp \
        nikto openvpn bind9-dnsutils vim bsdmainutils exploitdb hydra dotdotpwn exiftool html2text build-essential cewl hexedit file cupp
    echo -n
    echo "🧩 All basic packages are installed"
    echo -n

    echo "🧩 Unzipping rockyou"
    cd /usr/share/seclists/Passwords/Leaked-Databases/ && gunzip rockyou.txt.tar.gz && tar xvf rockyou.txt.tar
    
    echo -n
    echo "🧩 Set up prompt, alias, variables and functions"
    echo -n
    echo "cd /root/htb_machines/" >> /root/.bashrc
    
    # Prompt
    echo 'PS1='\''\[\e]0;\u@\h: \w\a\]\[\033[38;5;33m\]┌─(\[\033[38;5;148m\]\u㉿$(my_htb_ip)\[\033[38;5;33m\])-[\[\033[1;37m\]\w\[\033[38;5;33m\]]$(vpn_htb)$(socat_tcp_80)\n\[\033[38;5;33m\]└─▣ \[\033[0m\]'\''' >> /root/.bashrc
    echo "clear" >> /root/.bashrc
    
    # Variables
    echo 'export wordlist_large="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"' >> /root/.bashrc
    echo 'export wordlist="/usr/share/seclists/Discovery/Web-Content/big.txt"' >> /root/.bashrc
    echo 'export rockyou="/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"' >> /root/.bashrc
    echo 'PROMPT_COMMAND="history -a; history -n"' >> /root/.bashrc
    
    # Aliases
    echo 'alias vpnOff="pkill -f openvpn"' >> /root/.bashrc
    echo 'alias vpnOn="openvpn --config /root/htb_machines/htb.ovpn --daemon"' >> /root/.bashrc
    
    # Functions to add icons to the prompt
    echo "vpn_htb() { ip link show tun0 &>/dev/null && echo '🔒' || echo ''; }" >> ~/.bashrc
    echo "socat_tcp_80() { pgrep -f 'socat TCP-LISTEN:80' > /dev/null && echo '🚀' || echo ''; }" >> ~/.bashrc
    echo "my_htb_ip() { [[ -d /sys/class/net/tun0 ]] && ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo 'HTB'; }" >> ~/.bashrc
    echo "urlencode() { python3 -c \"import urllib.parse, sys; print(urllib.parse.quote(' '.join(sys.argv[1:])))\" \"\$@\"; }" >> ~/.bashrc

    echo -n
    echo "🧩 Upgrade Kali"
    apt update && apt upgrade -y
    echo -n
fi

# echo "🧩 Conecting HTB openVPN..."
# openvpn --config /root/htb_machines/*.ovpn --daemon


exec "$@"