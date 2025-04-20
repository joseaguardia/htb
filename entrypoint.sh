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
    mkdir -p /root/proyectos_hack
    
    echo "🧩 Updating and installing packages..."
    apt update
    apt install -y apt kali-linux-headless
    


    echo "cd /root/htb_machines/" >> /root/.bashrc

else
    # Connect to openvpn
    echo "Aquí conectaría a openvpn"
fi

# Execute main command (bash by default)
exec "$@"