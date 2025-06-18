#!/bin/bash

clear

#Colores y marcas
NOCOL='\e[0m' # No Color
GREEN='\e[1;32m'
BLUE='\e[1;34m'
RED='\e[1;31m'
MAGENTA='\e[1;35m'
OK="[${GREEN}✓${NOCOL}]"
KO="[${RED}✗${NOCOL}]"


GTFOBINSSUID="aa-exec,ab,agetty,alpine,ar,arj,arp,as,ascii-xfr,ash,aspell,atobm,awk,base32,base64,basenc,basez,bash,bc,bridge,busctl,busybox,bzip2,cabal,capsh,cat,chmod,choom,chown,chroot,clamscan,cmp,column,comm,cp,cpio,cpulimit,csh,csplit,csvtool,cupsfilter,curl,cut,dash,date,dd,debugfs,dialog,diff,dig,distcc,dmsetup,docker,dosbox,ed,efax,elvish,emacs,env,eqn,espeak,expand,expect,file,find,fish,flock,fmt,fold,gawk,gcore,gdb,genie,genisoimage,gimp,grep,gtester,gzip,hd,head,hexdump,highlight,hping3,iconv,install,ionice,ip,ispell,jjs,join,jq,jrunscript,julia,ksh,ksshell,kubectl,ld.so,less,links,logsave,look,lua,make,mawk,minicom,more,mosquitto,msgattrib,msgcat,msgconv,msgfilter,msgmerge,msguniq,multitime,mv,nasm,nawk,ncftp,nft,nice,nl,nm,nmap,node,nohup,ntpdate,od,openssl,openvpn,pandoc,paste,perf,perl,pexec,pg,php,pidstat,pr,ptx,python,python,python2,python2.7,python3,python3.6,python3.7,python3.8,python3.9,python3.10,rc,readelf,restic,rev,rlwrap,rsync,rtorrent,run-parts,rview,rvim,sash,scanmem,sed,setarch,setfacl,setlock,shuf,soelim,softlimit,sort,sqlite3,ss,ssh-agent,ssh-keygen,ssh-keyscan,sshpass,start-stop-daemon,stdbuf,strace,strings,sysctl,systemctl,tac,tail,taskset,tbl,tclsh,tee,terraform,tftp,tic,time,timeout,troff,ul,unexpand,uniq,unshare,unsquashfs,unzip,update-alternatives,uudecode,uuencode,vagrant,varnishncsa,view,vim,vimdiff,vipw,w3m,watch,wc,wget,whiptail,xargs,xdotool,xmodmap,xmore,xxd,xz,yash,zsh,zsoelim"



echo -e "${BLUE}=================================================================${NOCOL}"
echo -e "${MAGENTA}          SPARTA: Shell Privileges And Root Total Access${NOCOL}"
echo -e "${BLUE}=================================================================${NOCOL}"

echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 SYSTEM INFO"
echo -e "─────────────────────────────${NOCOL}"
echo
echo -e "${BLUE}OS:${NOCOL} $(grep PRETTY_NAME /etc/os-release | cut -d '"' -f2)"
echo -e "${BLUE}Hostname:${NOCOL} $(hostname)"
echo -e "${BLUE}IP:${NOCOL} $(hostname -I | awk '{print $1}')"
echo -e "${BLUE}Kernel:${NOCOL} $(uname -r)"
echo -e "${BLUE}Whoami:${NOCOL} $(whoami) - $(id)"
echo -e "${BLUE}Shell:${NOCOL} $SHELL - $TERM"





echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 PORTS & NETWORK"
echo -e "─────────────────────────────${NOCOL}"
echo
echo -e "${BLUE}Listening ports:${NOCOL}"
if command -v ss >/dev/null 2>&1; then
    ss -tnlp
elif command -v netstat >/dev/null 2>&1; then
    netstat -tnl 2>/dev/null 
else
    awk '$4=="0A"{split($2,a,":"); cmd="printf \"%d\n\" 0x"a[2]; cmd|getline p; close(cmd); print p}' /proc/net/tcp
fi
echo
echo -e "${BLUE}Entries in /etc/hosts:${NOCOL}"
grep -v "::" /etc/hosts



echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 SUDOERS"
echo -e "─────────────────────────────${NOCOL}"
echo


if command -v sudo >/dev/null 2>&1; then
    echo -e "${BLUE}sudo is installed${NOCOL}"
    SUDO_OUTPUT=$(sudo -ln 2>&1)

    SUDO_VERS=$(sudo -V | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    echo "Version $(sudo -V | head -n 1 | rev | cut -d ' ' -f1 | rev)"
    echo

    # return 0 if v1 < v2)
    version_lt() {
        [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]
    }

    # return 0 if v1 <= v2)
    version_le() {
        [ "$1" = "$2" ] || version_lt "$1" "$2"
    }

    # CVE-2021-3156: 1.8.2 <= v <= 1.8.31p2 o 1.9.0 <= v <= 1.9.5p1
    if ( version_le "1.8.2" "$SUDO_VERS" ) && ( version_lt "$SUDO_VERS" "1.8.32" ); then
        echo -e "${GREEN}sudo version $SUDO_VERS: CVE-2021-3156${NOCOL}"
    fi

    if ( version_le "1.9.0" "$SUDO_VERS" ) && ( version_lt "$SUDO_VERS" "1.9.6" ); then
        echo -e "${GREEN}sudo version $SUDO_VERS: CVE-2021-3156${NOCOL}"
    fi

    # CVE-2019-14287: v < 1.8.28
    if version_lt "$SUDO_VERS" "1.8.28"; then
        echo -e "${GREEN}sudo version $SUDO_VERS: CVE-2019-14287${NOCOL}"
    fi

    # CVE-2019-18634: v < 1.8.26 (si pwfeedback activado - no chequeado aquí)
    if version_lt "$SUDO_VERS" "1.8.26"; then
        echo -e "${GREEN}sudo version $SUDO_VERS: CVE-2019-18634 (if pwfeedback enabled)"
    fi

    # CVE-2013-1775: 1.8.0 <= v <= 1.8.6p7 (aproximado)
    if ( version_le "1.8.0" "$SUDO_VERS" ) && ( version_lt "$SUDO_VERS" "1.8.7" ); then
        echo -e "${GREEN}sudo version $SUDO_VERS: CVE-2013-1775${NOCOL}"
    fi

    if [[ "$SUDO_OUTPUT" =~ "required" ]]; then
        echo -e "${BLUE}sudo command failed: a password is required${NOCOL}"
    else
      if echo "$SUDO_OUTPUT" | grep -qi "sorry"; then
          echo "No sudoers privileges"
          exit 1
      fi

      if echo -e "$SUDO_OUTPUT" | grep -qi "may run"; then
          echo -e "$OK ${GREEN}User $(whoami) may ran some files as sudo: ${NOCOL}"
          echo -e "${GREEN}$SUDO_OUTPUT" | grep -i "may run the following" -A10 | tail -n +2
          echo -e "${NOCOL}"
      fi

      if echo "$SUDO_OUTPUT" | grep -q "ENV BASH_ENV"; then
          echo -e "${GREEN}ENV BASH_ENV enabled${NOCOL}"
      fi
    fi
else
    echo -e "${BLUE}sudo is not installed${NOCOL}"
fi



echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 SUID, CAPABILITIES & DOAS"
echo -e "─────────────────────────────${NOCOL}"
echo

echo -e "${BLUE}SUID:${NOCOL}"
SUID=$(find /usr/bin -perm -4000 2>/dev/null)
for perm in $SUID; do
	BASE=$(basename "$perm")
	if [[ ",$GTFOBINSSUID," == *",$BASE,"* ]]; then
		echo -e "${GREEN}$perm${NOCOL} ${OK} Owner: $(ls -l $perm | awk '{print $3}')"
  elif [[ "$BASE" == *pkexec* ]]; then
    echo -e "${GREEN}Detectado $(pkexec --version)${NOCOL}"
	else
		echo -e "$perm"
	fi  
done
echo
echo
echo -e "${BLUE}CAPABILITIES:${NOCOL}"
getcap -r / 2>/dev/null
echo
echo
echo -e "${BLUE}DOAS:${NOCOL}"
find / -type f -name "doas.conf" 2>/dev/null




echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 USERS"
echo -e "─────────────────────────────${NOCOL}"
echo

echo -e "${BLUE}All usernames in /etc/passwd:${NOCOL}"
cut -d ':' -f1 /etc/passwd | tr "\n" " "
echo
echo
echo -e "${BLUE}Users with shell${NOCOL}"
USERLIST=$(awk -F: '$3 == 0 || ($3 >= 1000 && $3 <= 2000) {print $1}' /etc/passwd)
ACTUALUSER=$(whoami)
for user in $USERLIST; do
if ! [ "$user" == "$ACTUALUSER" ]; then
	echo -e "${GREEN}$(grep $user /etc/passwd)${NOCOL}"
else
  echo -e "(me) $(grep $user /etc/passwd)"
fi  
done



echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 FILES"
echo -e "─────────────────────────────${NOCOL}"
echo

echo -e "${BLUE}Linux security files:${NOCOL}"
for file in /etc/passwd /etc/shadow; do
	[ -r $file ] && echo -e "${GREEN}$file${NOCOL} is readable"
  [ -w $file ] && echo -e "${GREEN}$file${NOCOL} is writeable"
done
echo

echo -e "${BLUE}Files and folder owns by $(whoami) outside home:${NOCOL}"
find / -user $(whoami) -print 2>/dev/null | grep -v "^/proc\|/home/$(whoami)\|^/dev"
echo

echo -e "${BLUE}/opt readable files:${NOCOL}"
find /opt -readable -type f 2>/dev/null
echo

echo -e "${BLUE}Writable files:${GREEN}"
find / -writable -type f 2>/dev/null | grep -vE "^/proc|~|^/dev"
echo -e "${NOCOL}"

echo -e "${BLUE}Directories in PATH:${NOCOL}"
echo $PATH | sed 's/:/\n/'g | xargs ls -ld 2>/dev/null



echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 DIRTY PIE"
echo -e "─────────────────────────────${NOCOL}"
echo

version=$(uname -r | cut -d'-' -f1)
major=$(echo "$version" | cut -d. -f1)
minor=$(echo "$version" | cut -d. -f2)
patch=$(echo "$version" | cut -d. -f3)

is_vulnerable=false

if [ "$major" -eq 5 ]; then
  if [ "$minor" -eq 8 ] || [ "$minor" -eq 9 ] || [ "$minor" -eq 10 ] || [ "$minor" -eq 11 ] || [ "$minor" -eq 12 ] || [ "$minor" -eq 13 ] || [ "$minor" -eq 14 ] || [ "$minor" -eq 15 ]; then
    is_vulnerable=true
  elif [ "$minor" -eq 16 ] && [ "$patch" -lt 11 ]; then
    is_vulnerable=true
  fi
fi

if $is_vulnerable; then
  echo -e "${BLUE}Kernel $version: ${GREEN}maybe vulnerable to Dirty Pipe (CVE-2022-0847)${NOCOL}"
else
  echo -e "${BLUE}Kernel $version:${NOCOL} not vulnerable to Dirty Pipe."
fi


echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 INFORMATION LEAKEAGE"
echo -e "─────────────────────────────${NOCOL}"
echo


echo -e "${BLUE}Environment:${NOCOL}"
env 2>/dev/null | grep -iE "pass|key|token|secret|cred|auth|login|email|api|db|ssh|ftp" | grep -v "^SSH_AUTH_SOCK\|^SSH_AGENT_PID\|^SSH_CLIENT\|^SSH_CONNECTION\|^SSH_TTY\|^HOME\|^USER\|^LOGNAME\|^PATH\|^PWD"
echo

echo -e "${BLUE}History:${NOCOL}"
history | head -n 10
echo

echo -e "${BLUE}/var/mail files:${NOCOL}"
find /var/mail/ -type f -readable 2>/dev/null
echo

echo -e "${BLUE}.htpasswd files:${NOCOL}"
find / -iname "*htpasswd*" -readable 2>/dev/null
echo

echo -e "${BLUE}Searching for .git directories:${NOCOL}"
find / -name .git -type d 2>/dev/null
echo

echo -e "${BLUE}Alias:${NOCOL}"
alias
echo

echo -e "${BLUE}Files with 'password' string:${NOCOL}"
for ruta in /tmp /etc /var/log /opt /var/tmp; do
	grep -Ril "password" $ruta 2>/dev/null | grep -v "^/etc/alternatives\|^/etc/pam.d"
done
echo



echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 DATABASES"
echo -e "─────────────────────────────${NOCOL}"
echo
echo -e "${BLUE}Search for database files:${NOCOL}"
find / -type f \( -name "*.db*" -o -name "*.sqlite*" -o -name "*.sqlite3*" -o -name "*.mdb*" -o -name "*.sql*" -o -name "*.dmp*" \) 2>/dev/null 



echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 CRON"
echo -e "─────────────────────────────${NOCOL}"
echo
echo -e "${BLUE}crontab:${NOCOL}"
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/* 2>/dev/null | grep -v "^#"
echo
echo -e "${BLUE}systemctl list-timers${NOCOL}"
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-timers --all 2>/dev/null
else
    echo "systemctl not found"
fi

echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 PROCESS"
echo -e "─────────────────────────────${NOCOL}"
echo
ps -eo user:20,cmd --no-headers | while read -r user cmd_rest; do
    if [ "$user" = "root" ]; then 
        echo -e "${GREEN}[$user] --> $cmd_rest${NOCOL}"
    elif [ "$user" = "$(whoami)" ]; then 
        echo -e "${BLUE}[$user] --> $cmd_rest${NOCOL}"
    else 
        echo "$[user] --> $cmd_rest"
    fi
done


echo
echo
echo -e "${MAGENTA}─────────────────────────────"
echo -e "🧩 NEW PROCESS"
echo -e "─────────────────────────────${NOCOL}"
echo

temp_file=$(mktemp)

ps -ef | grep -v "monitor_procesos.sh" | grep -v "ps -ef" | grep -v "grep" > "$temp_file"
echo -e "${BLUE}Searching for new processes...${NOCOL}"

self_pid=$$

while true; do
    new_temp=$(mktemp)
    ps -ef | grep -v "ps -ef" | grep -v "grep" | grep -v " $self_pid " > "$new_temp"
    
    new_processes=$(diff "$temp_file" "$new_temp" | grep "^>" | sed 's/^> //')
    
    if [ -n "$new_processes" ]; then
        #echo -e "\n[$(date +'%Y-%m-%d %H:%M:%S')] New process detected:"
        echo -e "${GREEN}$new_processes${NOCOL}"
    fi
    
    mv "$new_temp" "$temp_file"
    
    sleep 0.25
done

rm -f "$temp_file"
