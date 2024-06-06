#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================== SYSTEM INFO ==================${NC}"
(cat /proc/version || uname -a) 2>/dev/null
cat /etc/os-release 2>/dev/null
echo

echo -e "${BLUE}================== WRITE PERMISSIONS CHECK ==================${NC}"
for dir in ${PATH//:/ }; do
  if [ -w "$dir" ]; then
    echo -e "${GREEN}Writable directory in PATH: $dir${NC}"
  fi
done
echo

echo -e "${BLUE}================== ENVIRONMENT VARIABLES ==================${NC}"
(env || set) 2>/dev/null
echo

echo -e "${BLUE}================== DEFENSES ==================${NC}"
echo -e "${YELLOW}Checking for AppArmor...${NC}"
if command -v aa-status &> /dev/null; then
    aa-status
elif command -v apparmor_status &> /dev/null; then
    apparmor_status
elif ls -d /etc/apparmor* &> /dev/null; then
    ls -d /etc/apparmor*
else
    echo -e "${RED}Not found AppArmor${NC}"
fi
echo

echo -e "${YELLOW}Checking for SELinux...${NC}"
if command -v sestatus &> /dev/null; then
    sestatus
elif command -v getenforce &> /dev/null; then
    getenforce
elif [ -f /etc/selinux/config ]; then
    cat /etc/selinux/config
else
    echo -e "${RED}Not found SELinux${NC}"
fi
echo

echo -e "${BLUE}================== PROCESSES RUN BY ROOT ==================${NC}"
ps -U root -u root u
echo

echo -e "${BLUE}================== WRITABLE SYSTEMD SERVICE FILES ==================${NC}"
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -name "*.service" -writable 2>/dev/null
echo

echo -e "${BLUE}================== CRON JOBS WITH WILDCARD INJECTION ==================${NC}"
grep -r '[[:space:]][[:space:]]*[^[:space:]]' /etc/cron* 2>/dev/null
echo

echo -e "${BLUE}================== USER CRON PATH ==================${NC}"
crontab -l
echo

echo -e "${BLUE}================== SUDO COMMANDS CURRENT USER CAN EXECUTE ==================${NC}"
sudo -l
echo

echo -e "${BLUE}================== SUID BINARIES ==================${NC}"
find / -perm -4000 2>/dev/null
echo

echo -e "${BLUE}================== OPEN SCREEN SESSIONS ==================${NC}"
if command -v screen &> /dev/null; then
    screen -ls
else
    echo -e "${RED}screen command not found${NC}"
fi
echo

echo -e "${BLUE}================== LOGGED IN USERS ==================${NC}"
w
echo

echo -e "${BLUE}================== SENSITIVE FILES (DBs and SSH KEYS) ==================${NC}"
find / -name "*.db" -o -name "*.sqlite" -o -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.crt" 2>/dev/null
echo

echo -e "${BLUE}================== FILES WITH CAPABILITIES ==================${NC}"
getcap -r / 2>/dev/null
echo

echo -e "${BLUE}================== WORLD-WRITABLE FILES ==================${NC}"
find / -type f -perm -o+w 2>/dev/null
echo

echo -e "${BLUE}================== WORLD-WRITABLE DIRECTORIES ==================${NC}"
find / -type d -perm -o+w 2>/dev/null
echo

echo -e "${BLUE}================== ACTIVE NETWORK CONNECTIONS ==================${NC}"
netstat -tuln 2>/dev/null || ss -tuln
echo

echo -e "${BLUE}================== RECENTLY MODIFIED FILES ==================${NC}"
find / -type f -mtime -7 2>/dev/null
echo

echo -e "${BLUE}================== LOADED KERNEL MODULES ==================${NC}"
lsmod
echo

echo -e "${BLUE}================== USERS WITH UID 0 ==================${NC}"
awk -F: '($3 == 0) {print $1}' /etc/passwd
echo

echo -e "${BLUE}================== SSH CONFIGURATION ==================${NC}"
if [ -f /etc/ssh/sshd_config ]; then
    cat /etc/ssh/sshd_config
else
    echo -e "${RED}SSHD config not found${NC}"
fi
echo

echo -e "${BLUE}================== READABLE OR WRITABLE FILES OWNED BY ROOT ==================${NC}"
find / -user root \( -perm -u=r -o -perm -u=w \) 2>/dev/null
echo

echo -e "${BLUE}================== CHECKING FOR KNOWN VULNERABILITIES ==================${NC}"
kernel_version=$(uname -r)
cve_url="https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=$kernel_version"
echo -e "${YELLOW}Checking NVD for CVEs related to kernel version $kernel_version...${NC}"
curl -s "$cve_url" | grep -oP '"cveId":"CVE-[0-9-]+' | sed 's/"cveId":"//'
echo

echo -e "${BLUE}================== MONITORING SECURITY ADVISORIES ==================${NC}"
if [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    if [ "$DISTRIB_ID" = "Ubuntu" ]; then
        advisories_url="https://ubuntu.com/security/notices"
        echo -e "${YELLOW}Fetching latest security notices from $advisories_url...${NC}"
        curl -s "$advisories_url" | grep -oP 'CVE-[0-9-]+' | sort | uniq
    fi
fi
echo
