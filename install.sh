#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed to check the system OS, please contact the author!" >&2
    exit 1
fi
echo "The OS release is: $release"

arch() {
    case "$(uname -m)" in
    x86_64 | x64 | amd64) echo 'amd64' ;;
    i*86 | x86) echo '386' ;;
    armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
    armv7* | armv7 | arm) echo 'armv7' ;;
    armv6* | armv6) echo 'armv6' ;;
    armv5* | armv5) echo 'armv5' ;;
    s390x) echo 's390x' ;;
    *) echo -e "${green}Unsupported CPU architecture! ${plain}" && rm -f install.sh && exit 1 ;;
    esac
}

echo "arch: $(arch)"

os_version=""
os_version=$(grep -i version_id /etc/os-release | cut -d \" -f2 | cut -d . -f1)

if [[ "${release}" == "arch" ]]; then
    echo "Your OS is Arch Linux"
elif [[ "${release}" == "parch" ]]; then
    echo "Your OS is Parch linux"
elif [[ "${release}" == "manjaro" ]]; then
    echo "Your OS is Manjaro"
elif [[ "${release}" == "armbian" ]]; then
    echo "Your OS is Armbian"
elif [[ "${release}" == "opensuse-tumbleweed" ]]; then
    echo "Your OS is OpenSUSE Tumbleweed"
elif [[ "${release}" == "centos" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red} Please use CentOS 8 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "ubuntu" ]]; then
    if [[ ${os_version} -lt 20 ]]; then
        echo -e "${red} Please use Ubuntu 20 or higher version!${plain}\n" && exit 1
    fi
elif [[ "${release}" == "fedora" ]]; then
    if [[ ${os_version} -lt 36 ]]; then
        echo -e "${red} Please use Fedora 36 or higher version!${plain}\n" && exit 1
    fi
elif [[ "${release}" == "debian" ]]; then
    if [[ ${os_version} -lt 11 ]]; then
        echo -e "${red} Please use Debian 11 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "almalinux" ]]; then
    if [[ ${os_version} -lt 9 ]]; then
        echo -e "${red} Please use AlmaLinux 9 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "rocky" ]]; then
    if [[ ${os_version} -lt 9 ]]; then
        echo -e "${red} Please use Rocky Linux 9 or higher ${plain}\n" && exit 1
    fi
elif [[ "${release}" == "oracle" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red} Please use Oracle Linux 8 or higher ${plain}\n" && exit 1
    fi
else
    echo -e "${red}Your operating system is not supported by this script.${plain}\n"
    echo "Please ensure you are using one of the following supported operating systems:"
    echo "- Ubuntu 20.04+"
    echo "- Debian 11+"
    echo "- CentOS 8+"
    echo "- Fedora 36+"
    echo "- Arch Linux"
    echo "- Parch Linux"
    echo "- Manjaro"
    echo "- Armbian"
    echo "- AlmaLinux 9+"
    echo "- Rocky Linux 9+"
    echo "- Oracle Linux 8+"
    echo "- OpenSUSE Tumbleweed"
    exit 1

fi

install_base() {
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update && apt-get install -y -q wget curl tar tzdata
        ;;
    centos | almalinux | rocky | oracle)
        yum -y update && yum install -y -q wget curl tar tzdata
        ;;
    fedora)
        dnf -y update && dnf install -y -q wget curl tar tzdata
        ;;
    arch | manjaro | parch)
        pacman -Syu && pacman -Syu --noconfirm wget curl tar tzdata
        ;;
    opensuse-tumbleweed)
        zypper refresh && zypper -q install -y wget curl tar timezone
        ;;
    *)
        apt-get update && apt install -y -q wget curl tar tzdata
        ;;
    esac
}

gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}

# This function will be called when user installed x-ui out of security
config_after_install() {
    echo -e "${yellow}Install/update finished! For security it's recommended to modify panel settings ${plain}"
    if [[ ! -f "/etc/x-ui/x-ui.db" ]]; then
        local usernameTemp=$(gen_random_string 10)
        local passwordTemp=$(gen_random_string 10)
        local webBasePathTemp=$(gen_random_string 10)
        /usr/local/x-ui/x-ui setting -username ${usernameTemp} -password ${passwordTemp} -webBasePath ${webBasePathTemp}
        echo -e "This is a fresh installation, will generate random login info for security concerns:"
        echo -e "###############################################"
        echo -e "${green}Username: ${usernameTemp}${plain}"
        echo -e "${green}Password: ${passwordTemp}${plain}"
        echo -e "${green}WebBasePath: ${webBasePathTemp}${plain}"
        echo -e "###############################################"
        echo -e "${yellow}If you forgot your login info, you can type "x-ui settings" to check after installation${plain}"
    else
        echo -e "${yellow}This is your upgrade, will keep old settings. If you forgot your login info, you can type "x-ui settings" to check${plain}"
    fi
    /usr/local/x-ui/x-ui migrate
}

install_x-ui() {
    cd /usr/local/

    if [ $# == 0 ]; then
        last_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}Failed to fetch x-ui version, it maybe due to Github API restrictions, please try it later${plain}"
            exit 1
        fi
        echo -e "Got x-ui latest version: ${last_version}, beginning the installation..."
        wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz https://github.com/MHSanaei/3x-ui/releases/download/${last_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading x-ui failed, please be sure that your server can access Github ${plain}"
            exit 1
        fi
    else
        last_version=$1
        url="https://github.com/MHSanaei/3x-ui/releases/download/${last_version}/x-ui-linux-$(arch).tar.gz"
        echo -e "Beginning to install x-ui $1"
        wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Download x-ui $1 failed,please check the version exists ${plain}"
            exit 1
        fi
    fi

    if [[ -e /usr/local/x-ui/ ]]; then
        systemctl stop x-ui
        rm /usr/local/x-ui/ -rf
    fi

    tar zxvf x-ui-linux-$(arch).tar.gz
    rm x-ui-linux-$(arch).tar.gz -f
    cd x-ui
    chmod +x x-ui

    # Check the system's architecture and rename the file accordingly
    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi

    chmod +x x-ui bin/xray-linux-$(arch)
    cp -f x-ui.service /etc/systemd/system/
    wget --no-check-certificate -O /usr/bin/x-ui https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh
    chmod +x /usr/local/x-ui/x-ui.sh
    chmod +x /usr/bin/x-ui
    config_after_install

    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui
    echo -e "${green}x-ui ${last_version}${plain} installation finished, it is running now..."
    echo -e ""
    echo -e "x-ui control menu usages: "
    echo -e "----------------------------------------------"
    echo -e "SUBCOMMANDS:"
    echo -e "x-ui              - Admin Management Script"
    echo -e "x-ui start        - Start"
    echo -e "x-ui stop         - Stop"
    echo -e "x-ui restart      - Restart"
    echo -e "x-ui status       - Current Status"
    echo -e "x-ui settings     - Current Settings"
    echo -e "x-ui enable       - Enable Autostart on OS Startup"
    echo -e "x-ui disable      - Disable Autostart on OS Startup"
    echo -e "x-ui log          - Check logs"
    echo -e "x-ui banlog       - Check Fail2ban ban logs"
    echo -e "x-ui update       - Update"
    echo -e "x-ui custom       - custom version"
    echo -e "x-ui install      - Install"
    echo -e "x-ui uninstall    - Uninstall"
    echo -e "----------------------------------------------"
}

echo -e "${green}Running...${plain}"
install_base
install_x-ui $1

cd /root
apt-get install sqlite3 openssl jq -y
openssl req -x509 -newkey rsa:4096 -nodes -sha256 -keyout /etc/ssl/private/private.key -out /etc/ssl/certs/public.key -days 3650 -subj "/CN=APP"
next_id=$(($(sqlite3 /etc/x-ui/x-ui.db "SELECT IFNULL(MAX(id), 0) FROM settings;") + 1))
second_id=$((next_id + 1))
sqlite3 /etc/x-ui/x-ui.db "INSERT INTO settings VALUES (${next_id}, 'webKeyFile', '/etc/ssl/private/private.key'); INSERT INTO settings VALUES (${second_id}, 'webCertFile', '/etc/ssl/certs/public.key');"
x-ui restart
username=$(sqlite3 /etc/x-ui/x-ui.db 'SELECT username FROM users')
password=$(sqlite3 /etc/x-ui/x-ui.db 'SELECT password FROM users')
webBasePath=$(sqlite3 /etc/x-ui/x-ui.db 'SELECT value FROM settings WHERE key="webBasePath"')

while [[ "$(curl -k -b cookie -c cookie "https://localhost:2053${webBasePath}server/getNewX25519Cert" -X "POST" -H "X-Requested-With: XMLHttpRequest" | jq -r ".success")" == "false" ]]; do
	curl -k -b cookie -c cookie "https://localhost:2053${webBasePath}login" -d "username=${username}&password=${password}"
done

response=$(curl -k -b cookie -c cookie "https://localhost:2053${webBasePath}server/getNewX25519Cert" -X "POST" -H "X-Requested-With: XMLHttpRequest")
echo $(echo $response | jq -r ".obj.privateKey") | tee privateKey
echo $(echo $response | jq -r ".obj.publicKey") > publicKey
echo $(pwd)
echo $(ls)

cat << 'EOF' | sudo tee /usr/bin/randomUUID > /dev/null
#!/bin/bash
uuid="xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
for (( i=0; i<${#uuid}; i++ )); do
  case "${uuid:i:1}" in
    x) uuid="${uuid:0:i}$(printf '%x' $((RANDOM % 16)))${uuid:i + 1}" ;;
    y) uuid="${uuid:0:i}$(printf '%x' $((RANDOM % 4 + 8)))${uuid:i + 1}" ;;
  esac
done
echo "$uuid"
EOF

cat << 'EOF' | sudo tee /usr/bin/randomShortId > /dev/null
#!/bin/bash
lengths=(2 4 6 8 10 12 14 16)
seq="0123456789abcdef"
for ((i=${#lengths[@]}-1; i>0; i--)); do
    j=$((RANDOM % (i + 1)))
    temp=${lengths[i]}
    lengths[i]=${lengths[j]}
    lengths[j]=$temp
done
shortIds=()
for length in ${lengths[@]}; do
    random_string=""
    for ((i=0; i<length; i++)); do
        random_string+=${seq:RANDOM%${#seq}:1}
    done
    shortIds+=($random_string)
done
jsonOutput=$(printf '%s\n' "${shortIds[@]}" | jq -R . | jq -s .)
encodedOutput=$(printf '%s' "$jsonOutput" | jq -s -R @uri)
echo $encodedOutput | sed 's/^"\(.*\)"$/\1/' | sed 's/%20/%20%20%20/g' | sed 's/%5D/%20%20%20%20/g'
EOF

echo "tr -dc 'a-z0-9' < /dev/urandom | head -c 16" > /usr/bin/randomSubId

sudo chmod +x /usr/bin/randomUUID
sudo chmod +x /usr/bin/randomShortId
sudo chmod +x /usr/bin/randomSubId

read -p "Enter server name (Ex: RU-1): " remark

curl curl https://localhost:2053${webBasePath}panel/inbound/add -b cookie -d "up=0&down=0&total=0&remark=${remark}&enable=true&expiryTime=0&listen=&port=443&protocol=vless&settings=%7B%0A%20%20%22clients%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22id%22%3A%20%22$(randomUUID)%22%2C%0A%20%20%20%20%20%20%22flow%22%3A%20%22%22%2C%0A%20%20%20%20%20%20%22email%22%3A%20%22GENESIS%22%2C%0A%20%20%20%20%20%20%22limitIp%22%3A%200%2C%0A%20%20%20%20%20%20%22totalGB%22%3A%200%2C%0A%20%20%20%20%20%20%22expiryTime%22%3A%200%2C%0A%20%20%20%20%20%20%22enable%22%3A%20false%2C%0A%20%20%20%20%20%20%22tgId%22%3A%20%22%22%2C%0A%20%20%20%20%20%20%22subId%22%3A%20%22$(randomSubId)%22%2C%0A%20%20%20%20%20%20%22reset%22%3A%200%0A%20%20%20%20%7D%0A%20%20%5D%2C%0A%20%20%22decryption%22%3A%20%22none%22%2C%0A%20%20%22fallbacks%22%3A%20%5B%5D%0A%7D&streamSettings=%7B%0A%20%20%22network%22%3A%20%22tcp%22%2C%0A%20%20%22security%22%3A%20%22reality%22%2C%0A%20%20%22externalProxy%22%3A%20%5B%5D%2C%0A%20%20%22realitySettings%22%3A%20%7B%0A%20%20%20%20%22show%22%3A%20false%2C%0A%20%20%20%20%22xver%22%3A%200%2C%0A%20%20%20%20%22dest%22%3A%20%22cloudflare.com%3A443%22%2C%0A%20%20%20%20%22serverNames%22%3A%20%5B%0A%20%20%20%20%20%20%22cloudflare.com%22%2C%0A%20%20%20%20%20%20%22www.cloudflare.com%22%0A%20%20%20%20%5D%2C%0A%20%20%20%20%22privateKey%22%3A%20%22$(cat privateKey)%22%2C%0A%20%20%20%20%22minClient%22%3A%20%22%22%2C%0A%20%20%20%20%22maxClient%22%3A%20%22%22%2C%0A%20%20%20%20%22maxTimediff%22%3A%200%2C%0A%20%20%20%20%22shortIds%22%3A%20$(randomShortId)%5D%2C%0A%20%20%20%20%22settings%22%3A%20%7B%0A%20%20%20%20%20%20%22publicKey%22%3A%20%22$(cat publicKey)%22%2C%0A%20%20%20%20%20%20%22fingerprint%22%3A%20%22random%22%2C%0A%20%20%20%20%20%20%22serverName%22%3A%20%22%22%2C%0A%20%20%20%20%20%20%22spiderX%22%3A%20%22%2F%22%0A%20%20%20%20%7D%0A%20%20%7D%2C%0A%20%20%22tcpSettings%22%3A%20%7B%0A%20%20%20%20%22acceptProxyProtocol%22%3A%20false%2C%0A%20%20%20%20%22header%22%3A%20%7B%0A%20%20%20%20%20%20%22type%22%3A%20%22none%22%0A%20%20%20%20%7D%0A%20%20%7D%0A%7D&sniffing=%7B%0A%20%20%22enabled%22%3A%20true%2C%0A%20%20%22destOverride%22%3A%20%5B%0A%20%20%20%20%22http%22%2C%0A%20%20%20%20%22tls%22%2C%0A%20%20%20%20%22quic%22%2C%0A%20%20%20%20%22fakedns%22%0A%20%20%5D%2C%0A%20%20%22metadataOnly%22%3A%20false%2C%0A%20%20%22routeOnly%22%3A%20false%0A%7D" -k

echo
echo -e "${green}URL: https://$(hostname -i):2053${webBasePath}${plain}"
echo -e "${green}Username: ${username}${plain}"
echo -e "${green}Password: ${password}${plain}"
echo "v1.1"