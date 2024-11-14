#!/usr/bin/env bash
#==========================================================================================
#
# SCRIPT NAME        :     manager.sh
#
# AUTHOR             :     Louis GAMBART
# CREATION DATE      :     2023.11.21
# RELEASE            :     1.1.0
# USAGE SYNTAX       :     .\manager.sh
#
# SCRIPT DESCRIPTION :     This script is used to manage a reverse proxy configuration for nginx docker
#
#==========================================================================================
#
#                 - RELEASE NOTES -
# v1.0.0  2023.11.21 - Louis GAMBART - Initial version
# v1.1.0  2024.02.27 - Louis GAMBART - Rework to follow base script
#
#==========================================================================================


#####################
#                   #
#  I - COLOR CODES  #
#                   #
#####################

No_Color='\033[0m'      # No Color
Red='\033[0;31m'        # Red
Yellow='\033[0;33m'     # Yellow
Green='\033[0;32m'      # Green
Blue='\033[0;34m'       # Blue


####################
#                  #
#  II - VARIABLES  #
#                  #
####################

NGINX_CONF_DIR=$NGINX_CONF_DIR_REPLACE
NGINX_VAR_DIR=$NGINX_LOG_DIR_REPLACE
NGINX_SSL_DIR=$NGINX_SSL_DIR_REPLACE
SCRIPT_NAME="manager.sh"


#####################
#                   #
#  III - FUNCTIONS  #
#                   #
#####################

add_service () {
    # Add a service to the reverse proxy
    # :param $1: service name
    # :param $2: server name
    # :param $3: server ip
    # :param $4: is https
    # :param $5: allow origin

    echo -e -n "\n${Yellow}Adding service $1 to reverse proxy...${No_Color}"

    # check if https
    if [ "$4" = 'y' ]; then
        service_type="https"
    elif [ "$4" = 'n' ]; then
        service_type="http"
    else
        echo -e " ${Red} ERR - Invalid input for https/http${No_Color}"
        exit 1
    fi

    # create ssl certificate
    Country=$(grep COUNTRY "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    State=$(grep STATE "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    Location=$(grep LOCATION "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    Orga=$(grep ORGANIZATION-GLOBAL "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    OrgaUnit=$(grep ORGANIZATION-UNIT "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    Days=$(grep DAYS "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)

    {
        echo "[req]"
        echo "distinguished_name = req_distinguished_name"
        echo "x509_extensions = v3_req"
        echo "prompt = no"
        echo "[req_distinguished_name]"
        echo "C = $Country"
        echo "ST = $State"
        echo "L = $Location"
        echo "O = $Orga"
        echo "OU = $OrgaUnit"
        echo "[v3_req]"
        echo "keyUsage = critical, digitalSignature, keyAgreement"
        echo "extendedKeyUsage = serverAuth"
        echo "subjectAltName = @alt_names"
        echo "[alt_names]"
        echo "DNS.1 = $2"
    } >> "$NGINX_SSL_DIR"/"$2".ext.cnf

    openssl req -new -newkey rsa:4096 -sha256 -days "$Days" -nodes -x509 -keyout "$NGINX_SSL_DIR"/"$2".key -out "$NGINX_SSL_DIR"/"$2".crt -subj "/C=$Country/ST=$State/L=$Location/O=$Orga/OU=$OrgaUnit/CN=$2" -config "$NGINX_SSL_DIR"/"$2".ext.cnf > /dev/null 2>&1
    rm "$NGINX_SSL_DIR"/"$2".ext.cnf

    # create log dir
    mkdir -p "$NGINX_VAR_DIR"/"$2"

    # create conf file
    cat >> "$NGINX_CONF_DIR"/"$2".conf <<EOF
map \$http_upgrade \$connection_upgrade {
	default upgrade;
	'' close;
}

# $1
server {
    listen 80;
    server_name $2;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;

    ssl_certificate $NGINX_SSL_DIR/$2.crt;
    ssl_certificate_key $NGINX_SSL_DIR/$2.key;

    server_name $2;

    error_log $NGINX_VAR_DIR/$2/error.log;
    access_log $NGINX_VAR_DIR/$2/access.log;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";
    add_header Referrer-Policy "no-referrer";
    add_header Access-Control-Allow-Origin "$5";
    add_header Cross-Origin-Embedder-Policy "require-corp";
    add_header Cross-Origin-Opener-Policy "same-origin";
    add_header Cross-Origin-Resource-Policy "same-site";

    add_header Permissions-Policy ();
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https: http:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'";

    proxy_cookie_flags ~ secure httponly samesite=strict;

    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Scheme \$scheme;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Real-IP \$remote_addr;

        proxy_pass $service_type://$3;
    }
}
EOF
    echo -e "${Green} OK${No_Color}"
    echo -e -n "${Yellow}Restarting nginx...${No_Color}"
    nginx -s reload
    echo -e "${Green} OK${No_Color}\n"
    echo -e "If you want to add options to the service, use the following command: ${Blue}nano $NGINX_CONF_DIR/$2.conf${No_Color}"
    echo -e "You can find the certificate and the private key in the following directory: ${Blue}$NGINX_SSL_DIR${No_Color}"
}


remove_service () {
    # Remove a service from the reverse proxy
    # :param $1: server name

    # check if service exists
    echo -e -n "${Yellow}Checking if service exists...${No_Color}"

    if [ ! -f $NGINX_CONF_DIR/"$1".conf ]; then
        echo -e "${Red} Service does not exist${No_Color}"
        return
    fi
    echo -e "${Green} OK${No_Color}"

    echo -e "${Yellow}You are about to remove the service $1 from the reverse proxy${No_Color}"
    read -r -p "Are you sure? [y/n] " removal_confirmation
    if [ "$removal_confirmation" = 'y' ]; then
        rm -rf "${NGINX_CONF_DIR:?}/$1".conf
        rm -rf "${NGINX_VAR_DIR:?}/$1"
        rm -rf "${NGINX_SSL_DIR:?}/$1".crt
        rm -rf "${NGINX_SSL_DIR:?}/$1".key

        echo -e "${Green}Service $1 removed from reverse proxy${No_Color}"
        echo -e -n "${Yellow}Restarting nginx...${No_Color}"
        nginx -s reload
        echo -e "${Green} OK${No_Color}"
    elif [ "$removal_confirmation" = 'n' ]; then
        echo -e "${Green}Service $1 not removed from reverse proxy${No_Color}"
        return
    else
        echo -e "${Red} ERR - Invalid input${No_Color}"
        return
    fi
}


list_services () {
    # List all services in the reverse proxy

    echo -e -n "\n${Yellow}Listing services...${No_Color}"

    for file in "$NGINX_CONF_DIR"/*.conf; do
        if [ ! -f "$file" ]; then
            echo -e "${Red} No services found${No_Color}"
            exit 1
        fi
        echo -e "${Green} OK${No_Color}"
        echo -e "${Green}$(basename "$file" .conf)${No_Color}"
        server_ip=$(pcregrep -o1 'proxy_pass http[s]?://([^/]*)(?!;)' "$file" | sed 's/;$//')
        echo -e "  IP: ${Green}$server_ip${No_Color}"
    done
}


check_service () {
    # Check if a service is already in the reverse proxy
    # :param $1: service name
    # :return: 0 if exists, 1 if not

    if [ -f "$NGINX_CONF_DIR"/"$1".conf ]; then
        return 0
    else
        return 1
    fi
}


backup_nginx () {
    # Backup nginx configuration
    tar -czf ./nginx_backup.tar.gz /etc/nginx > /dev/null 2>&1
}


address_check () {
    # Check if the address is valid
    # :param $1: address
    # :return: 0 if valid, 1 if not

    #check if : in $1
    if [[ $1 =~ .*":".* ]]; then
        address=${1%:*}
        port=${1#*:}
        if [[ "$address" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$ ]] && [[ "$port" -ge 0 ]] && [[ "$port" -le 65536 ]]; then
            return 0
        else
            return 1
        fi
    else
        if [[ "$1" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$ ]]; then
            return 0
        else
            return 1
        fi
    fi
}


print_help () {
    # Print help message
    echo -e """
    ${Green} SYNOPSIS
        ${SCRIPT_NAME} [-hv]

     DESCRIPTION
        This script is used to manage a nginx reverse proxy. The script will also install nginx if it is not installed.

     OPTIONS
        -h, --help         Print the help message
        -v, --version      Print the script version
    ${No_Color}
    """
}


print_version () {
    # Print version message
    echo -e """
    ${Green}
    version       ${SCRIPT_NAME} 1.1.1
    author        Louis GAMBART (https://louis-gambart.fr)
    license       GNU GPLv3.0
    script_id     0
    """
}


#########################
#                       #
#  IV - SCRIPT OPTIONS  #
#                       #
#########################

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -h|--help)
            print_help
            exit 0
            ;;
        -v|--version)
            print_version
            exit 0
            ;;
        *)
            echo -e "${Red}Unknown option: $key${No_Color}"
            print_help
            exit 0
            ;;
    esac
    shift
done


####################
#                  #
#  V - ROOT CHECK  #
#                  #
####################

echo -e -n "${Yellow}Checking if you are root...${No_Color}"
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${Red} ERR - Please run the script as root${No_Color}"
    exit 1
elif [[ -n ${SUDO_USER} ]]; then
    echo -e "${Red} ERR - Please run the script as root, without SUDO user${No_Color}"
    exit 1
else
    echo -e "${Green} OK${No_Color}\n"
fi


########################
#                      #
#  VIII - MAIN SCRIPT  #
#                      #
########################

PS3='Please enter your choice: '
select option in "Add service" "Remove service" "List services" "Backup nginx" "Exit"; do
    case $option in
        "Add service")
            echo ""
            read -r -p "Enter server name like service.clubnix.fr: " server_name
            result=$(echo "$server_name" | pcregrep '(?=^.{1,254}$)(^(?>(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)')
            if [[ -z "$server_name" ]]; then
                echo -e "${Red}No server name entered${No_Color}"
                break
            elif [[ -z "$result" ]]; then
                echo -e "${Red}Invalid server name${No_Color}"
                break
            elif check_service "$server_name"; then
                echo -e "${Red}Service already exists${No_Color}"
                break
            fi
            read -r -p "Enter IP address of the server and the port if necessary: " server_ip
            if ! address_check "$server_ip"; then
                echo -e "${Red}Invalid address${No_Color}"
                break
            fi
            read -r -p "Enter the service name: " service_name
            read -r -p "Is the service a https service? [y/n]: " https
            read -r -p "Enter the allow origin (if you don't know, enter *): " allow_origin

            add_service "$service_name" "$server_name" "$server_ip" "$https" "$allow_origin"
            break
            ;;
        "Remove service")
            list_services
            echo ""
            read -r -p "Enter server name to remove: " server_name
            remove_service "$server_name"
            break
            ;;
        "List services")
            list_services
            break
            ;;
        "Backup nginx")
            echo -e -n "\n${Yellow}Backing up nginx...${No_Color}"
            backup_nginx
            echo -e "${Green} OK${No_Color}"
            break
            ;;
        "Exit")
            break
            ;;
        *)
            echo -e "${Red}Invalid option${No_Color} $REPLY"
            break
            ;;
    esac
done
