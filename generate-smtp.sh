#!/bin/bash

while getopts ":s:d:u:p:o:a:v:c:" opt; do
  case $opt in
  s)
    SERVER_NAME="$OPTARG"
    echo "SERVER_NAME=${OPTARG}" | tee -a install.log
    ;;
  d)
    DOMAIN_NAME="$OPTARG"
    echo "DOMAIN_NAME=${OPTARG}" | tee -a install.log
    ;;
  u)
    SQL_USER="$OPTARG"
    echo "SQL_USER=${OPTARG}" | tee -a install.log
    ;;
  p)
    SQL_PASSWORD="$OPTARG"
    echo "SQL_PASSWORD=${OPTARG}" | tee -a install.log
    ;;
  o)
    POSTFIX_PASSWORD="$OPTARG"
    echo "POSTFIX_PASSWORD=${OPTARG}" | tee -a install.log
    ;;
  a)
    MAIL_DATABASE="$OPTARG"
    echo "MAIL_DATABASE=${OPTARG}" | tee -a install.log
    ;;
  v)
    INSTALL_ANTIVIRUS="$OPTARG"
    echo "INSTALL_ANTIVIRUS=${OPTARG}" | tee -a install.log
    ;;
  c)
    EMAIL_CONFIG="$OPTARG"
    echo "EMAIL_CONFIG=${OPTARG}" | tee -a install.log
    ;;
  \?)
    echo "Invalid option -$OPTARG" >&2
    ;;
  esac
done

[[ -z "${MAIL_DATABASE}" ]] && {
  MAIL_DATABASE="mail"
}

[[ -z "${DOMAIN_NAME}" ]] && {
  echo "Domain was not setup"
  exit 127
}

[[ -z "${SERVER_NAME}" ]] && {
  echo "Server Name was not setup"
  exit 127
}

hostname "${SERVER_NAME}.${DOMAIN_NAME}"
hostname
echo '' >install.log

output() {
  echo "$1" | ts ["%F %H:%M:%S"] | tee -a install.log
}

checkForErrors() {
  if [ $? -ne "0" ]; then
    printf "${1}"
    exit 127
  fi
}

updateSystem() {

  localHostname="${SERVER_NAME}.${DOMAIN_NAME}"
  echo "Getting the latest packages" | tee -a install.log
  set -o errexit # abort on nonzero exitstatus
  set -o nounset # abort on unbound variable

  sudo apt-get update | tee -a install.log
  sudo apt-get upgrade --assume-yes | tee -a install.log
  sudo apt-get install --assume-yes \
    moreutils \
    php-fpm \
    php-mysql \
    php-mbstring \
    php-imap \
    mutt \
    sipcalc \
    python3-pip |
    tee -a install.log
  localDomain=${DOMAIN_NAME}
}

installCertBot() {
  sudo add-apt-repository universe | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo apt-get update --assume-yes | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo apt-get install --assume-yes \
    certbot \
    python3-certbot-nginx |
    ts |
    tee -a install.log
  wget -O - https://get.acme.sh | sh -s email=postfix@${localDomain} | ts ["%F %H:%M:%S"] | tee -a install.log
}

generateCertificate() {
  [[ -z "${localDomain}" ]] && {
    echo "Local domain not setup"
    exit 127
  }

  echo "Generating domain certificate for domain ${localHostname}" | ts ["%F %H:%M:%S"] | tee -a /tools/install.log
  /root/.acme.sh/acme.sh --issue --alpn --standalone -d ${localHostname} --home /usr/share/ca-certificates --post-hook "cat /usr/share/ca-certificates/${localHostname}/${localHostname}.key /usr/share/ca-certificates/${localHostname}/${localHostname}.cer > /usr/share/ca-certificates/${localHostname}/${localHostname}.pem" --reloadcmd 'systemctl restart postfix; systemctl restart dovecot; systemctl restart mysql; systemctl restart nginx' | ts ["%F %H:%M:%S"] | tee -a install.log
}

installNginx() {
  echo "Installing NGINX..." | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo apt-get install --assume-yes \
    ca-certificates \
    nginx-full |
    ts ["%F %H:%M:%S"] |
    tee -a install.log
  echo "Adding NGINX firewall rule..." | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo ufw allow http | ts ["%F %H:%M:%S"] | tee -a install.log
}

setupNginx() {
  echo "Setting up NGINX Web server..." | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cat <<_EOF_ >/etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
  worker_connections 768;
}

http {
  ### START HTTP SETTINGS ###
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
  # server_tokens off;
  # server_names_hash_bucket_size 64;
  # server_name_in_redirect off;
  ### END HTTP SETTINGS ###
  ### START SSL SETTINGS ###  
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
  ### END SSL SETTINGS ###

  ### START GZIP SETTINGS ###  
  gzip on;
  # gzip_vary on;
  # gzip_proxied any;
  # gzip_comp_level 6;
  # gzip_buffers 16 8k;
  # gzip_http_version 1.1;
  # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
  ### END GZIP SETTINGS ###

  ### START VIRTUAL_HOSTS SETTINGS ###  
  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
  ### END VIRTUAL_HOSTS SETTINGS ###
}  
_EOF_
  cat <<_EOF_ >/etc/nginx/conf.d/security-headers.conf
add_header Content-Security-Policy "default-src 'self'; upgrade-insecure-requests; block-all-mixed-content";
_EOF_
  if test -f "/etc/nginx/sites-enabled/default"; then
    sudo rm /etc/nginx/sites-enabled/default | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  cat >/etc/nginx/sites-enabled/postfixadmin <<_EOF_
server {
    listen 80;
    listen [::]:80;
    server_name ${localHostname}; 
    return 301 https://${localHostname}\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    # SSL
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:20m;
    ssl_session_tickets off;
    ssl_prefer_server_ciphers on;

    ssl_certificate     /usr/share/ca-certificates/${localHostname}/fullchain.cer;
    ssl_certificate_key /usr/share/ca-certificates/${localHostname}/${localHostname}.key;
    ssl_trusted_certificate /usr/share/ca-certificates/${localHostname}/ca.cer;
    
    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    server_name ${localHostname};
    
    root /var/www/postfixadmin/public;

    index index.html index.htm index.php;
    
    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
_EOF_
}

# Predicate that returns exit status 0 if the database root password
# is set, a nonzero exit status otherwise.
is_mysql_root_password_set() {
  ! mysqladmin --user=root status >/dev/null 2>&1
}

# Predicate that returns exit status 0 if the mysql(1) command is available,
# nonzero exit status otherwise.
is_mysql_command_available() {
  which mysql >/dev/null 2>&1
}

check_sql_active() {
  sudo systemctl is-active --quiet mysql
  if [ $? -ne 0 ]; then
    echo "Attempting to restart MySql Service"
    sudo systemctl restart mysql
    if [ $? -ne 0 ]; then
      echo "MySql service is not running, cannot proceed"
      exit 127
    fi
  fi
}

installDatabase() {
  echo "Installing MariaDB..." | ts ["%F %H:%M:%S"] | tee -a install.log
  [[ -z "${SQL_USER}" ]] && {
    echo "SQL User was not set"
    exit 127
  }
  [[ -z "${SQL_PASSWORD}" ]] && {
    echo "SQL User was not set"
    exit 127
  }

  sudo apt-get install --assume-yes \
    mariadb-server |
    ts ["%F %H:%M:%S"] |
    tee -a install.log
}

secureDatabase() {
  echo "Securing MariaDB..." | ts ["%F %H:%M:%S"] | tee -a install.log

  if ! is_mysql_command_available; then
    echo "The MySQL/MariaDB client mysql is not installed."
    exit 1
  fi

  if ! is_mysql_root_password_set; then
    echo "Database root password is not set, creating"
    mysql --user=root <<_EOF_
UPDATE mysql.user SET Password=PASSWORD('${SQL_PASSWORD}') WHERE User='root';
FLUSH PRIVILEGES;
_EOF_
  fi
  mysql --user=root -p${SQL_PASSWORD} <<_EOF_
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${SQL_PASSWORD}';
DROP USER IF EXISTS '${SQL_USER}'@'%';
DROP USER IF EXISTS '${SQL_USER}'@'localhost';
DROP USER IF EXISTS '${SQL_USER}'@'127.0.0.1';
CREATE USER IF NOT EXISTS '${SQL_USER}'@'%' IDENTIFIED BY '${SQL_PASSWORD}';
CREATE USER IF NOT EXISTS '${SQL_USER}'@'localhost' IDENTIFIED BY '${SQL_PASSWORD}';
CREATE USER IF NOT EXISTS '${SQL_USER}'@'127.0.0.1' IDENTIFIED BY '${SQL_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO '${SQL_USER}'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO '${SQL_USER}'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO '${SQL_USER}'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;
_EOF_

  checkForErrors "Could not create users"
  sudo ufw allow 3306 | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart mysql | ts ["%F %H:%M:%S"] | tee -a install.log
  check_sql_active
}

setupDatabase() {
  echo ${localHostname}
  echo "Setting up MariaDB SQL server..." | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mariadb.conf.d/50-server.cnf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cat <<_EOF_ >/etc/mysql/mariadb.conf.d/50-server.cnf
[server]

[mysqld]

user            = mysql
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
port            = 3306
basedir         = /usr
datadir         = /var/lib/mysql
tmpdir          = /tmp
lc-messages-dir = /usr/share/mysql
skip-external-locking
bind-address            = 0.0.0.0
key_buffer_size         = 16M
max_allowed_packet      = 16M
thread_stack            = 192K
thread_cache_size       = 8
myisam_recover_options  = BACKUP
query_cache_limit       = 1M
query_cache_size        = 16M
general_log_file        = /var/log/mysql/mysql.log
general_log             = 1
log_error               = /var/log/mysql/error.log
expire_logs_days        = 10
max_binlog_size   = 100M
ssl-ca=/usr/share/ca-certificates/${localHostname}/ca.cer
ssl-cert=/usr/share/ca-certificates/${localHostname}/${localHostname}.cer
ssl-key=/usr/share/ca-certificates/${localHostname}/${localHostname}.key
ssl-cipher=DHE-RSA-AES256-SHA:AES256-SHA:AES128-SHA
ssl=off
character-set-server  = utf8mb4
collation-server      = utf8mb4_general_ci
[embedded]
[mariadb]
[mariadb-10.1]
_EOF_
}

installPostfix() {
  echo "Installing Postfix..." >>install.log
  debconf-set-selections <<<"postfix postfix/mailname string $localHostname"
  debconf-set-selections <<<"postfix postfix/main_mailer_type string 'Internet Site'"

  sudo apt-get install --assume-yes \
    postfix \
    postfix-mysql \
    mariadb-client \
    postfix-policyd-spf-python \
    postfix-pcre |
    ts ["%F %H:%M:%S"] |
    tee -a install.log
}

setupPostfix() {
  echo "Setting up Postfix..." | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/postfix/main.cf /etc/postfix/main.cf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/postfix/master.cf /etc/postfix/master.cf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cat >/etc/postfix/main.cf <<_EOF_
# See /usr/share/postfix/main.cf.dist for a commented, more complete version
# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname
compatibility_level=2
smtpd_banner = $localHostname ESMTP ${localHostname}
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# TLS parameters
smtpd_tls_cert_file=/usr/share/ca-certificates/${localHostname}/fullchain.cer
smtpd_tls_CAfile=/usr/share/ca-certificates/${localHostname}/ca.cer
smtpd_tls_key_file=/usr/share/ca-certificates/${localHostname}/${localHostname}.key
smtpd_use_tls=yes
smtpd_tls_auth_only = yes
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtpd_tls_received_header = yes
smtpd_tls_loglevel = 1
smtpd_sasl_security_options = noanonymous, noplaintext
smtpd_sasl_tls_security_options = noanonymous


# Authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc package for
# information on enabling SSL in the smtp client.

# Restrictions
smtpd_helo_restrictions =
        permit_mynetworks,
        permit_sasl_authenticated,
        reject_invalid_helo_hostname,
        reject_non_fqdn_helo_hostname,
        reject_unknown_helo_hostname

smtpd_recipient_restrictions = 
        permit_mynetworks,
        permit_sasl_authenticated,
        reject_unauth_destination,
        check_policy_service unix:private/policyd-spf,
        check_policy_service inet:127.0.0.1:10023,
        reject_invalid_hostname,
        reject_non_fqdn_hostname,
        reject_non_fqdn_sender,
        reject_non_fqdn_recipient,
        reject_unknown_sender_domain,
        reject_rbl_client sbl.spamhaus.org,
        reject_rbl_client cbl.abuseat.org

smtpd_sender_restrictions =
        permit_sasl_authenticated,
        permit_mynetworks,
        reject_non_fqdn_sender,
        reject_unknown_sender_domain
smtpd_relay_restrictions =
        permit_mynetworks,
        permit_sasl_authenticated,
        defer_unauth_destination

# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc package for
# information on enabling SSL in the smtp client.

myhostname = ${localDomain}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydomain = ${localDomain}
myorigin = \$mydomain
mydestination = localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# Handing off local delivery to Dovecot's LMTP, and telling it where to store mail
virtual_transport = lmtp:unix:private/dovecot-lmtp
dovecot_destination_recipient_limit = 1

# This specifies where the virtual mailbox folders will be located.
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_maps = mysql:/etc/postfix/mysql_virtual_mailbox_maps.cf, mysql:/etc/postfix/mysql_virtual_mailbox_domainaliases_maps.cf
virtual_uid_maps = static:150
virtual_gid_maps = static:8
virtual_alias_maps = mysql:/etc/postfix/mysql_virtual_alias_maps.cf, mysql:/etc/postfix/mysql_virtual_alias_domainaliases_maps.cf
virtual_mailbox_domains = mysql:/etc/postfix/mysql_virtual_domains_maps.cf
smtpd_sender_login_maps = mysql:/etc/postfix/mysql_virtual_sender_login_maps.cf

# Getting rid of unwanted headers. See: https://posluns.com/guides/header-removal/
header_checks = regexp:/etc/postfix/header_checks
# getting rid of x-original-to
enable_original_recipient = no

# Even more Restrictions and MTA params
disable_vrfy_command = yes
strict_rfc821_envelopes = yes
#smtpd_etrn_restrictions = reject
#smtpd_reject_unlisted_sender = yes
#smtpd_reject_unlisted_recipient = yes
smtpd_delay_reject = yes
smtpd_helo_required = yes
smtp_always_send_ehlo = yes
#smtpd_hard_error_limit = 1
smtpd_timeout = 30s
smtp_helo_timeout = 15s
smtp_rcpt_timeout = 15s
smtpd_recipient_limit = 40
minimal_backoff_time = 180s
maximal_backoff_time = 3h

# Reply Rejection Codes
invalid_hostname_reject_code = 550
non_fqdn_reject_code = 550
unknown_address_reject_code = 550
unknown_client_reject_code = 550
unknown_hostname_reject_code = 550
unverified_recipient_reject_code = 550
unverified_sender_reject_code = 550

# Milter configuration
# OpenDKIM
milter_default_action = accept
# Postfix ≥ 2.6 milter_protocol = 6, Postfix ≤ 2.5 milter_protocol = 2
milter_protocol = 6
smtpd_milters = inet:localhost:8891,local:opendmarc/opendmarc.sock
non_smtpd_milters = \$smtpd_milters
_EOF_

  [[ "$INSTALL_ANTIVIRUS" == "yes" ]] && {
    cat >>/etc/postfix/main.cf <<_EOF_
content_filter = amavis:127.0.0.1:10024
_EOF_
  }

  cat >/etc/postfix/master.cf <<_EOF_
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master" or
# on-line: http://www.postfix.org/master.5.html).
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================
smtp      inet  n       -       y       -       -       smtpd
  -o content_filter=spamassassin
#smtp      inet  n       -       y       -       1       postscreen
#smtpd     pass  -       -       y       -       -       smtpd
#dnsblog   unix  -       -       y       -       0       dnsblog
#tlsproxy  unix  -       -       y       -       0       tlsproxy
submission inet n       -       y      -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_reject_unlisted_recipient=no
  -o content_filter=spamassassin
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       -       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o content_filter=spamassassin
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
#628       inet  n       -       y       -       -       qmqpd
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
#qmgr     unix  n       -       n       300     1       oqmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
        -o syslog_name=postfix/\$service_name
#       -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d \${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a\$sender - \$nexthop!rmail (\$recipient)
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r \$nexthop (\$recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t\$nexthop -f\$sender \$recipient
scalemail-backend unix  -       n       n       -       2       pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store \${nexthop} \${user} \${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  \${nexthop} \${user}
policyd-spf  unix  -       n       n       -       0       spawn
    user=policyd-spf argv=/usr/bin/policyd-spf
spamassassin unix -     n       n       -       -       pipe
    user=spamd argv=/usr/bin/spamc -f -e  
    /usr/sbin/sendmail -oi -f \${sender} \${recipient}
dovecot      unix   -        n      n       -       -   pipe
  flags=DRhu user=vmail:mail argv=/usr/lib/dovecot/dovecot-lda -d \$(recipient)
_EOF_

  [[ "$INSTALL_ANTIVIRUS" == "yes" ]] && {
    cat >>/etc/postfix/master.cf <<_EOF_
amavis      unix    -       -       y       -       3       smtp
  -o smtp_data_done_timeout=1200
  -o smtp_send_xforward_command=yes
  -o disable_dns_lookups=yes
  -o max_use=20
127.0.0.1:10025 inet    n       -       y       -       -       smtpd
  -o content_filter=
  -o local_recipient_maps=
  -o relay_recipient_maps=
  -o smtpd_restriction_classes=
  -o smtpd_delay_reject=no
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_helo_restrictions=
  -o smtpd_sender_restrictions=
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o smtpd_data_restrictions=reject_unauth_pipelining
  -o smtpd_end_of_data_restrictions=
  -o mynetworks=127.0.0.0/8
  -o smtpd_error_sleep_time=0
  -o smtpd_soft_error_limit=1001
  -o smtpd_hard_error_limit=1000
  -o smtpd_client_connection_count_limit=0
  -o smtpd_client_connection_rate_limit=0
  -o receive_override_options=no_header_body_checks,no_unknown_recipient_checks,no_milters
_EOF_
  }

  output "Finished configuring Postfix"
}

installDovecot() {
  echo "Installing Dovecot..." | ts ["%F %H:%M:%S"] | tee -a install.log
  set -e
  set -o nounset # abort on unbound variable

  sudo apt-get update
  sudo apt-get install --assume-yes \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    dovecot-lmtpd \
    dovecot-mysql |
    ts ["%F %H:%M:%S"] |
    tee -a install.log

  # Adding the vhosts folder
  echo "Adding the vhosts folders" | ts ["%F %H:%M:%S"] | tee -a install.log
  if ! test -d "/var/mail/vhosts"; then
    sudo mkdir -p "/var/mail/vhosts" | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  # Adding the virtual user
  echo "Adding the vmail user to system" | ts ["%F %H:%M:%S"] | tee -a install.log
  set +e
  USERID=$(id -u vmail)
  userTest=$?
  set -e

  if [ "$userTest" -ne 0 ]; then
    echo "Creating Users"
    sudo groupadd -g 5000 vmail | ts ["%F %H:%M:%S"] | tee -a install.log
    sudo useradd -g vmail -u 5000 vmail -d /var/mail | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  echo "Adding the user for the folder /var/mail" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo chown -R vmail:vmail /var/mail
}

setupDovecot() {
  echo "Setting up Dovecot..." | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-auth.conf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/dovecot/conf.d/10-mail.conf /etc/dovecot/conf.d/10-mail.conf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/dovecot/conf.d/10-master.conf /etc/dovecot/conf.d/10-master.conf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.bak | ts ["%F %H:%M:%S"] | tee -a install.log

  cat >/etc/dovecot/conf.d/10-auth.conf <<_EOF_
##
## Authentication processes
##

disable_plaintext_auth = yes
auth_mechanisms = plain login
!include auth-system.conf.ext
!include auth-sql.conf.ext
_EOF_

  cat >/etc/dovecot/conf.d/10-mail.conf <<_EOF_
##
## Mailbox locations and namespaces
##

mail_location = maildir:/var/mail/vhosts/%d/%n/

namespace inbox {
  inbox = yes
}

mail_privileged_group = mail

protocol !indexer-worker {
  # If folder vsize calculation requires opening more than this many mails from
  # disk (i.e. mail sizes aren't in cache already), return failure and finish
  # the calculation via indexer process. Disabled by default. This setting must
  # be 0 for indexer-worker processes.
  #mail_vsize_bg_after_count = 0
}

_EOF_

  cat >/etc/dovecot/conf.d/10-master.conf <<_EOF_
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 0
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service lmtp {
 unix_listener /var/spool/postfix/private/dovecot-lmtp {
   mode = 0600
   user = postfix
   group = postfix
  }
}

service imap {
  process_limit = 1024
}

service pop3 {
  process_limit = 1024
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }

  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    #group = vmail
  }

  user = dovecot
}

service auth-worker {
  user = vmail
}

service dict {
  unix_listener dict {
    #mode = 0600
    #user = 
    #group = 
  }
}
_EOF_

  cat >/etc/dovecot/conf.d/10-ssl.conf <<_EOF_
##
## SSL settings
##

ssl = required

ssl_cert = </usr/share/ca-certificates/mail.$localDomain/fullchain.cer
ssl_key = </usr/share/ca-certificates/mail.$localDomain/mail.$localDomain.key

ssl_client_ca_dir = /etc/ssl/certs
_EOF_

  cat >/etc/dovecot/conf.d/auth-sql.conf.ext <<_EOF_
# Authentication for SQL users. Included from 10-auth.conf.
#
# <doc/wiki/AuthDatabase.SQL.txt>

passdb {
  driver = sql

  args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
_EOF_

  cat >/etc/dovecot/dovecot-sql.conf.ext <<_EOF_
driver = mysql
connect = host=localhost dbname=$MAIL_DATABASE user=${SQL_USER} password=$SQL_PASSWORD
default_pass_scheme = SHA512.b64
password_query = \
  SELECT username as user, password, '/var/mail/vhosts/%d/%n' as userdb_home, \
  'maildir:/var/mail/vhosts/%d/%n' as userdb_mail, 150 as userdb_uid, 8 as userdb_gid \
  FROM mailbox WHERE username = '%u' AND active = '1'
user_query = \
  SELECT '/var/mail/vhosts/%d/%n' as home, 'maildir:/var/mail/vhosts/%d/%n' as mail, \
  150 AS uid, 8 AS gid, concat('dirsize:storage=', quota) AS quota \
  FROM mailbox WHERE username = '%u' AND active = '1'
_EOF_

  cat >/etc/dovecot/dovecot.conf <<_EOF_
## Dovecot configuration file

!include_try /usr/share/dovecot/protocols.d/*.protocol
protocols = imap pop3 lmtp

dict {
  #quota = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext
  #expire = sqlite:/etc/dovecot/dovecot-dict-sql.conf.ext
}

!include conf.d/*.conf
!include_try local.conf

_EOF_
}

installOpenDkim() {
  echo "Installing OpenDKIM" | ts ["%F %H:%M:%S"] | tee -a install.log
  FQDN=$(hostname -d)
  DKIM_HOSTNAME=$(hostname -s)
  SHORT_FQDN=$(echo $FQDN | tr "." "_")
  DATESUFFIX=$(date +"%Y%m")
  KEYNAME="${DATESUFFIX}_${SHORT_FQDN}"

  sudo apt-get install --assume-yes \
    opendkim \
    opendkim-tools \
    postfix-policyd-spf-python \
    postfix-pcre |
    ts ["%F %H:%M:%S"] |
    tee -a install.log

  echo "Generating default configuration files" | ts ["%F %H:%M:%S"] | tee -a install.log
  chmod u=rw,go=r /etc/opendkim.conf | ts ["%F %H:%M:%S"] | tee -a install.log
  if ! test -d /etc/opendkim; then
    echo "Creating the key default structure" | ts ["%F %H:%M:%S"] | tee -a install.log
    mkdir /etc/opendkim | ts ["%F %H:%M:%S"] | tee -a install.log
    mkdir /etc/opendkim/keys | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  chown -R opendkim:opendkim /etc/opendkim | ts ["%F %H:%M:%S"] | tee -a install.log
  chmod go-rw /etc/opendkim/keys | ts ["%F %H:%M:%S"] | tee -a install.log

  if ! test -f /etc/opendkim/signing.table; then
    echo "Creating Signing Table file" | ts ["%F %H:%M:%S"] | tee -a install.log
    touch /etc/opendkim/signing.table | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  if ! test -f /etc/opendkim/key.table; then
    echo "Creating Key Table file" | ts ["%F %H:%M:%S"] | tee -a install.log
    touch /etc/opendkim/key.table | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  if ! test -f /etc/opendkim/trusted.hosts; then
    echo "Adding the computer default trusted senders" | ts ["%F %H:%M:%S"] | tee -a install.log
    printf "127.0.0.1\n::1\nlocalhost\n$DKIM_HOSTNAME\n$DKIM_HOSTNAME.$FQDN\nmail.$FQDN\n$FQDN" >/etc/opendkim/trusted.hosts | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  echo "Adding OpenDKIM to postfix" | ts ["%F %H:%M:%S"] | tee -a install.log
  chown -R opendkim:opendkim /etc/opendkim | ts ["%F %H:%M:%S"] | tee -a install.log
  chmod -R go-rwx /etc/opendkim/keys | ts ["%F %H:%M:%S"] | tee -a install.log

  if ! test -d /var/spool/postfix/opendkim; then
    mkdir /var/spool/postfix/opendkim | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  chown opendkim:postfix /var/spool/postfix/opendkim | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo adduser postfix opendkim | ts ["%F %H:%M:%S"] | tee -a install.log

  echo "Finished" | ts ["%F %H:%M:%S"] | tee -a install.log
}

setupOpenDkim() {
  output "Configuring OpenDkim"

  cat >/etc/opendkim.conf <<_EOF_
# Carlos Lapao Generated Configuration for OpenDkim

Syslog yes
UMask 007
UserID opendkim
PidFile /var/run/opendkim/opendkim.pid

KeyTable /etc/opendkim/key.table
SigningTable refile:/etc/opendkim/signing.table

ExternalIgnoreList /etc/opendkim/trusted.hosts
InternalHosts /etc/opendkim/trusted.hosts
Socket inet:8891@localhost
Canonicalization relaxed/simple
Mode sv
SubDomains no
#ADSPAction		continue
AutoRestart yes
AutoRestartRate 10/1M
Background yes
DNSTimeout 5
SignatureAlgorithm rsa-sha256

OversignHeaders From
_EOF_

  cat >/etc/default/opendkim <<_EOF_
# Carlos Lapao Generated Configuration for OpenDkim defaults
RUNDIR=/var/run/opendkim
SOCKET=inet:8891@localhost
USER=opendkim
GROUP=opendkim
PIDFILE=\$RUNDIR/\$NAME.pid
EXTRAAFTER=
_EOF_

  output "Generating the DKIM Key"
  output "Creating the record of the key in the signing table"
  SIGNTABLE="*@$FQDN $SHORT_FQDN"
  KEYTABLE="$SHORT_FQDN $FQDN:$KEYNAME:/etc/opendkim/keys/$SHORT_FQDN.private"

  set +e
  SIGNTABLE_RECORD_EXISTS=$(grep -n "$SIGNTABLE" /etc/opendkim/signing.table)
  set -e
  if [ -z "$SIGNTABLE_RECORD_EXISTS" ]; then
    output "FQDN record not found in the signing table, adding"
    cat >>/etc/opendkim/signing.table <<_EOF_
*@$FQDN $SHORT_FQDN
_EOF_
  else
    output "FQDN record already present in the signing table"
  fi

  set +e
  KEYTABLE_RECORD_EXISTS=$(grep -n "$KEYTABLE" /etc/opendkim/key.table)
  set -e
  if [ -z "$KEYTABLE_RECORD_EXISTS" ]; then
    output "Key record not found in the key table, adding"
    cat >>/etc/opendkim/key.table <<_EOF_
$SHORT_FQDN $FQDN:$KEYNAME:/etc/opendkim/keys/$SHORT_FQDN.private
_EOF_
  else
    output "Key record already present in the signing table"
  fi

  if [ -z "$KEYTABLE_RECORD_EXISTS" ]; then
    cd /etc/opendkim/keys

    echo "Removing existing keys" | ts ["%F %H:%M:%S"] | tee -a /tools/install.log
    if test -f /etc/opendkim/keys/${SHORT_FQDN}.private; then
      rm /etc/opendkim/keys/${SHORT_FQDN}.private
    fi
    if test -f /etc/opendkim/keys/${SHORT_FQDN}.private; then
      rm /etc/opendkim/keys/${SHORT_FQDN}.txt
    fi

    opendkim-genkey -b 2048 -h rsa-sha256 -r -s ${KEYNAME} -d ${FQDN} -v | ts ["%F %H:%M:%S"] | tee -a /tools/install.log

    echo "Renaming the generated keys to ${SHORT_FQDN}.private" | ts ["%F %H:%M:%S"] | tee -a /tools/install.log
    mv ${KEYNAME}.private ${SHORT_FQDN}.private
    mv ${KEYNAME}.txt ${SHORT_FQDN}.txt

    cd ~
  else
    output "DKIM keys have already been generated, ignoring..."
  fi

  chown -R opendkim:opendkim /etc/opendkim
  chmod -R go-rw /etc/opendkim/keys

  output "Generating the DKIM record"

  DKIMH=$(tr -d '\n' </etc/opendkim/keys/${SHORT_FQDN}.txt | tr -d '"' | tr -d ' ' | cut -d';' -f 2 | tr -d '\t')
  DKIMK=$(tr -d '\n' </etc/opendkim/keys/${SHORT_FQDN}.txt | tr -d '"' | tr -d ' ' | cut -d';' -f 3 | tr -d '\t')
  DKIMS=$(tr -d '\n' </etc/opendkim/keys/${SHORT_FQDN}.txt | tr -d '"' | tr -d ' ' | cut -d';' -f 4 | tr -d '\t')
  DKIMCERT=$(tr -d '\n' </etc/opendkim/keys/${SHORT_FQDN}.txt | tr -d '"' | tr -d ' ' | cut -d';' -f 5 | tr -d '\t' | sed 's/.$//')

  DKIM_RECORD="v=DKIM1; h=sha256; $DKIMK; $DKIMS; $DKIMCERT"

  output "The DKIM record was added successfully to the domain $FQDN"

  output "Restarting the services"
  systemctl restart opendkim
  systemctl restart postfix
  ipv4=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
  ipv6temp=$(ip -6 addr show eth0 | grep -oP '(?<=inet6\s)[\da-f:]+' | tr '\n' ' ')
  IFS="," read -a ipv6 <<<${ipv6temp}
  SPF_RECORD="v=spf1 a:mail.${FQDN} -ip4:${ipv4}"
  for ip6 in $ipv6; do
    expandedIp6=$(sipcalc ${ip6} | fgrep Expanded | cut -d '-' -f 2 | sed 's/\b:0000\b/:0/g' | xargs)
    SPF_RECORD="${SPF_RECORD} -ip6:${ip6}"
    SPF_RECORD="${SPF_RECORD} -ip6:${expandedIp6}"
  done
  SPF_RECORD="${SPF_RECORD} -all"
  ADSP_RECORD="dkim=all"
  ipv4=$()
  DMARC_RECORD="v=DMARC1;p=quarantine;sp=quarantine;adkim=r;aspf=r;fo=1;rf=afrf;rua=mailto:admin@${FQDN}"

  # Fixing the debian issue with the wrong socket
  echo "Fixing the Ubuntu Socket Error" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo /lib/opendkim/opendkim.service.generate | ts ["%F %H:%M:%S"] | tee -a install.log
  systemctl daemon-reload | ts ["%F %H:%M:%S"] | tee -a install.log

  output "Finished configuring OpenDmarc/OpenDkim DNS records"
}

installOpenDmarc() {
  echo "Installing OpenDMARC" | ts ["%F %H:%M:%S"] | tee -a install.log

  DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes opendmarc | ts ["%F %H:%M:%S"] | tee -a install.log

  echo "Enable OpenDMARC to auto restart" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl enable opendmarc | ts ["%F %H:%M:%S"] | tee -a install.log

  echo "Creating the SOCKET configuration"
  if ! test -d /var/spool/postfix/opendmarc; then
    echo "Default SOCKET folder does not exists, creating" | ts ["%F %H:%M:%S"] | tee -a install.log
    sudo mkdir -p /var/spool/postfix/opendmarc | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  sudo chown opendmarc:opendmarc /var/spool/postfix/opendmarc -R | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo chmod 750 /var/spool/postfix/opendmarc/ -R | ts ["%F %H:%M:%S"] | tee -a install.log

  echo "Adding postfix group to opendmarc user" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo adduser postfix opendmarc | ts ["%F %H:%M:%S"] | tee -a install.log

  echo "Restarting the OpenDMARC service" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart opendmarc | ts ["%F %H:%M:%S"] | tee -a install.log
}

setupOpenDmarc() {
  echo "Setting up OpenDMARC..." | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/opendmarc.conf /etc/opendmarc.conf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cat >/etc/opendmarc.conf <<_EOF_
# This is a basic configuration that can easily be adapted to suit a standard
# installation. For more advanced options, see opendkim.conf(5) and/or
# /usr/share/doc/opendmarc/examples/opendmarc.conf.sample.

AuthservID OpenDMARC
IgnoreAuthenticatedClients true
RequiredHeaders true
SPFIgnoreResults true
SPFSelfValidate true
PidFile /var/run/opendmarc/opendmarc.pid
PublicSuffixList /usr/share/publicsuffix
RejectFailures false
Socket local:/var/spool/postfix/opendmarc/opendmarc.sock
Syslog true
TrustedAuthservIDs mail.$localDomain
UMask 0002
UserID opendmarc  
_EOF_
}

installPostgrey() {
  echo "Installing Postgrey" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo apt-get update
  debconf-set-selections <<<"postfix postfix/mailname string $SERVER_NAME" | ts ["%F %H:%M:%S"] | tee -a install.log
  debconf-set-selections <<<"postfix postfix/main_mailer_type string 'Internet Site'" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo apt-get install --assume-yes \
    postgrey |
    ts ["%F %H:%M:%S"] |
    tee -a install.log

  echo "Restarting Postgrey" | ts ["%F %H:%M:%S"] | tee -a install.log
  systemctl enable postgrey | ts ["%F %H:%M:%S"] | tee -a install.log
  systemctl start postgrey | ts ["%F %H:%M:%S"] | tee -a install.log
}

setupPostgrey() {
  echo "Setting up Postgrey..." | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/default/postgrey /etc/default/postgrey.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cat >/etc/default/postgrey <<_EOF_
#test
# postgrey startup options, created for Debian

# you may want to set
#   --delay=N   how long to greylist, seconds (default: 300)
#   --max-age=N delete old entries after N days (default: 35)
# see also the postgrey(8) manpage

POSTGREY_OPTS="--inet=127.0.0.1:10023 --delay=60"

# the --greylist-text commandline argument can not be easily passed through
# POSTGREY_OPTS when it contains spaces.  So, insert your text here:
#POSTGREY_TEXT="Your customized rejection message here"
_EOF_
}

installSpamAssassin() {
  echo "Installing SpamAssassin" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo apt install --assume-yes \
    spamassassin \
    spamc |
    ts ["%F %H:%M:%S"] |
    tee -a install.log

  echo "Adding SpamAssassin User" | ts ["%F %H:%M:%S"] | tee -a install.log
  set +e
  USER=$(id -u spamd >/dev/null 2>&1)
  if [ $? -eq 1 ]; then
    yes | sudo adduser spamd --disabled-login
  fi
  set -e

  echo "Restarting SpamAssassin" | ts ["%F %H:%M:%S"] | tee -a install.log

  sudo systemctl enable spamassassin | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl start spamassassin | ts ["%F %H:%M:%S"] | tee -a install.log
}

setupSpamAssassin() {
  echo "Setting up SpamAssassin..." | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/default/spamassassin /etc/default/spamassassin.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cp /etc/spamassassin/local.cf /etc/spamassassin/local.cf.bak | ts ["%F %H:%M:%S"] | tee -a install.log
  cat >/etc/default/spamassassin <<_EOF_
# /etc/default/spamassassin
# Duncan Findlay

ENABLED=1
SAHOME="/var/log/spamassassin/"

OPTIONS="--create-prefs --max-children 5 --username spamd --helper-home-dir /home/spamd/ -s /home/spamd/spamd.log"

PIDFILE="/var/run/spamd.pid"

CRON=1
_EOF_

  cat >/etc/spamassassin/local.cf <<_EOF_
rewrite_header Subject [***** SPAM _SCORE_ *****]
required_score          5.0
use_bayes               1
bayes_auto_learn        1
_EOF_
}

installAntivirus() {
  echo "Installing Antivirus" | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo apt-get install --assume-yes amavisd-new clamav clamav-daemon | ts ["%F %H:%M:%S"] | tee -a install.log

  USER=$(id -u clamav >/dev/null 2>&1)
  if [ $? -eq 1 ]; then
    echo "Creating clamav user" | ts ["%F %H:%M:%S"] | tee -a install.log
    yes | sudo adduser clamav amavis --disabled-login
  fi
  USER=$(id -u amavis >/dev/null 2>&1)
  if [ $? -eq 1 ]; then
    echo "Creating amavis user" | ts ["%F %H:%M:%S"] | tee -a install.log
    yes | sudo adduser amavis clamav --disabled-login
  fi

  cat >/etc/clamav/clamd.conf <<_EOF_
#Automatically Generated by clamav-daemon postinst
#To reconfigure clamd run #dpkg-reconfigure clamav-daemon
#Please read /usr/share/doc/clamav-daemon/README.Debian.gz for details
LocalSocket /var/run/clamav/clamd.ctl
FixStaleSocket true
LocalSocketGroup clamav
LocalSocketMode 666
# TemporaryDirectory is not set to its default /tmp here to make overriding
# the default with environment variables TMPDIR/TMP/TEMP possible
User clamav
ScanMail true
ScanArchive true
ArchiveBlockEncrypted false
MaxDirectoryRecursion 15
FollowDirectorySymlinks false
FollowFileSymlinks false
ReadTimeout 180
MaxThreads 12
MaxConnectionQueueLength 15
LogSyslog false
LogRotate true
LogFacility LOG_LOCAL6
LogClean false
LogVerbose false
PreludeEnable no
PreludeAnalyzerName ClamAV
DatabaseDirectory /var/lib/clamav
OfficialDatabaseOnly false
SelfCheck 3600
Foreground false
Debug false
ScanPE true
MaxEmbeddedPE 10M
ScanOLE2 true
ScanPDF true
ScanHTML true
MaxHTMLNormalize 10M
MaxHTMLNoTags 2M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
ScanSWF true
ExitOnOOM false
LeaveTemporaryFiles false
AlgorithmicDetection true
ScanELF true
IdleTimeout 30
CrossFilesystems true
PhishingSignatures true
PhishingScanURLs true
PhishingAlwaysBlockSSLMismatch false
PhishingAlwaysBlockCloak false
PartitionIntersection false
DetectPUA false
ScanPartialMessages false
HeuristicScanPrecedence false
StructuredDataDetection false
CommandReadTimeout 30
SendBufTimeout 200
MaxQueue 100
ExtendedDetectionInfo true
OLE2BlockMacros false
AllowAllMatchScan true
ForceToDisk false
DisableCertCheck false
DisableCache false
MaxScanTime 120000
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 16
MaxFiles 10000
MaxPartitions 50
MaxIconsPE 100
PCREMatchLimit 10000
PCRERecMatchLimit 5000
PCREMaxFileSize 25M
ScanXMLDOCS true
ScanHWP3 true
MaxRecHWP3 16
StreamMaxLength 25M
LogFile /var/log/clamav/clamav.log
LogTime true
LogFileUnlock false
LogFileMaxSize 0
Bytecode true
BytecodeSecurity TrustSigned
BytecodeTimeout 60000
OnAccessMaxFileSize 5M
_EOF_
  cat >/etc/amavis/conf.d/15-content_filter_mode <<_EOF_
use strict;

# You can modify this file to re-enable SPAM checking through spamassassin
# and to re-enable antivirus checking.

#
# Default antivirus checking mode
# Please note, that anti-virus checking is DISABLED by 
# default.
# If You wish to enable it, please uncomment the following lines:


@bypass_virus_checks_maps = (
   \\%bypass_virus_checks, \\@bypass_virus_checks_acl, \\\$bypass_virus_checks_re);


#
# Default SPAM checking mode
# Please note, that anti-spam checking is DISABLED by 
# default.
# If You wish to enable it, please uncomment the following lines:


@bypass_spam_checks_maps = (
   \\%bypass_spam_checks, \\@bypass_spam_checks_acl, \\\$bypass_spam_checks_re);

1;  # ensure a defined return
_EOF_
  cat >/etc/amavis/conf.d/50-user <<_EOF_
use strict;
 
\$max_servers  = 3;
 
\$sa_tag_level_deflt  = -9999;
 
@lookup_sql_dsn = (
    ['DBI:mysql:database=mail;host=127.0.0.1;port=3306',
     '${SQL_USER}',
     '${SQL_PASSWORD}']);
\$sql_select_policy = 'SELECT domain from domain WHERE CONCAT("@",domain) IN (%k)';
 
# Uncomment to bump up the log level when testing.
# \$log_level = 2;
 
#------------ Do not modify anything below this line -------------
1;  # ensure a defined return
_EOF_
  sudo systemctl stop clamav-freshclam.service
  freshclam
  sudo systemctl restart clamav-daemon
  sudo systemctl restart amavis
  sudo systemctl restart spamassassin
}

reload() {
  echo "Reloading Services..." | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart postgrey | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart spamassassin | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart opendkim | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart opendmarc | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart dovecot | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart postfix | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo systemctl restart mysql | ts ["%F %H:%M:%S"] | tee -a install.log
}

initDatabase() {
  echo "Initiating Mail Database..." | ts ["%F %H:%M:%S"] | tee -a install.log

  mailUser="postfix"
  localhostUUID=$(uuidgen)
  virtualUserUUID=$(uuidgen)
  postfixUserUUID=$(uuidgen)
  rootUserUUID=$(uuidgen)

  if ! is_mysql_command_available; then
    echo "The MySQL/MariaDB client mysql(1) is not installed."
    exit 1
  fi

  mysql -u "root" -p"${SQL_PASSWORD}" -h localhost <<_EOF_
    CREATE DATABASE IF NOT EXISTS ${MAIL_DATABASE};
    GRANT ALL PRIVILEGES ON ${MAIL_DATABASE}.* TO '${SQL_USER}'@'%';
    GRANT ALL PRIVILEGES ON ${MAIL_DATABASE}.* TO '${SQL_USER}'@'localhost';
    GRANT ALL PRIVILEGES ON ${MAIL_DATABASE}.* TO '${SQL_USER}'@'127.0.0.1';
    FLUSH PRIVILEGES;
    
    USE ${MAIL_DATABASE};
_EOF_

  # generating the sql files for postfix
  if test -f "/etc/postfix/mysql_virtual_alias_domainaliases_maps.cf"; then
    sudo rm /etc/postfix/mysql_virtual_alias_domainaliases_maps.cf | ts ["%F %H:%M:%S"] | tee -a install.log
  fi
  if test -f "/etc/postfix/mysql_virtual_alias_maps.cf"; then
    sudo rm /etc/postfix/mysql_virtual_alias_maps.cf | ts ["%F %H:%M:%S"] | tee -a install.log
  fi
  if test -f "/etc/postfix/mysql-virtual-alias-maps.cf"; then
    sudo rm /etc/postfix/mysql-virtual-alias-maps.cf | ts ["%F %H:%M:%S"] | tee -a install.log
  fi
  if test -f "/etc/postfix/mysql-virtual-email2email.cf"; then
    sudo rm /etc/postfix/mysql-virtual-email2email.cf | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  cat >/etc/postfix/mysql_virtual_alias_domainaliases_maps.cf <<_EOF_
user = ${SQL_USER}
password = ${SQL_PASSWORD}
hosts = 127.0.0.1
dbname = mail
query = SELECT goto FROM alias,alias_domain
  WHERE alias_domain.alias_domain = '%d'
  AND alias.address=concat('%u', '@', alias_domain.target_domain)
  AND alias.active = 1  
_EOF_

  cat >/etc/postfix/mysql_virtual_alias_maps.cf <<_EOF_
user = ${SQL_USER}
password = ${SQL_PASSWORD}
hosts = 127.0.0.1
dbname = mail
table = alias
select_field = goto
where_field = address
additional_conditions = and active = '1' 
_EOF_

  cat >/etc/postfix/mysql_virtual_domains_maps.cf <<_EOF_
user = ${SQL_USER}
password = ${SQL_PASSWORD}
hosts = 127.0.0.1
dbname = mail
table = domain
select_field = domain
where_field = domain
additional_conditions = and backupmx = '0' and active = '1' 
_EOF_

  cat >/etc/postfix/mysql_virtual_mailbox_domainaliases_maps.cf <<_EOF_
user = ${SQL_USER}
password = ${SQL_PASSWORD}
hosts = 127.0.0.1
dbname = mail
query = SELECT maildir FROM mailbox, alias_domain
  WHERE alias_domain.alias_domain = '%d'
  AND mailbox.username=concat('%u', '@', alias_domain.target_domain )
  AND mailbox.active = 1
_EOF_

  cat >/etc/postfix/mysql_virtual_mailbox_maps.cf <<_EOF_
user = ${SQL_USER}
password = ${SQL_PASSWORD}
hosts = 127.0.0.1
dbname = mail
table = mailbox
select_field = CONCAT(domain, '/', local_part)
where_field = username
additional_conditions = and active = '1'
_EOF_

  cat >/etc/postfix/mysql_virtual_sender_login_maps.cf <<_EOF_
user = ${SQL_USER}
password = ${SQL_PASSWORD}
hosts = 127.0.0.1
dbname = mail
query = SELECT goto FROM alias WHERE address='%s'
_EOF_

  cat >/etc/postfix/header_checks <<_EOF_
/^Received:/                 IGNORE
/^User-Agent:/               IGNORE
/^X-Mailer:/                 IGNORE
/^X-Originating-IP:/         IGNORE
/^x-cr-[a-z]*:/              IGNORE
/^Thread-Index:/             IGNORE
_EOF_

  ## Creating the virtual host folder
  sudo mkdir -p /var/mail/vhosts/${localDomain} | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo chown -R vmail:vmail /var/mail | ts ["%F %H:%M:%S"] | tee -a install.log

  sudo chown -R vmail:dovecot /etc/dovecot | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo chmod -R o-rwx /etc/dovecot | ts ["%F %H:%M:%S"] | tee -a install.log

  # Unjail the mysql and postfix
  echo "/var/run/mysqld /var/spool/postfix/var/run/mysqld bind defaults,bind 0 0" >>/etc/fstab

  sudo ufw allow 25 | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo ufw allow 465 | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo ufw allow 587 | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo ufw allow 143 | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo ufw allow 993 | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo ufw allow 110 | ts ["%F %H:%M:%S"] | tee -a install.log
  sudo ufw allow 995 | ts ["%F %H:%M:%S"] | tee -a install.log
}

installPostfixAdmin() {
  output "Installing PostfixAdmin..."
  if test -d "/var/www/postfixadmin"; then
    output "Removing PostfixAdmin folder..."
    sudo rm -r /var/www/postfixadmin | ts ["%F %H:%M:%S"] | tee -a install.log
  fi

  git clone https://github.com/postfixadmin/postfixadmin.git /var/www/postfixadmin | ts ["%F %H:%M:%S"] | tee -a install.log

  mkdir -p /var/www/postfixadmin/templates_c
  chown -R www-data /var/www/postfixadmin/templates_c

  postfixAdminPassword=$(php -r "echo password_hash('${POSTFIX_PASSWORD}', PASSWORD_DEFAULT);")

  cat >/var/www/postfixadmin/config.local.php <<_EOF_
<?php
\$CONF['database_type'] = 'mysqli';
\$CONF['database_host'] = '${localHostname}';
\$CONF['database_user'] = '${SQL_USER}';
\$CONF['database_password'] = '${SQL_PASSWORD}';
\$CONF['database_name'] = 'mail';
\$CONF['setup_password'] = '${postfixAdminPassword}';
\$CONF['configured'] = true;
\$CONF['default_aliases'] = array (
  'abuse'      => 'abuse@${localDomain}',
  'hostmaster' => 'hostmaster@${localDomain}',
  'postmaster' => 'postmaster@${localDomain}',
  'webmaster'  => 'webmaster@${localDomain}'
);
\$CONF['fetchmail'] = 'NO';
\$CONF['show_footer_text'] = 'YES';
\$CONF['footer_text'] = 'Return to ${localHostname}';
\$CONF['footer_link'] = 'https://${localHostname}';
\$CONF['quota'] = 'YES';
\$CONF['domain_quota'] = 'YES';
\$CONF['quota_multiplier'] = '1024000';
\$CONF['used_quotas'] = 'YES';
\$CONF['new_quota_table'] = 'YES';
\$CONF['encrypt'] = 'sha512.b64';

\$CONF['aliases'] = '0';
\$CONF['mailboxes'] = '0';
\$CONF['maxquota'] = '0';
\$CONF['domain_quota_default'] = '0';
?>
_EOF_
  sudo systemctl restart nginx
  setupDatabase=$(curl https://mail.local-build.co/setup.php -k)
  set +e
  sudo bash /var/www/postfixadmin/scripts/postfixadmin-cli admin add superadmin@${localDomain} --superadmin 1 --active 1 --password ${POSTFIX_PASSWORD} --password2 ${POSTFIX_PASSWORD}
  sudo bash /var/www/postfixadmin/scripts/postfixadmin-cli domain add ${localDomain} aliases=0 mailboxes=0
  sudo bash /var/www/postfixadmin/scripts/postfixadmin-cli mailbox add admin@${localDomain} --password ${POSTFIX_PASSWORD} --password2 ${POSTFIX_PASSWORD}
  set -e
}

saveDnsConfiguration() {
  cat >/root/dns_config <<_EOF_
{
  "SPF_RECORD": {
    "key": "@",
    "type": "TXT",
    "value": "${SPF_RECORD}"    
  },
  "ADSP_RECORD": {
    "key": "_adsp._domainkey",
    "type": "TXT",
    "value": "${ADSP_RECORD}"    
  },
  "OPEN_DMARC_RECORD": {
    "key": "_dmarc",
    "type": "TXT",
    "value": "${DMARC_RECORD}"    
  },
  "OPEN_DKIM_RECORD": {
    "key": "${KEYNAME}._domainkey",
    "type": "TXT",
    "value": "${DKIM_RECORD}"    
  }
}
_EOF_
  [ ! -z "$EMAIL_CONFIG" ] && {
    cat /root/dns_config | mutt -s "${localHostname} DNS configuration" ${EMAIL_CONFIG}
    output "Configuration sent to ${EMAIL_CONFIG}"
  }
}

# Updating system to the latest version
updateSystem
# Installing Web Service and Certification Service
installCertBot

installNginx
setupNginx
# Installing supporting database for postfix
installDatabase
# Setting up the MariaDB database
setupDatabase
# Securing the SQL Database
secureDatabase
# Installing Postfix
installPostfix
# Setting up Postfix
setupPostfix
# Installing Dovecot
installDovecot
# Setting up Dovecot
setupDovecot
# Installing OpenDmarc
installOpenDkim
setupOpenDkim
# Installing OpenDkim
installOpenDmarc
# Setting up OpenDmarc
setupOpenDmarc
# Installing Postgrey
installPostgrey
# Setting up Postgrey
setupPostgrey
# Installing SpamAssassin
installSpamAssassin
# Setting up SpamAssassin
setupSpamAssassin
[[ "$INSTALL_ANTIVIRUS" == "yes" ]] && {
  # Installing Anitvirus
  installAntivirus
}
# Initiate Mail Database
initDatabase

# installing Certificates
generateCertificate

# Reloading Services
reload

installPostfixAdmin

saveDnsConfiguration
