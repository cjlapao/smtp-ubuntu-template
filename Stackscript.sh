#!/bin/bash
# <UDF name="SERVER_NAME" Label="Server Name" />
# <UDF name="DOMAIN_NAME" Label="Mail Domain Name" />
# <UDF name="SQL_USER" Label="Mail Database User" />
# <UDF name="SQL_PASSWORD" Label="Mail Database User Password" />
# <UDF name="POSTFIX_PASSWORD" Label="Mail Postfix Password" />
# <UDF name="MAIL_DATABASE" Label="Mail Database name" />
# <UDF name="INSTALL_ANTIVIRUS" Label="Use CLAMAV antivirus [yes/no]" />
# <UDF name="EMAIL_CONFIG" Label="Email address to recieve DNS config" />

mkdir /tools
git clone https://github.com/cjlapao/smtp-ubuntu-template.git /tools
cd /tools

chmod +x /tools/generate-smtp.sh
/tools/generate-smtp.sh -s $SERVER_NAME -d $DOMAIN_NAME -u $SQL_USER -p $SQL_PASSWORD -o $POSTFIX_PASSWORD -a $MAIL_DATABASE -v $INSTALL_ANTIVIRUS -c $EMAIL_CONFIG -l /tools/install.log
