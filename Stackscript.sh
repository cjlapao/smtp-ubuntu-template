#!/bin/bash

# <UDF name="SERVER_NAME" Label="Server Name" />
# <UDF name="DOMAIN_NAME" Label="Mail Domain Name" />
# <UDF name="SQL_USER" Label="Mail Database User" />
# <UDF name="SQL_PASSWORD" Label="Mail Database User Password" />
# <UDF name="POSTFIX_PASSWORD" Label="Mail Postfix Password" />
# <UDF name="MAIL_DATABASE" Label="Mail Database name" />
# <UDF name="INSTALL_ANTIVIRUS" Label="Use CLAMAV antivirus [yes/no]" />
# <UDF name="EMAIL_CONFIG" Label="Email address to recieve DNS config" />

git clone https://github.com/cjlapao/smtp-ubuntu-template.git

cd smtp-ubuntu-template
chmod +x generate-smtp.sh
./generate-smtp.sh
