#!/bin/bash
#######################################################################
# Copyright (c) 2016 ENEO Tecnología S.L.
# This file is part of redBorder.
# redBorder is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# redBorder is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License License for more details.
# You should have received a copy of the GNU Affero General Public License License
# along with redBorder. If not, see <http://www.gnu.org/licenses/>.
#######################################################################

source /etc/profile
source $RBBIN/rb_functions.sh
source $RBBIN/rb_manager_functions.sh

# ?¿ ##CMO##
manufacturer=$(dmidecode -t 1| grep "Manufacturer:" | sed 's/.*Manufacturer: //')

if [ -f /var/lock/master.lock ]; then
  echo "INFO: this manager has already been initialized"
  exit 0
fi

touch /var/lock/master.lock
chattr +i /var/lock/master.lock
touch /var/lock/master-running.lock

#[ -f /opt/rb/etc/lock/keepalived ] && rm -f /opt/rb/etc/lock/keepalived

service chef-client stop

# AMAZON Installation (user-data)
[ -f /etc/redborder/externals.conf ] && source /etc/redborder/externals.conf
if [ "x$CDOMAIN" != "x" -a "x$S3HOST" != "x" -a "x$AWS_ACCESS_KEY" != "x" -a "x$AWS_SECRET_KEY" != "x" -a -f /root/.aws/credentials ]; then
  bash $RBBIN/rb_route53.sh -d "$CDOMAIN" -r "${REGION}" -v "$VPCID" -a "$PUBLIC_HOSTEDZONE_ID" -b "$PRIVATE_HOSTEDZONE_ID" -x "master"

  cat > /root/.s3cfg <<- _RBEOF2_
[default]
access_key = $AWS_ACCESS_KEY
secret_key = $AWS_SECRET_KEY
_RBEOF2_

  if [ "x$S3TYPE" == "xaws" ] ; then
    cat >> /root/.s3cfg <<- _RBEOF2_
host_base = s3.amazonaws.com
host_bucket = %(bucket)s.s3.amazonaws.com
_RBEOF2_
  else
    cat >> /root/.s3cfg <<- _RBEOF2_
host_base = $S3HOST
host_bucket = %(bucket)s.${S3HOST}
_RBEOF2_
  fi

  cat >> /root/.s3cfg <<- _RBEOF2_
access_token =
add_encoding_exts =
add_headers =
cache_file =
cloudfront_host = cloudfront.amazonaws.com
default_mime_type = binary/octet-stream
delay_updates = False
delete_after = False
delete_after_fetch = False
delete_removed = False
dry_run = False
enable_multipart = True
encoding = UTF-8
encrypt = False
follow_symlinks = False
force = False
get_continue = False
gpg_command = /usr/bin/gpg
gpg_decrypt = %(gpg_command)s -d --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s
gpg_encrypt = %(gpg_command)s -c --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s
gpg_passphrase = redborder
guess_mime_type = True
human_readable_sizes = False
invalidate_default_index_on_cf = False
invalidate_default_index_root_on_cf = True
invalidate_on_cf = False
list_md5 = False
log_target_prefix =
mime_type =
multipart_chunk_size_mb = 50
preserve_attrs = True
progress_meter = True
proxy_host =
proxy_port = 0
recursive = False
recv_chunk = 4096
reduced_redundancy = False
send_chunk = 4096
simpledb_host = sdb.amazonaws.com
skip_existing = False
socket_timeout = 300
urlencoding_mode = normal
use_https = True
verbosity = WARNING
website_endpoint = http://%(bucket)s.s3-website-%(location)s.amazonaws.com/
website_error =
website_index = index.html
_RBEOF2_

fi

if [ "x$CRESTORE" == "x1" -a "x$S3BUCKET" != "x" -a -f /root/.s3cfg ]; then
  # Do Backup. But now...
  echo "Do backup!"
  #
  #hostname -s > /etc/hostname
  #[ ! -f /etc/redborder/rB.lic ] && cp /var/chef/cookbooks/redBorder-manager/files/default/rB.lic /etc/redborder/
  #
  #if [ "x$manufacturer" == "xXen" -o "x$manufacturer" == "xxen" -a "x$AWS_ACCESS_KEY" != "x" -a "x$AWS_SECRET_KEY" != "x" ]; then
  #  pdate "Configuring virtual ips"
  #  secip=$(timeout 100 /opt/rb/bin/rb_aws_secondary_ip.sh -a 2>/dev/null|grep "^IP: "|awk '{print $2}')
  #  [ "x$secip" != "x" ] && bkpcmd="/opt/rb/bin/rb_upload_ips -y -p $secip -u $secip -g $secip -f $secip"
  #  bkpcmd="$bkpcmd; /opt/rb/bin/rb_upload_ips -y | grep Chef::DataBagItem"
  #  pdate "New virtual ips: ${secip}"
  #fi

  #if [ "x$S3HOST" != "x" -a "x$S3TYPE" == "xaws" -a "x$AWS_ACCESS_KEY" != "x" -a "x$AWS_SECRET_KEY" != "x" -a -f /opt/rb/bin/rb_external_s3 ]; then
  #  bkpcmd="$bkpcmd; /opt/rb/bin/rb_external_s3 -a \"$AWS_ACCESS_KEY\" -k \"$AWS_SECRET_KEY\" -b \"$S3BUCKET\" -r \"$S3HOST\" -e \"$CHEF_AWS_ACCESS_KEY\" -t \"$CHEF_AWS_SECRET_KEY\" -f -l \"$REGION\" -o"
  #fi

  #pdate "Restoring backup"
  #/opt/rb/bin/rb_backup_node.rb -r -3 -n -k $S3BUCKET -c "$bkpcmd"
  #pdate "End restored backup"
else
  # Let's start

  service postgresql start
  service nginx start

  ERCHEFCFG="/var/opt/chef-server/erchef/etc/app.config"

  # External S3 user data
  if [ "x$S3HOST" != "x" -a "x$S3TYPE" == "xaws" -a "x$AWS_ACCESS_KEY" != "x" -a "x$AWS_SECRET_KEY" != "x" -a "x${S3BUCKET}" != "x" ]; then
    sed -i "s|s3_access_key_id,.*|s3_access_key_id, \"${AWS_ACCESS_KEY}\"},|" $ERCHEFCFG
    sed -i "s|s3_secret_key_id,.*|s3_secret_key_id, \"${AWS_SECRET_KEY}\"},|" $ERCHEFCFG
    sed -i "s|s3_url,.*|s3_url, \"https://${S3HOST}\"},|" $ERCHEFCFG
    sed -i "s|s3_platform_bucket_name,.*|s3_platform_bucket_name, \"${S3BUCKET}\"},|" $ERCHEFCFG
    sed -i "s|s3_external_url,.*|s3_external_url, \"https://${S3HOST}\"},|" $ERCHEFCFG
    sed -i  's/"redBorder": {/"redBorder": {\n      "uploaded_s3": true,/' /var/chef/data/role/manager.json
    rm -rf /var/opt/chef-server/bookshelf/data/bookshelf
  else
    #configuring erchef to use local cookbooks
    sed -i 's|s3_external_url.*$|s3_external_url, "https://localhost"},|' $ERCHEFCFG |grep s3_external_url
  fi

  #Force data not to be uploaded
  pdate "Copying local cookbooks into cache"
  mkdir -p /var/chef/cache/cookbooks/
  for n in redBorder-common ntp redBorder-manager snmp geodb ohai rsyslog; do # Need cookbooks
    rsync -a /var/chef/cookbooks/${n}/ /var/chef/cache/cookbooks/$n
  done
  chown -R chef:chef /var/chef/cache/cookbooks
  chown chef:chef /var/chef/cache /var/chef

  #rsync -a /var/chef/cookbooks/geodb/files/default/* /opt/rb/share/GeoIP/ #?????
  #chmod 666 /opt/rb/share/GeoIP/*
  #chown root:root /opt/rb/share/GeoIP/*

  #TODO
  #[ -f /usr/lib/rb-samza-bi/app/rb-samza-bi.tar.gz ] && touch -t 201412210000 /usr/lib/rb-samza-bi/app/rb-samza-bi.tar.gz
  #[ -f /usr/lib/rb-samza-location/app/rb-samza-location.tar.gz ] && touch -t 201412210000 /usr/lib/rb-samza-location/app/rb-samza-location.tar.gz

  # Starting erchef and associated services
  service erchef status &>/dev/null
  [ $? -ne 3 ] && service erchef reload
  rb_chef start

  ########################
  # Configuring database #
  ########################
  pdate "Initiating database: "
  ldconfig &>/dev/null

  PGPOOLPASS=""

  if [ -f /var/www/rb-rails/config/database.yml ]; then
    REDBORDERDBPASS=$(cat /var/www/rb-rails/config/database.yml |grep password|head -n 1 |sed 's/^.*password: //')
  fi

  [ "x$REDBORDERDBPASS" == "x" ] && REDBORDERDBPASS="`< /dev/urandom tr -dc A-Za-z0-9 | head -c128 | sed 's/ //g'`"

  if [ -f /var/www/rb-rails/config/database.yml ]; then
    DRUIDDBPASS=$(cat /var/www/rb-rails/config/database.yml |grep password|tail -n 1 |sed 's/^.*password: //')
  fi

  [ "x$DRUIDDBPASS" == "x" ] && DRUIDDBPASS="`< /dev/urandom tr -dc A-Za-z0-9 | head -c128 | sed 's/ //g'`"

  [ "x$OOZIEPASS" == "x" ] && OOZIEPASS="`< /dev/urandom tr -dc A-Za-z0-9 | head -c128 | sed 's/ //g'`"

  RABBITMQPASS="`grep rabbitmq_password $ERCHEFCFG | sed 's/[^"]*"//' | sed 's/">>},[ ]*$//'`"
  OPSCODE_CHEFPASS="`grep db_pass $ERCHEFCFG | sed 's/[^"]*"//' | sed 's/"},[ ]*$//'`"
  BOOKSHELFKEY="`grep s3_access_key_id $ERCHEFCFG | sed 's/[^"]*"//' | sed 's/"},[ ]*$//'`"
  BOOKSHELFSECRET="`grep s3_secret_key_id $ERCHEFCFG | sed 's/[^"]*"//' | sed 's/"},[ ]*$//'`"

  wait_service postgresql

  #pgpool passwords
  [ -f /usr/share/pgpool-II/pgpool-recovery.sql ] && su - opscode-pgsql -s /bin/bash -c "psql -f /usr/share/pgpool-II/pgpool-recovery.sql template1"
  [ -f /usr/share/pgpool-II/pgpool-regclass.sql ] && su - opscode-pgsql -s /bin/bash -c "psql -f /usr/share/pgpool-II/pgpool-regclass.sql template1"

  for n in redborder ; do # only redborder database?
    su - opscode-pgsql -s /bin/bash -c "dropdb $n &>/dev/null"
    su - opscode-pgsql -s /bin/bash -c "createdb --encoding=UTF8 --template=template0 $n"
    [ -f /usr/share/pgpool-II/pgpool-recovery.sql ] && su - opscode-pgsql -s /bin/bash -c "psql -f /usr/share/pgpool-II/pgpool-recovery.sql $n"
    [ -f /usr/share/pgpool-II/pgpool-regclass.sql ] && su - opscode-pgsql -s /bin/bash -c "psql -f /usr/share/pgpool-II/pgpool-regclass.sql $n"
  done
  su - opscode-pgsql -s /bin/bash -c "dropdb druid &>/dev/null"
  su - opscode-pgsql -s /bin/bash -c "createdb druid"
  su - opscode-pgsql -s /bin/bash -c "dropdb oozie &>/dev/null"
  su - opscode-pgsql -s /bin/bash -c "createdb oozie"

  # INFO: The vrrp can have only 8 caracters
  VRRPPASS=`< /dev/urandom tr -dc A-Za-z0-9 | head -c8 | sed 's/ //g'`

  # Generate MD5 password for pgpool
  if [ ! -f /etc/pgpool-II/pool_passwd ]; then
      mkdir -p /etc/pgpool-II/
      rm -f /etc/pgpool-II/pool_passwd
      touch /etc/pgpool-II/pool_passwd
      [ ! -f /etc/pgpool-II/pgpool.conf -a -f /etc/pgpool-II/pgpool.conf.default ] && cp /etc/pgpool-II/pgpool.conf.default /etc/pgpool-II/pgpool.conf
      pg_md5 --md5auth --username=redborder "${REDBORDERDBPASS}" -f /etc/pgpool-II/pgpool.conf
      pg_md5 --md5auth --username=druid "${DRUIDDBPASS}" -f /etc/pgpool-II/pgpool.conf
      pg_md5 --md5auth --username=oozie "${OOZIEPASS}" -f
      /etc/pgpool-II/pgpool.conf
      pg_md5 --md5auth --username=opscode_chef "${OPSCODE_CHEFPASS}" -f /etc/pgpool-II/pgpool.conf
  fi

  PGPOOLPASS="`< /dev/urandom tr -dc A-Za-z0-9 | head -c35 | sed 's/ //g'`"
  PGPOOLPASSMD5="`pg_md5 $PGPOOLPASS`"
  REDBORDERDBPASSMD5="`cat /etc/pgpool-II/pool_passwd | grep "^redborder:"|tr ':' ' ' | awk '{print $2}'`"
  DRUIDDBPASSMD5="`cat /etc/pgpool-II/pool_passwd | grep "^druid:"|tr ':' ' ' | awk '{print $2}'`"
  OOZIEPASSMD5="`cat /etc/pgpool-II/pool_passwd | grep "^oozie:"|tr ':' ' ' | awk '{print $2}'`"
  OPSCODE_CHEFPASSMD5="`cat /etc/pgpool-II/pool_passwd | grep "^opscode_chef:"|tr ':' ' ' | awk '{print $2}'`"

  su - opscode-pgsql -s /bin/bash -c "echo \"CREATE USER redborder WITH PASSWORD '$REDBORDERDBPASS';\" | psql -U opscode-pgsql"
  su - opscode-pgsql -s /bin/bash -c "echo \"ALTER  USER redborder WITH PASSWORD '$REDBORDERDBPASS';\" | psql -U opscode-pgsql" &>/dev/null
  su - opscode-pgsql -s /bin/bash -c "echo \"CREATE USER druid WITH PASSWORD '$DRUIDDBPASS';\" | psql -U opscode-pgsql"
  su - opscode-pgsql -s /bin/bash -c "echo \"ALTER  USER druid WITH PASSWORD '$DRUIDDBPASS';\" | psql -U opscode-pgsql"
  su - opscode-pgsql -s /bin/bash -c "echo \"CREATE USER oozie WITH PASSWORD '$OOZIEPASS';\" | psql -U opscode-pgsql"
  su - opscode-pgsql -s /bin/bash -c "echo \"ALTER  USER oozie WITH PASSWORD '$OOZIEPASS';\" | psql -U opscode-pgsql"

  pdate "Configuring first secrets"

  ####################
  # Configuring chef #
  ####################
  cdomain="redborder.cluster"

  [ -f /etc/redborder/cdomain ] && cdomain=$(head /etc/redborder/cdomain -n 1)
  [ "x$cdomain" == "x" ] && cdomain="redborder.cluster"

  # Data bags
  cat > /var/chef/data/data_bag/rBglobal/domain.json <<- _RBEOF2_
{
  "id": "domain",
  "name": "${cdomain}"
}
_RBEOF2_

  [ "x$PUBLICCDOMAIN" == "x" ] && PUBLICCDOMAIN="$cdomain"
  cat > /var/chef/data/data_bag/rBglobal/publicdomain.json <<- _RBEOF2_
{
  "id": "publicdomain",
  "name": "${PUBLICCDOMAIN}"
}
_RBEOF2_

  sed -i "s/admin@.*\"/admin@$cdomain/" /var/chef/data/data_bag/passwords/s3_secrets.json
  sed -i "s/s3.redborder.cluster/s3.$cdomain/" /var/chef/data/data_bag/passwords/s3_secrets.json
  sed -i "s|^chef_server_url .*|chef_server_url  \"http://erchef.$cdomain:8000\"|" /etc/chef/client.rb*
  sed -i "s/\.redborder\.cluster/.${cdomain}/g" /etc/hosts

  grep -q erchef.${cdomain} /etc/hosts
  [ $? -ne 0 ] && echo "127.0.0.1   erchef.${cdomain}" >> /etc/hosts

  mkdir -p /var/chef/data/data_bag_encrypted/passwords/
  cat > /var/chef/data/data_bag_encrypted/passwords/db_opscode_chef.json <<- _RBEOF2_
{
  "id": "db_opscode_chef",
  "username": "opscode_chef",
  "database": "opscode_chef",
  "hostname": "postgresql.${cdomain}",
  "port": 5432,
  "pass": "$OPSCODE_CHEFPASS",
  "md5_pass": "$OPSCODE_CHEFPASSMD5"
}
_RBEOF2_

  rm -f /var/chef/data/data_bag/passwords/db_opscode_chef.json

  # Create pgpool data bag item
  if [ "x$PGPOOLPASS" != "x" ]; then
    cat > /var/chef/data/data_bag_encrypted/passwords/pgp_pgpool.json <<- _RBEOF2_
{
  "id": "pgp_pgpool",
  "username": "pgpool",
  "pass": "$PGPOOLPASS",
  "md5_pass": "$PGPOOLPASSMD5"
}
_RBEOF2_
  else
    rm -f /var/chef/data/data_bag_encrypted/passwords/pgp_pgpool.json
  fi

  rm -f /var/chef/data/data_bag/passwords/pgp_pgpool.json

  # Create rabbitmq data bag item
  cat > /var/chef/data/data_bag_encrypted/passwords/rabbitmq.json <<- _RBEOF2_
{
  "id": "rabbitmq",
  "username": "chef",
  "pass": "$RABBITMQPASS"
}
_RBEOF2_
  rm -f /var/chef/data/data_bag/passwords/rabbitmq.json

  if [ "x$VRRPPASS" != "x" ]; then
    cat > /var/chef/data/data_bag_encrypted/passwords/vrrp.json <<- _RBEOF2_
{
  "id": "vrrp",
  "username": "vrrp",
  "start_id": "$[ ( $RANDOM % ( $[ 200 - 10 ] + 1 ) ) + 10 ]",
  "pass": "$VRRPPASS"
}
_RBEOF2_
  else
    rm -f /var/chef/data/data_bag_encrypted/passwords/vrrp.json
  fi
  rm -f /var/chef/data/data_bag/passwords/vrrp.json

  cat > /var/chef/data/data_bag_encrypted/passwords/db_redborder.json <<- _RBEOF2_
{
  "id": "db_redborder",
  "username": "redborder",
  "database": "redborder",
  "hostname": "postgresql.${cdomain}",
  "port": 5432,
  "pass": "$REDBORDERDBPASS",
  "md5_pass": "$REDBORDERDBPASSMD5"
}
_RBEOF2_
  rm -f /var/chef/data/data_bag/passwords/db_redborder.json

  cat > /var/chef/data/data_bag_encrypted/passwords/db_druid.json <<- _RBEOF2_
{
  "id": "db_druid",
  "username": "druid",
  "database": "druid",
  "hostname": "postgresql.${cdomain}",
  "port": 5432,
  "pass": "$DRUIDDBPASS",
  "md5_pass": "$DRUIDDBPASSMD5"
}
_RBEOF2_
  rm -f /var/chef/data/data_bag/passwords/db_druid.json

  cat > /var/chef/data/data_bag_encrypted/passwords/db_oozie.json <<- _RBEOF2_
{
  "id": "db_oozie",
  "username": "oozie",
  "database": "oozie",
  "hostname": "postgresql.${cdomain}",
  "port": 5432,
  "pass": "$OOZIEPASS",
  "md5_pass": "$OOZIEPASSMD5"
}
_RBEOF2_
  rm -f /var/chef/data/data_bag/passwords/db_druid.json

  cat > /var/chef/data/data_bag_encrypted/passwords/opscode-bookshelf-admin.json <<- _RBEOF2_
{
  "id": "opscode-bookshelf-admin",
  "key_id": "$BOOKSHELFKEY",
  "key_secret": "$BOOKSHELFSECRET"
}
_RBEOF2_
  rm -f /var/chef/data/data_bag/passwords/opscode-bookshelf-admin.json

  mkdir -p /etc/rabbitmq/
  echo -n "$RABBITMQPASS" > /etc/rabbitmq/rabbitmq-pass.conf

  #rb-webui secret key
  RBWEBISECRET="`< /dev/urandom tr -dc A-Za-z0-9 | head -c128 | sed 's/ //g'`"
  cat > /var/chef/data/data_bag_encrypted/passwords/rb-webui_secret_token.json <<- _RBEOF2_
{
  "id": "rb-webui_secret_token",
  "secret": "$RBWEBISECRET"
}
_RBEOF2_
  rm -f /var/chef/data/data_bag/passwords/rb-webui_secret_token.json


  if [ -f /usr/lib/nmspd/app/nmsp.jar ]; then
    NMSPMAC=$(ip a | grep link/ether | tail -n 1 | awk '{print $2}')
    if [ "x$NMSPMAC" == "x" ]; then
      NMSPMAC="$(< /dev/urandom tr -dc a-f0-9 | head -c2 | sed 's/ //g'):$(< /dev/urandom tr -dc a-f0-9 | head -c2 | sed 's/ //g'):$(< /dev/urandom tr -dc a-f0-9 | head -c2 | sed 's/ //g'):$(< /dev/urandom tr -dc a-f0-9 | head -c2 | sed 's/ //g'):$(< /dev/urandom tr -dc a-f0-9 | head -c2 | sed 's/ //g'):$(< /dev/urandom tr -dc a-f0-9 | head -c2 | sed 's/ //g'):"
    fi
    rm -f /var/chef/cookbooks/redBorder-manager/files/default/aes.keystore
    rm -f /var/chef/data/data_bag_encrypted/passwords/nmspd-key-hashes.json
    mkdir -p /var/chef/data/data_bag_encrypted/passwords /var/chef/cookbooks/redBorder-manager/files/default
    java -cp /usr/lib/nmspd/app/deps/*:/usr/lib/nmspd/app/nmsp.jar net.redborder.nmsp.NmspConsumer config-gen /var/chef/cookbooks/redBorder-manager/files/default/ /var/chef/data/data_bag_encrypted/passwords/ $NMSPMAC
  fi

  wait_service erchef

  pdate "Uploading cookbooks"
  knife cookbook upload geodb &>/dev/null
  knife cookbook upload ntp &>/dev/null

  HOME="/root" $RBBIN/rb_upload_cookbooks.sh -q
  echo

  # Certificates
  pdate "Generating certificates"
  if [ ! -f var/www/rb-rails/config/rsa ]; then
      ssh-keygen -t rsa -f /var/www/rb-rails/config/rsa -N ""
      mkdir -p /var/chef/data/data_bag_encrypted/passwords/
      echo "{
  \"id\": \"ssh\",
  \"username\": \"redborder\",
  \"public_rsa\": \"`cat /var/www/rb-rails/config/rsa.pub`\"
}" > /var/chef/data/data_bag_encrypted/passwords/ssh.json

  fi

  # Generating new certs
  for n in ${cdomain} webui.${cdomain} erchef.${cdomain} repo.${cdomain} chefwebui.${cdomain} s3.${cdomain} data.${cdomain}; do
      [ ! -f /var/opt/chef-server/nginx/ca/$n.crt ] && $RBBIN/rb_create_cert.sh -n $n
  done

  #generating cluster uuid
  mkdir -p /var/chef/data/data_bag_encrypted/rBglobal
  cat > /var/chef/data/data_bag_encrypted/rBglobal/cluster.json <<- _RBEOF2_
{
  "id": "cluster",
  "uuid": "$(cat /proc/sys/kernel/random/uuid)"
}
_RBEOF2_

  pdate "Uploading chef data"

  HOME="/root" $RBBIN/rb_upload_chef_data.sh -y

  rm -rf /var/chef/data/data_bag_encrypted/*

  [ ! -f /etc/chef/client.rb ] && cp /etc/chef/client.rb.default /etc/chef/client.rb
  CLIENTNAME=`hostname -s`

  if [ ! -f /etc/chef/client.pem ]; then
      pdate "Registering chef-client ..."
      HOME="/root" knife client -c /root/.chef/knife.rb --disable-editing create $CLIENTNAME > /etc/chef/client.pem
  fi

  HOME="/root" knife node -c /root/.chef/knife.rb --disable-editing create $CLIENTNAME
  HOME="/root" knife node -c /root/.chef/knife.rb run_list add $CLIENTNAME "role[manager]"

  if [ ! -d /var/www/rb-rails/config ]; then
      mkdir -p /var/www/rb-rails/config
      chown rb-webui:rb-webui /var/www/rb-rails/config
  fi

  [ ! -f /etc/redborder/rB.lic -a -f /var/chef/cookbooks/redBorder-manager/files/default/rB.lic ] && cp /var/chef/cookbooks/redBorder-manager/files/default/rB.lic /etc/redborder/rB.lic

  if [ ! -f /var/www/rb-rails/config/rb-chef-webui.pem ]; then
      pdate "Generating rb-chef-webui.pem"
      HOME="/root" knife client create rb-chef-webui -a --file /var/www/rb-rails/config/rb-chef-webui.pem -c /root/.chef/knife.rb --disable-editing
      chown rb-webui:rb-webui /var/www/rb-rails/config/rb-chef-webui.pem
      chmod 600 /var/www/rb-rails/config/rb-chef-webui.pem
  fi

  pdate "Uploading certs"
  [ ! -f /var/www/rb-rails/config/rsa ] && $RBBIN/rb_create_rsa.sh -f
  $RBDIR/rb_upload_certs.sh

  # Roles
  [ -f /etc/chef/initialrole ] && initialrole=$(head /etc/chef/initialrole -n 1)
  [ "x$initialrole" == "x" ] && initialrole="master"

  if [ ! -f /etc/redborder/mode/manager ]; then
      if [ -f /etc/redborderenterprise ]; then
          if [ -f /etc/chef/initialrole ]; then
              if [ "x$initialrole" == "xcore" -o "x$initialrole" == "xcoreriak" -o "x$initialrole" == "xcoreplus" -o "x$initialrole" == "xcorezk"  ]; then
                  $RBBIN/rb_set_mode.rb $initialrole
              else
                  $RBBIN/rb_set_mode.rb master
                  $RBBIN/rb_riak_status.rb enable
              fi
          else
              $RBBIN/rb_set_mode.rb master
              $RBBIN/rb_riak_status.rb enable
          fi
          #/opt/rb/bin/rb_set_mode.rb corezk
          $RBBIN/rb_update_timestamp.rb &>/dev/null
      else
          $RBBIN/rb_set_mode.rb master
      fi
      # Lock the cluster creation
      touch /etc/redborder/cluster.lock
  fi

  mkdir -p /root/.chef/trusted_certs/
  rsync /var/opt/chef-server/nginx/ca/erchef.${cdomain}.crt /var/opt/chef-server/nginx/ca/${cdomain}.crt /root/.chef/trusted_certs/
  mkdir -p /home/redBorder/.chef/trusted_certs/
  rsync /var/opt/chef-server/nginx/ca/erchef.${cdomain}.crt /var/opt/chef-server/nginx/ca/${cdomain}.crt /home/redBorder/.chef/trusted_certs/
  chown -R redBorder:redBorder /home/redBorder/.chef

  #change local certifcate
  sed -i "s/localhost.crt/erchef.${cdomain}.crt/" /var/opt/chef-server/nginx/etc/nginx.conf

  # configuring externals
  if [ -f /etc/redborder/enterprise ]; then
    if [ "x$manufacturer" == "xXen" -o "x$manufacturer" == "xxen" -a "x$AWS_ACCESS_KEY" != "x" -a "x$AWS_SECRET_KEY" != "x" ]; then
      pdate "Configuring virtual ips"
      secip=$(timeout 100 $RBBIN/rb_aws_secondary_ip.sh -a 2>/dev/null|grep "^IP: "|awk '{print $2}')
      pdate "New virtual ips: ${secip}"

      [ "x$secip" != "x" ] && $RBBIN/rb_upload_ips -y -p $secip -u $secip -g $secip -f $secip

      $RBBIN/rb_upload_ips -y | grep Chef::DataBagItem
    fi

    pdate "Configuring externals"

    [ "x$MODULES" != "x" -a -f $RBBIN/rb_set_modules.rb ] && rb_set_modules.rb $MODULES
    [ "x$NODESERVICES" != "x" -a -f $RBBIN/rb_set_service.rb ] && $RBBIN/rb_set_service.rb $NODESERVICES

    if [ "x$ENRICHMODE" != "x" ]; then
      if [ "x$ENRICHMODE" == "xrb-enrich" ]; then
        $RBBIN/rb_set_topic.rb rb_flow:rb-enrich
      elif [ "x$ENRICHMODE" == "xsamza" ]; then
        $RBBIN/rb_set_topic.rb rb_flow:samza rb_event:samza rb_monitor:samza rb_state:samza rb_social:samza
      fi
    fi
    if [ "x$S3HOST" != "x" -o "x$SQLHOST" != "x" -o "x$ELASTICCACHEENDPOINT" != "x" ]; then
      service chef-client stop
      for nserv in postgresql nginx rabbitmq chef-expander chef-solr bookshelf erchef; do
        service $nserv start
      done
      if [ "x$S3TYPE" == "xaws" ]; then
        if [ "x$S3BUCKET" != "x" ]; then
          $RBBIN/rb_external_s3 -a "$AWS_ACCESS_KEY" -k "$AWS_SECRET_KEY" -b "$S3BUCKET" -r "$S3HOST" -e "$CHEF_AWS_ACCESS_KEY" -t "$CHEF_AWS_SECRET_KEY" -f -l "$REGION"
        else
          f_set_color red
          echo "  ERROR: Invalid AWS credentials. Setting local s3 storage!!"
          f_set_color norm
        fi
      else
        $RBBIN/rb_external_s3 -fd
      fi
      if [ "x$ELASTICCACHEENDPOINT" != "x" ]; then
        $RBBIN/rb_external_memcached -fr $ELASTICCACHEENDPOINT
      else
        $RBBIN/rb_external_memcached -d -f
      fi
      if [ "x$SQLHOST" == "x" -o "x$SQLDB" == "x" -o "x$SQLUSER" == "x" -o "x$SQLPASSWORD" == "x" ]; then
        $RBBIN/rb_external_postgresql -d -t redborder -f
        $RBBIN/rb_external_postgresql -d -t druid -f
        $RBBIN/rb_external_postgresql -d -t opscode_chef -f
        $RBBIN/rb_external_postgresql -d -t oozie -f
      else
        SQLHOST=$(echo $SQLHOST|sed 's/:.*//')
        $RBBIN/rb_initpg.sh -ier "${SQLHOST}" -u "${SQLUSER}" -p "${SQLPASSWORD}" -d "${SQLDB}" -f
      fi
    fi
  fi

  [ -f /etc/chef/initialdata.json ] && $RBBIN/rb_chef_node /etc/chef/initialdata.json
  [ -f /etc/chef/initialrole.json ] && $RBBIN/rb_chef_role /etc/chef/initialrole.json

  pdate "Configuring chef client (first time). Please wait...  "
  echo "###########################################################" >>/root/.install-chef-client.log
  echo "redBorder install 1/3 run $(date)" >>/root/.install-chef-client.log
  echo "###########################################################" >>/root/.install-chef-client.log
  $RBBIN/rb_run_chef_once.sh &>/root/.install-chef-client.log
  echo "" >>/root/.install-chef-client.log
  echo "###########################################################" >>/root/.install-chef-client.log
  echo "redBorder install 2/3 run $(date)" >>/root/.install-chef-client.log
  echo "###########################################################" >>/root/.install-chef-client.log
  $RBBIN/rb_run_chef_once.sh &>>/root/.install-chef-client.log
  echo "" >>/root/.install-chef-client.log
  echo "###########################################################" >>/root/.install-chef-client.log
  echo "redBorder install 3/3 run $(date)" >>/root/.install-chef-client.log
  echo "###########################################################" >>/root/.install-chef-client.log
  $RBBIN/rb_run_chef_once.sh &>>/root/.install-chef-client.log
  echo "" >>/root/.install-chef-client.log

  pushd $RBDIR/var/www/rb-rails &>/dev/null

  rb_service start memcached &>/dev/null

  pdate "Creating database structure: "

  echo "### COMMAND: env NO_MODULES=1 RAILS_ENV=production rake db:migrate" &>>/root/.install-redborder-db.log
  env NO_MODULES=1 RAILS_ENV=production rake db:migrate &>>/root/.install-redborder-db.log

  echo "### COMMAND: env NO_MODULES=1 RAILS_ENV=production rake db:migrate:modules" &>>/root/.install-redborder-db.log
  env NO_MODULES=1 RAILS_ENV=production rake db:migrate:modules &>>/root/.install-redborder-db.log

  echo "### COMMAND: env NO_MODULES=1 RAILS_ENV=production rake db:seed" &>>/root/.install-redborder-db.log
  env NO_MODULES=1 RAILS_ENV=production rake db:seed &>>/root/.install-redborder-db.log

  echo "### COMMAND: RAILS_ENV=production rake db:seed:modules" &>>/root/.install-redborder-db.log
  RAILS_ENV=production rake db:seed:modules &>>/root/.install-redborder-db.log

  echo "### COMMAND: rake redBorder:generate_server_key" &>>/root/.install-redborder-db.log
  RAILS_ENV=production rake redBorder:generate_server_key &>>/root/.install-redborder-db.log
  popd &>/dev/null

  pdate "Initiating rules database. Please wait ... "
  [ -f /etc/druid/database.sql ] && cat /etc/druid/database.sql | psql -U druid &>/root/.install-druid-db.log

  if [ -d /etc/psql/sql ]; then
    pushd /etc/psql/sql &>/dev/null
    for n in $(ls -d * 2>/dev/null); do
      if [ -d $n ];then
        if [ "x$n" == "xopscode-pgsql" ]; then
          for s in $(ls $n/* 2>/dev/null); do
            su - opscode-pgsql -s /bin/bash -c "psql -f /etc/psql/sql/$s" &>>/root/.install-$n-db.log
          done
        else
          for s in $(ls $n/* 2>/dev/null); do
            cat $s | psql -U $n &>>/root/.install-$n-db.log
          done
        fi
      fi
    done
    popd &>/dev/null
  fi

  if [ -f /usr/lib/oozie/bin/ooziedb.sh ]; then
    pushd /usr/lib/oozie &>/dev/null
    ./bin/ooziedb.sh create -sqlfile /etc/oozie/database.sql -run &>/root/.install-oozie-db.log
    popd &>/dev/null
  fi

  [ -f $RBBIN/rb_clean_riak_data.sh ] && $RBBIN/rb_clean_riak_data.sh -f

  if [ "x$initialrole" == "xmaster" ]; then
    pdate "Creating initial topics"
    service rb-monitor stop
    service zookeeper start
    service kafka start
    wait_service zookeeper
    wait_service kafka
    $RBBIN/rb_create_topics.sh |grep -v "Due to limitations in metric names"
    service kafka stop
    service zookeeper stop
  fi
fi

/etc/init.d/chef-server-webui stop &>/dev/null

if [ "x$CMDFINISH_MASTER" != "x" ]; then
  pdate "Executing $CMDFINISH_MASTER"
  eval $CMDFINISH_MASTER
fi

rm -f /etc/redborder/master-running.lock
pdate "Finished master"
