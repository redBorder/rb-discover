#!/bin/bash

sys_ip_rb_manager=$1 # remote manager node (master)
sys_manager_mode=$2
sys_manager_rsa=$3

CLIENTPEM="/etc/chef/client.pem"
VALIDATIONFILE="/etc/chef/validation.pem"
DATABAGKEY="/etc/chef/encrypted_data_bag_secret"
RUBYDIR=$(ls -r -d /usr/local/rvm/rubies/ruby-2.*| grep -v "@global" | head -n 1)
GEMDIR=$(ls -r -d /usr/local/rvm/gems/ruby-2.*| grep -v "@global" | head -n 1)

function usage(){
  echo "$0 <manager_ip> <mode> [<identity_file>] "
  exit 1
}

# First boot Initial configufations
[ "x$sys_ip_rb_manager" == "x" -o "x$sys_manager_mode" == "x" ] && usage

# Register FLAG
if [ -f $CLIENTPEM ];then
  sys_flag_registered=1
else
  sys_flag_registered=0
fi

# f_sys_rb_register (MAIN)

# Set domain. ##CMO## Where "/etc/redborder/cdomain" is configured? ##
[ -f /etc/redborder/cdomain ] && cdomain=$(head -n 1 /etc/redborder/cdomain | tr '\n' ' ' | awk '{print $1}')
[ "x$cdomain" == "x" ] && cdomain="redborder.cluster"

# Set manager mode. Default: custom
MANAGER_SEL_MODE="$sys_manager_mode"
[ "x$MANAGER_SEL_MODE" == "x" ] && MANAGER_SEL_MODE="custom"
# Check a valid mode
if [ "x$MANAGER_SEL_MODE" != "xslave" -a "x$MANAGER_SEL_MODE" != "xcompute" -a "x$MANAGER_SEL_MODE" != "xrealtime" -a "x$MANAGER_SEL_MODE" != "xhistorical" -a "x$MANAGER_SEL_MODE" != "xkafka" -a "x$MANAGER_SEL_MODE" != "xzookeeper" -a "x$MANAGER_SEL_MODE" != "xdatabase" -a "x$MANAGER_SEL_MODE" != "xweb" -a "x$MANAGER_SEL_MODE" != "xs3" -a "x$MANAGER_SEL_MODE" != "xhadoop" -a "x$MANAGER_SEL_MODE" != "xstorm_nimbus" -a "x$MANAGER_SEL_MODE" != "xstorm_supervisor" -a "x$MANAGER_SEL_MODE" != "xnprobe" -a "x$MANAGER_SEL_MODE" != "xzoo_kafka" -a "x$MANAGER_SEL_MODE" != "xweb_full" -a "x$MANAGER_SEL_MODE" != "xkafkaconsumer" -a "x$MANAGER_SEL_MODE" != "xcoreriak" -a "x$MANAGER_SEL_MODE" != "xbrokerweb" -a "x$MANAGER_SEL_MODE" != "xzoo_web" -a "x$MANAGER_SEL_MODE" != "xcore" -a "x$MANAGER_SEL_MODE" != "xcorezk" -a "x$MANAGER_SEL_MODE" != "xconsumer" -a "x$MANAGER_SEL_MODE" != "xnginx" -a "x$MANAGER_SEL_MODE" != "xenrichment" -a "x$MANAGER_SEL_MODE" != "xcustom" -a "x$MANAGER_SEL_MODE" != "xmiddleManager" -a "x$MANAGER_SEL_MODE" != "xcoreplus" -a "x$MANAGER_SEL_MODE" != "xsamza" -a "x$MANAGER_SEL_MODE" != "xwebdruid" -a "x$MANAGER_SEL_MODE" != "xbroker" -a "x$MANAGER_SEL_MODE" != "xhttp2k" -a "x$MANAGER_SEL_MODE" != "xk2http"  -a "x$MANAGER_SEL_MODE" != "xdatanode" ]; then
  f_set_color red
  echo "ERROR: mode not valid ($MANAGER_SEL_MODE)!!!!"
  f_set_color norm
fi
echo "Selected Mode: $MANAGER_SEL_MODE"

# Check if master node exists and get through SCP some configuration files to TMPDIR

# Dest temporal dir
TMPDIR="/tmp/dir$RANDOM"
rm -rf $TMPDIR && mkdir -p $TMPDIR

# Delete master entry in known_hosts files ##CMO##
[ -f ~/.ssh/known_hosts ] && sed -i "/^${sys_ip_rb_manager} /d" ~/.ssh/known_hosts

# Files to download from master node
files_scp="/etc/chef/validation.pem $DATABAGKEY /home/redborder/.chef/trusted_certs/erchef.${cdomain}.crt /etc/hosts /etc/keepalived/keepalived.conf /etc/redborder/cluster-installed.txt /root/.chef/admin.pem /home/redborder/.s3cfg"
#mkdir -p /root/.chef/trusted_certs

# downloading files from master
if [ "x$sys_manager_rsa" != "x" -a -f $sys_manager_rsa ]; then
  scp -i $sys_manager_rsa -o StrictHostKeyChecking=no -q redborder@${sys_ip_rb_manager}:"$files_scp" $TMPDIR;
else
  echo -n "INFO: You are going to connect via ssh to redborder@${sys_ip_rb_manager}"
  scp -o StrictHostKeyChecking=no -q redborder@${sys_ip_rb_manager}:"$files_scp" $TMPDIR;
fi

# Check downloaded files form master node
scp_error=1
if [ ! -f $TMPDIR/validation.pem ]; then
    scp_error_msg="Error downloading validation cert file"
elif [ ! -f $TMPDIR/$(basename $DATABAGKEY) ]; then
    scp_error_msg="Error downloading encrypted data bag file"
elif [ ! -f $TMPDIR/erchef.${cdomain}.crt ]; then
    scp_error_msg="Error downloading erchef.${cdomain}.crt file"
else
    if [ -f $TMPDIR/cluster-installed.txt ]; then
        if [ ! -f $TMPDIR/admin.pem ]; then
            scp_error_msg="Error downloading admin.pem file"
        elif [ ! -f $TMPDIR/.s3cfg ]; then
            scp_error_msg="Error downloading .s3cfg file"
        else
            scp_error=0
        fi
    else
        scp_error_msg="The remote manager has not finished configuring the cluster. Please wait"
    fi
fi

### Begin configuration if manager is ready ###

if [ $scp_error -eq 0 ]; then
  # connection ok ... stop all services
  echo "Stopping services ... Please be patient"
  service chef-client stop
  PIDCHEF=$(pidof chef-client)
  [ "x$PIDCHEF" != "x" ] && kill -9 $PIDCHEF

  rb_service all stop

  # ?¿?¿?¿?¿ ##CMO##
  ifdown lo:0 &>/dev/null
  ifdown lo:1 &>/dev/null

  # Set date & time
  f_sync_manager_time

  # Overwrite /etc/hosts until chef-client create it
  cat >/etc/hosts <<rBEOF
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 $(hostname)
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

# Virtual
${sys_ip_rb_manager}     virtual.${cdomain} erchef.${cdomain}

# S3 names
rBEOF
  ### RIAK / S3 ###
  # Obtaining S3 host domains
  s3names=""
  # If slave, get it from downloaded files from master
  if [ -f ${TMPDIR}/hosts ]; then
    s3names=$(egrep "riak.${cdomain}| rbookshelf\.| bookshelf\." ${TMPDIR}/hosts | grep -v localhost | sed 's/[^ ]*[ ]*//' | tr '\n' ' ')
  else # If master, set with defined cdomain
    s3names="riak.${cdomain} s3.${cdomain} redborder.s3.${cdomain} riak-cs.s3.${cdomain} rbookshelf.s3.${cdomain} bookshelf.s3.${cdomain}"
  fi
  echo "${sys_ip_rb_manager}      $s3names" >> /etc/hosts

  # Checking connectivity
  echo -n "Checking S3 connectivity: "
  # Creating new s3cfg
  [ -f /root/.s3cfg ] && mv /root/.s3cfg /root/.s3cfg.bak
  mv ${TMPDIR}/.s3cfg /root/.s3cfg # Get s3cfg downloaded from master
  grep "^host_base" /root/.s3cfg | grep -q "s3.${cdomain}$"
  if [ $? -eq 0 ]; then
      s3cmd ls 2>/dev/null | awk '{print $3}'|grep -q "^s3://"
      if [ $? -eq 0 ]; then
        e_ok
      else
        e_fail
        echo    "WARNING: s3 looks not accesible and probably the register will not work."
        rm -f /root/.s3cfg.bak
      fi
  else
    echo -n " (not verified - maybe external s3)"
    e_ok
  fi

  ### CERTS ###
  rm -f $CLIENTPEM $VALIDATIONFILE $DATABAGKEY
  mv ${TMPDIR}/validation.pem $VALIDATIONFILE
  mv ${TMPDIR}/$(basename $DATABAGKEY) $DATABAGKEY

  # copying valid certs
  rm -f /root/.chef/trusted_certs/erchef.*.crt /home/redborder/.chef/trusted_certs/erchef.*.crt
  mkdir -p /root/.chef/trusted_certs/ && mkdir -p /home/redborder/.chef/trusted_certs/

  mv ${TMPDIR}/erchef.${cdomain}.crt /root/.chef/trusted_certs/
  cp /root/.chef/trusted_certs/erchef.${cdomain}.crt /home/redborder/.chef/trusted_certs/
  chown -R redborder:redborder /home/redborder/.chef

  mv ${TMPDIR}/admin.pem /root/.chef/admin.pem

  # Set ACL for /etc/chef/validation.pem and /root/.chef/admin.pem
  setfacl -m u:redborder:r /etc/chef/validation.pem /root/.chef/admin.pem

  ### CHEF-CLIENT CONFIG ###
  # If chef-client is not configured yet, creates a new client.rb from default file
  if [ ! -f /etc/chef/client.rb -a ! -f /etc/chef/client.rb.default ]; then
    # Creating default client.rb.default file
    cat >/etc/chef/client.rb.default <<EOF
log_level        :info
validation_key   "/etc/chef/validation.pem"
validation_client_name "chef-validator"
client_key       "/etc/chef/client.pem"
chef_server_url  "http://erchef.${cdomain}:8000"
file_cache_path  "/var/chef/cache"
file_backup_path "/var/chef/backups"
pid_file         "/var/run/chef/client.pid"
EOF

    # Creates client.rb from client.rb.default
    cp /etc/chef/client.rb.default /etc/chef/client.rb
    sed -i "s%^chef_server_url.*%chef_server_url  \"http://${sys_ip_rb_manager}:8000\"%" /etc/chef/client.rb

    # Creates role-manager-once
    cat >/etc/chef/role-manager-once.json <<EOF
{
"run_list": [ "role[manager]" ],
"redBorder": {
"force-run-once": true
}
}
EOF
  fi

  ### Cleaning system ###
  # Deleting riak data
  /usr/bin/rb_clean_riak_data.sh -af
  # Deleting postgresql local data
  echo -n "Deleting local postgresql data "
  rm -rf /var/opt/chef-server/postgresql/data/*
  p_ok_fail $?
  # Deleting bookshelf local data
  echo -n "Deleting local bookshelf s3 data "
  rm -rf /var/opt/chef-server/bookshelf/data/bookshelf/*
  p_ok_fail $?
  # Deleting hadoop local data
  echo -n "Deleting local hadoop data "
  rm -rf /var/lib/hadoop/*
  rm -rf /var/log/hadoop/*
  mkdir -p /var/lib/hadoop/data
  chown hadoop:hadoop /var/lib/hadoop/data
  p_ok_fail 0
  # Deleting temp a log files
  rm -rf /tmp/kafka/* /tmp/realtime/* /tmp/druid/* /tmp/zookeeper/* /opt/rb/var/www/rb-rails/log/* /var/log/druid/* /var/log/kafka/* /var/log/nprobe/* /var/log/rb-webui/* /var/log/zookeeper/*
  rm -f /etc/redborder/cluster.lock
  rm -f /var/chef/cache/chef-client-running.pid

  # Flag?
  touch /etc/redborder/cluster-installed.lock

  ### BEGIN CHEF-CLIENT REGISTER ###
  echo "Registering ... (Please wait) "
  /usr/bin/rb_run_chef_once.sh # &>/dev/null

  # Chef initial configuring
  step=0
  while [ $step -lt 40 ]; do #Max 40 chef runs
    step=$(( $step + 1 ))
    if [ -f $VALIDATIONFILE -a -f $CLIENTPEM -a -f /var/www/rb-rails/config/rb-chef-webui.pem -a -f /etc/redborder/manager_index -a "x$(head -n 1 /etc/redborder/manager_index 2>/dev/null)" != "x" ]; then
        # Finish configuration
        sys_flag_registered=1
        f_set_color green
        echo
        echo -n "Manager registered successfully with chef server"
        f_set_color norm
        e_ok
        step=1000 #Flag for registered manager
    else
        sleep 3
        /usr/bin/rb_run_chef_once.sh &>/dev/null
    fi
    # Creates manager role when rb-chef-webui.pem is ready
    [ -f /var/www/rb-rails/config/rb-chef-webui.pem ] && /usr/bin/rb_create_manager_role.rb
  done

  if [ $step != 1000 ]; then
      echo -n "Manager NOT registered "
      sys_flag_registered=0
      e_fail
  else
      # Create manager role
      /usr/bin/rb_create_manager_role.rb

      # Set manager mode
      /usr/bin/rb_set_mode.rb ${MANAGER_SEL_MODE}

      # Create chef node
      [ -f /etc/chef/initialdata.json ] && /usr/bin/rb_chef_node /etc/chef/initialdata.json

      # more chef runs...
      /usr/bin/rb_run_chef_once.sh &>/dev/null
      /usr/bin/rb_run_chef_once.sh &>/dev/null
  fi

  # Removing install lock flags
  rm -f /etc/redborder/cluster-installed.lock
  rm -f /etc/redborder/riak_blocked #Where is created??? ##CMO##

  chkconfig --add chef-client
  service chef-client start &>/dev/null

else # $scp_error == 1
    if [ "x$scp_error_msg" != "x" ]; then
        echo_fail "$scp_error_msg"
    else
        echo_fail "Unkonwn error!!!"
    fi
fi

}

f_sync_manager_time(){
  /etc/init.d/ntpd status &>/dev/null
  NTPDSTARTED=$?
  if [ $NTPDSTARTED -eq 0 ]; then
      #ntpd is started
      /etc/init.d/ntpd stop
  fi

  echo -n "Synchronizing time with ${sys_ip_rb_manager} ... "
  ntpdate ${sys_ip_rb_manager} &>/dev/null
  RET=$?
  p_ok_fail $RET
  hwclock --systohc
  if [ $RET -eq 0 ]; then
      hwclock --systohc
  fi
  sleep 3
  chkconfig ntpd on
  chkconfig ntpdate on

  if [ $NTPDSTARTED -eq 0 ]; then
      /etc/init.d/ntpd start
  fi
  sleep 2
}

# Fake register
# echo "f_sys_rb_register $manager $mode $rsakey"
# logger "f_sys_rb_register $manager $mode $rsakey"
