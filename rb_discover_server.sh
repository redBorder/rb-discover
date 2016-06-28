#!/bin/bash

source /etc/profile.d/redborder-common.sh
source /etc/profile.d/rvm.sh

rvm gemset use default

exec rb_discover_server.rb $*
