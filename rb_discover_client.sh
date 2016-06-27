#!/bin/bash

source /etc/profile.d/redborder-common.sh
source /etc/profile.d/rvm.sh

rvm gemset use rb-discover

exec rb_discover_client.rb $*
