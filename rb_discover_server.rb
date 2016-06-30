#!/usr/bin/env ruby

#######################################################################
## Copyright (c) 2014 ENEO Tecnología S.L.
## This file is part of redBorder.
## redBorder is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
## redBorder is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License License for more details.
## You should have received a copy of the GNU Affero General Public License License
## along with redBorder. If not, see <http://www.gnu.org/licenses/>.
########################################################################

require 'getopt/std'
require 'yaml'
require 'json'
require 'system/getifaddrs' 
require 'symmetric-encryption'

require File.join(ENV['RBDIR'].nil? ? '/usr/lib/redborder' : ENV['RBDIR'],'lib/udp_ping')

def local_ip?(ip)
    ret = false
    System.get_all_ifaddrs.each do |x|
        if x[:inet_addr].to_s == ip.to_s
            # local ip address match
            ret = true
            break
        end
    end
    ret
end

USERDATA="/var/lib/cloud/instance/user-data.txt"

if File.exist?USERDATA
    File.open(USERDATA).each do |line|
        unless line.match(/^\s*DISCOVER_KEY=(?<key>[^\s]*)\s*$/).nil?
            SymmetricEncryption.cipher = SymmetricEncryption::Cipher.new(:key=>line.match(/^\s*DISCOVER_KEY=(?<key>[^\s]*)\s*$/)[:key],:cipher_name => 'aes-128-cbc')
        end
    end
end

cdomain = File.read("/etc/redborder/cdomain").split("\n").first if File.exist?"/etc/redborder/cdomain"
cdomain="redborder.cluster" if cdomain.nil? or cdomain==""

def usage()
  printf("INFO: rb_discover_server.rb [-h][-o][-d][ -c config_file ]\n")
  printf("          -h -> print this help\n")
  printf("          -o -> ignore local request\n")
  printf("          -d -> daemon process\n")
  exit 1
end

config_file_str = "/etc/rb-discover/config.yml"
port = 8070
local_client_ip = nil
accept_local_request = true

opt = Getopt::Std.getopts("c:hod")
usage if opt["h"]

Process.daemon if opt["d"]

p "Starting redBorder-discover server..."

if File.exist?config_file_str
    config_file = File.read(config_file_str)
    config      = YAML.load(config_file)
else
    config      = {}
end

config["answer"] = {} if config["answer"].nil?

if opt["o"]
    accept_local_request = false
    local_client_ip=`ip a s bond1 2>/dev/null|grep brd|grep inet|head -n 1 | awk '{print $2}'|sed 's|/.*||'`.chomp
    # better: System.get_all_ifaddrs?
end

thread = UDPPing.start_service_announcer(port) do |client_msg, client_ip|
    #if client_ip!=local_client_ip and !client_msg.nil? 
    if (not local_ip?(client_ip) or accept_local_request) and (not client_msg.nil?) 
        # fisrt, read configuration file if exist or initialize client_data as an empty json
        begin 
            client_data = JSON.parse(client_msg)
        rescue Exception => e  
            client_data = {}
        end
        
        # Next, build the answer
        answer=config["answer"].clone
        answer["installed"] = File.exist?"/etc/redborder/cluster-installed.txt"
        answer["master"]    = File.exist?"/etc/redborder/master.lock"
        if answer["private_rsa"].nil? or answer["chef_server"].nil? or !answer["installed"]
            # There are no config created or not installed file?, we are not ready
            answer["ready"] = false 
        else
            # we are ready ;-)
            answer["ready"] = true
        end
        
        if (!client_data["only_ready"] or (client_data["only_ready"] and (answer["master"] or answer["installed"] or answer["ready"])))
            # The client is connecting directly because client_data["only_ready"] = false, due to provided the option "-r" or
            # The client connect via broadcast and thi server is master, installed or ready
            if ( client_data["cdomain"].nil? or client_data["cdomain"].chomp == "" or client_data["cdomain"].chomp == cdomain )
                # the client came from the same cdomain or its cdomain is not defined, so the client is allowed
                answer["client"]     = client_ip
                answer["client_msg"] = client_msg
                # Setting mode for the client
                if File.exists?'/etc/redborder/manager_mode'
                    # from manager_mode
                    answer["mode"] = File.open('/etc/redborder/manager_mode', &:readline).strip
                elsif File.exists?'/etc/chef/initialrole'
                    # or from chef (initialrole)
                    answer["mode"] = File.open('/etc/chef/initialrole', &:readline).strip
                else
                    # or set default mode to corezk
                    answer["mode"] = "corezk"
                end
                answer["mode"] = "corezk" if answer["mode"].nil?
                p "New redBorder client #{client_ip} (msg: #{client_msg})"
                ret=answer
            else
                p "ERROR: The client #{client_ip} is not allowed because it asks for other cluster domain (#{client_data["cdomain"]}) different than the server one (#{cdomain})"
                ret=nil
            end
        else
            p "ERROR: The client #{client_ip} is not allowed because this server is not ready -> master:#{answer["master"]}; installed:#{answer["installed"]}; ready:#{answer["ready"]}"
            ret=nil
        end
    else
        p "ERROR: Local client is not allowed (#{client_ip})"
        ret=nil
    end
    ret
end

thread.join

## vim:ts=4:sw=4:expandtab:ai:nowrap:formatoptions=croqln:
