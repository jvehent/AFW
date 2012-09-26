#
# Author:: Julien Vehent
# Cookbook Name:: afw
# Recipe:: default
#
# Copyright 2012, AWeber, Julien Vehent
#
# See LICENSE in README file
#

# flush all stored compiled rules at chef-run, and regenerate them
node['afw']['chains'] = {}
node['afw']['tables']['filter']['rules'] = []
node['afw']['tables']['filter']['chains'] = []
node['afw']['tables']['raw']['rules'] = []
node['afw']['tables']['raw']['chains'] = []
node['afw']['tables']['mangle']['rules'] = []
node['afw']['tables']['mangle']['chains'] = []
node['afw']['tables']['nat']['rules'] = []
node['afw']['tables']['nat']['chains'] = []

class Chef::Recipe
  include AFWCore
end

node['afw']['rules'].each do |name,params|
  log("AFW: processing rule '#{name}'")
  if process_rule(node, name, params)
    log("AFW: finished processing of rule '#{name}'")
  end
end

directory "/etc/firewall" do
  owner "root"
  group "root"
  mode "0700"
  action :create
end

template "/etc/firewall/rules.iptables" do
  mode 0400
  owner "root"
  group "root"
end

package "iptables"

execute "restore firewall" do
  command "iptables-restore < /etc/firewall/rules.iptables"
  action :nothing
  if node['afw']['enable']
    subscribes :run,
                resources(:template => "/etc/firewall/rules.iptables"),
                :delayed
  else
    Chef::Log.error "AFW: is disabled. enable='#{node['afw']['enable']}'"
  end
end
