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
node.default['afw']['chains'] = {}
node.default['afw']['tables']['filter']['rules'] = []
node.default['afw']['tables']['filter']['chains'] = []
node.default['afw']['tables']['raw']['rules'] = []
node.default['afw']['tables']['raw']['chains'] = []
node.default['afw']['tables']['mangle']['rules'] = []
node.default['afw']['tables']['mangle']['chains'] = []
node.default['afw']['tables']['nat']['rules'] = []
node.default['afw']['tables']['nat']['chains'] = []

class Chef::Recipe
  include AFW
end

node['afw']['rules'].each do |name,params|
  Chef::Log.info("AFW: processing rule '#{name}'")
  if process_rule(node, name, params)
    Chef::Log.info("AFW: finished processing of rule '#{name}'")
  else
    Chef::Log.info("AFW: rule '#{name}' failed. Skipping it.")
  end
end

package 'iptables'

directory '/etc/firewall' do
  owner 'root'
  group 'root'
  mode '0700'
  action :create
end

template '/etc/firewall/rules.iptables' do
  mode 0400
  owner 'root'
  group 'root'
end

cookbook_file '/etc/firewall/empty.iptables' do
  mode 0400
  owner 'root'
  group 'root'
  source 'empty.iptables'
end

case node[:platform]
  when 'ubuntu'
    cookbook_file '/etc/init/firewall.conf' do
      owner 'root'
      group 'root'
      mode 0600
      source 'upstart-firewall.conf'
    end
  else
    cookbook_file '/etc/init.d/firewall' do
      owner 'root'
      group 'root'
      mode 0750
      source 'initd-firewall'
    end
end

service 'firewall' do
  case node[:platform]
    when 'ubuntu'
      if node[:platform_version].to_f >= 9.10
        provider Chef::Provider::Service::Upstart
      else
        priority(99)
      end
  end
  action [:enable, :start]
end

ruby_block 'cleanup_rules' do
  block do
    node.set['afw']['rules'] = {}
    node.set['afw']['chains'] = {}
    node.set['afw']['tables'] = {}
  end
end

execute 'restore firewall' do
  command 'iptables-restore < /etc/firewall/rules.iptables'
  action :nothing
  if node['afw']['enable']
    subscribes :run,
               resources(:template => '/etc/firewall/rules.iptables'),
               :delayed
  else
    Chef::Log.error "AFW: is disabled. enable='#{node['afw']['enable']}'"
  end
  notifies :create, 'ruby_block[cleanup_rules]'
end
