#
# Cookbook Name:: afw
# Recipe:: cloudstack-agent
#
# Copyright 2012, AWeber
#
# All rights reserved - Do Not Redistribute
#

def insert_rule_into_table(rule, nftable)
  if rule =~ /^-(A|I)/ and rule =~ /-j/
    node['afw']['tables'][nftable]['rules'] << rule.chomp
    log("AFW::Cloudstack-agent: Preserving rule '#{rule.chomp}'")
  end
end

# Cloudstack will define rules in the FORWARD chain and FILTER table, we want
# to save those rules and inject them in AFW, so that they are kept between runs
cmd = Chef::ShellOut.new("iptables -S FORWARD -t filter")
cmd_ret = cmd.run_command
cmd.stdout.each do |line|
  insert_rule_into_table(line, "filter")
end
cmd = Chef::ShellOut.new("iptables -S PREROUTING -t nat")
cmd_ret = cmd.run_command
cmd.stdout.each do |line|
  insert_rule_into_table(line, "nat")
end
cmd = Chef::ShellOut.new("iptables -S POSTROUTING -t nat")
cmd_ret = cmd.run_command
cmd.stdout.each do |line|
  insert_rule_into_table(line, "nat")
end

# Now save the custom chains from all tables, but take only the ones that
# are not created by AFW itself
%w{filter nat raw mangle}.each do |nftable|
  cmd = Chef::ShellOut.new("iptables-save -t #{nftable}|grep '^:'")
  cmd_ret = cmd.run_command
  cmd.stdout.each do |line|
    chain_str = line.split.first
    chain = chain_str[1,30]
    log("AFW::Cloudstack-agent: Evaluating chain '#{chain}'")
    if not (nftable.eql?('filter') and node['afw']['chains'].include?(chain)) \
       and not (chain =~ /INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING/)
      node['afw']['tables'][nftable]['chains'] << line.chomp
      log("AFW::Cloudstack-agent: Preserving chain '#{chain}' in table #{nftable}")
      getchain = Chef::ShellOut.new("iptables -S #{chain} -t #{nftable}")
      getchain_ret = getchain.run_command
      getchain.stdout.each do |rule|
        insert_rule_into_table(rule, nftable)
      end
    end
  end
end
