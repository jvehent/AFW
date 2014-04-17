default['afw']['enable'] = true
default['afw']['enable_input_drop'] = true
default['afw']['enable_output_drop'] = false
default['afw']['enable_input_drop_log'] = true
default['afw']['enable_output_drop_log'] = true
# Passes -m comment --comment "Rule Name Here" to iptables
# On some platforms, you might need to load ipt_comment or xt_comment modules
default['afw']['use_rule_comments'] = true
# If always_update is true, the iptables rules will be reloaded on every chef
# run, even if nothing has changed
default['afw']['always_update'] = true

# Default attributes, do not modify
default['afw']['missing_user'] = false
default['afw']['tables']['filter']['rules'] = []
default['afw']['tables']['filter']['chains'] = []
default['afw']['tables']['raw']['rules'] = []
default['afw']['tables']['raw']['chains'] = []
default['afw']['tables']['mangle']['rules'] = []
default['afw']['tables']['mangle']['chains'] = []
default['afw']['tables']['nat']['rules'] = []
default['afw']['tables']['nat']['chains'] = []

default['afw']['ruby_source'] = "gempackage"
#default['afw']['ruby_source'] = "package"
#default['afw']['ruby_source'] = "none"

default['afw']['enable_rules_cleanup'] = true

case platform
when "centos","redhat","fedora"
  set['afw']['dnsruby_package_name'] = "rubygem-dnsruby"
when "debian","ubuntu"
  set['afw']['dnsruby_package_name'] = "ruby-dnsruby"
end
