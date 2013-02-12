default['afw']['enable'] = true
default['afw']['enable_input_drop'] = true
default['afw']['enable_output_drop'] = false
default['afw']['enable_input_drop_log'] = true
default['afw']['enable_output_drop_log'] = true
# Passes -m comment --comment "Rule Name Here" to iptables
# On some platforms, you might need to load ipt_comment or xt_comment modules
default['afw']['use_rule_comments'] = true

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
