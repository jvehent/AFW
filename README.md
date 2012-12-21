# The Advanced FireWall (afw) for Chef

__A__dvanced __F__ire__W__all (AFW) for Chef and Linux that uses Iptables
to dynamically configure inbound and outbound rules on nodes.

AFW uses Chef searches extensively to open access to systems. Instead of
specifying the IP addresses of a set of sources or destinations, AFW allows you
to specify searches in Chef syntax to list those systems. It is designed to be
a lot more dynamic and maintainable than regular firewalls, and allows for
filtering inbound and outbound traffic.

AFW support `raw` rules, that are just straight `iptables` syntax passed to the
template. For these, Chef searches are not supported, but it gives you access
to the full set of features `iptables` provides.

AFW runs on any Linux 2.6 or 3.x. It does *not* rely on distribution specific
wrapper, such as ufw for ubuntu, but calls `iptables-restore` directly.

## Rules definitions
Rules must be added in roles or nodes attributes. A typical rule looks like:

```
:afw =>
  :rules =>
    'MongoDB App Entry Point' => {
      :protocol => 'tcp',
      :direction => 'in',
      :interface => 'default',
      :user => 'mongodb',
      :source => ['(roles:*nodejs-app-node OR roles:*python-worker-node OR roles:*python-api-node) AND SAMETAG',
                  '10.4.76.2',
                  'backup-server.example.net']
      :dport => '27017'
    },
}

```

Rules must be added into `node[:afw][:rules]`, and follow this syntax:

```

:afw =>
  :rules =>
    '<rule name>' =>
      :direction => '<in|out>',
      :protocol => '<udp|tcp|icmp>',
      :user => '<local user from /etc/passwd>',
      :interface => '<default|all|eth0|eth1|br0|...>',
      :source => '<ip|fqdn|chef search>|['<ip|fqdn|chef search>',...]'>',
      :sport => '<integer(:integer))>',
      :destination => '<ip|fqdn|chef search>|['<ip|fqdn|chef search>',...]'>',
      :dport => '<integer(:integer)>',
      :env => '<production|staging|...>',
      :options => ['disable_env_limit', 'disable_syntax_check', ...]
}

```

* __Rule Name__ : A `string` that identifies the rule as uniquely as possible.

* __direction__ (__mandatory__): `in` is for inbound firewall rules.
`out` for outbound firewall rules.
Select whether the rule will apply to packets entering the system (`in`) or
leaving it (`out`).

* __protocol__ (__mandatory__):
Select the L4 protocol this rule applies to: `udp`, `tcp` or `icmp`.

* __user__ (___mandatory___):
Set the local user allowed to transmit packets. The user is checked only for
outbound firewall rules (iptables limitation) but must be set for inbound
rules as well, to ease auditing rules & systems.
Note: if the local user doesn't exists, the provisioning will fail at the end,
when the rules are loaded. If the user is installed by a package, the next chef
run will succeed and fix the issue.

* __dport__ (__mandatory__):
Set the destination port of the connections being filtered. This is mandatory.
Except when it's not (eg. icmp).

* __interface__ (*optional*):
Select the network interface. If absent of set to `all`, the interface
parameter won't be set at all, setting the rule on all interfaces.

* __source__ (__mandatory for `in` rules__):
Set the source IP of the packets. This parameter can either be a single IP or
network (eg. `10.1.2.0/32`), a Fully Qualified Domain Name (eg. `bob.colo.lair`)
 or a Chef Search (eg. `roles:mongodb`).
By default, searches are limited to the same `chef_environment` (eg. staging),
to allow for firewall rules that open connections between environments, you
will need an `heresy` parameter.
In a chef-search, you can also use they keyword `SAMETAG` that will limit the
search to the nodes that share the same tags. This is useful if, for example,
you want to open connections to a database from all nodes within the same
service tag, but not beyond.
The syntax for a search would look like: 'roles:whatever-api AND SAMETAG'.
If you have multiple sources and destinations, you can set them in a array:
```
'AMQP Producers' => {
  :direction => 'in',
  :user => 'rabbitmq',
  :protocol => 'tcp',
  :interface => 'default',
  :source => ['producer1.internal.domain.com',
              'producer2.internal.domain.com',
              '192.168.1.1',
              'roles:megaserver'],
  :dport => '5672'
}
```

* __destination__ (*Same as `source`*)

* __sport__ (*optional*):
Set the source port in the firewall rule. For `in` rules, that means the source
port of the remote machine. For `out` rules, that means the source port of this
node when establishing a connection to a remote node.

* __env__ (*optional*):
The env parameters can be used to limit the application of a rule to a specific
environment. If `:env => 'staging'` is set, the rule will be applied to nodes in
the staging environment only.

* __options__ (*optional*):
- disable_env_limit:
`disable_env_limit` can also used to cross environment.
If `:options => ['disable_env_limit']` is set, the source and destination searches
will return results from all environments, instead of limiting the result to the
environment the node lives in.
The following rule will allow production workers to connect to staging
BackendDB. Don't do that. Keep environments isolated as much as possible.
```
      'Production Worker to Staging BackendDB' => {
        :protocol => 'tcp',
        :direction => 'out',
        :user => 'application-user',
        :destination => 'roles:*backenddb* AND SAMETAG AND chef_environment:staging',
        :dport => '15017',
        :env => 'production',
        :options => ['disable_env_limit']
      }
```
- disable_syntax_check:
`disable_syntax_check` will turn off the rule validation step for a specific rule.
This is useful if you want to define a rule without source/destination, and
let another recipe populate the source/destination arrays later on.
```
      'API calls from servers' => {
        :protocol => 'tcp',
        :direction => 'in',
        :user => 'www-data',
        :dport => '80',
        :options => ['disable_syntax_check']
      },
```
You would then have a separate recipe that inserts IPs in this rule:
```
node[:afw][:rules]['API calls from servers'][:source] = []
ip_list = ['1.2.3.4', '4.5.6.7', '12.32.43.54']
ip_list.each do |ip|
  node[:afw][:rules]['API calls from servers'][:source].push(ip)
end
```

### Creating rules from external cookbooks
If you want a cookbook to create firewal rules directly, as opposed to storing
these rules in a roles, then you need to use the `create_rule()` function from
the `AFW` module.
Example: create outbound firewall rule for haproxy in the haproxy cookbook
#### depend in AFW in the metadata
`cookbooks/haproxy/metadata.rb`
```
[...]
depends 'AFW'
```
#### create the rule from the recipe using ruby
```
 # Call the AFW module to create the rule
 AFW.create_rule(node,
                 "Haproxy outbound to #{destination}:#{port}",
                 {'protocol' => 'tcp',
                  'direction' => 'out',
                  'user' => 'haproxy',
                  'destination' => "#{destination}",
                  'dport' => "#{port}"
                 })
```
Note that `AFW.create_rule()` must be called from a normal section of ruby code
directly (not from a `ruby_block`) to ensure that the rules are compiled at
chef compile time. The AFW template will later (at runtime) populate these rules
into the `iptables-restore` file.

### Predefined rules
Predefined rules are iptables rules that are used directly by AFW. Those rules
are used for specific purposes only, such as using a very particular module for
which AFW wouldn't have any support.
Predefined rules only support 2 arguments: `table` and `rule`.

* __table__:
the netfilter table on which this rule must be applied. One of `nat`, `raw`,
`mangle` or `filter.

* __rule__: the firewall rule itself, in iptables-save format (do not specify
a table in this format, or it will fail).

example:
```
  :afw => {
    :rules => {

      'Accept all packets router through the bridge' => {
        :table => 'filter',
        :rule => '-I FORWARD -o br0 -m physdev --physdev-is-bridged -j ACCEPT'
      },

      'Drop connection to the admin panel on the eth0 interface' => {
        :table => 'mangle',
        :rule => '-A INPUT -i eth0 -p tcp --dport 80 -m string --string "get /admin http/1.1" --icase --algo bm -m conntrack --ctstate ESTABLISHED -j DROP'
      },

      'DNAT a source IP to change the destination port' => {
        :table => 'nat',
        :rule => '-A PREROUTING -i eth3 -s 201.23.72.3 -p tcp --dport 8008 -j DNAT --to-destination 127.0.0.1:1234'
      },

      'Dont do conntrack on this specific user's UDP packets' => {
        :table => 'raw',
        :rule => '-A OUTPUT -o eth0 -p udp -m owner --uid-owner 105 -j NOTRACK'
      }
    }
  }
```

## Rules Generation

The recipe will generate a rule file in `/etc/firewall/rules.iptables` that
conforms to the iptables-save/restore syntax.
At the end of the chef-run, and if the rules file has been modified during the
run, the `iptables-restore` command will reload the entire ruleset.

Here's an example of templated ruleset. Notice how the rules are regrouped by
system user, to make them easier to read.

```
# Generated by AFW on Tue Sep 25 02:55:32 +0000 2012

*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -o lo -j NOTRACK
-A PREROUTING -i lo -j NOTRACK
COMMIT

*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT

*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# some default rules we want to open everywhere
-A INPUT -p tcp --dport 22 -s 1.0.0.0/8 -j ACCEPT
-A INPUT -p tcp --dport 22 -s 12.30.0.0/16 -j ACCEPT
-A OUTPUT -p udp --dport 53 -d 1.0.0.0/8 -j ACCEPT

:app-user - [0:0]
-A OUTPUT -m owner --uid-owner 999 -m state --state NEW -j app-user
-A app-user -o eth0 -p tcp --dport 2003 -d 1.2.3.4 -m conntrack --ctstate NEW -j ACCEPT
-A app-user -o eth0 -p tcp --dport 27017 -d 1.1.4.3 -m conntrack --ctstate NEW -j ACCEPT
-A app-user -o eth0 -p tcp --dport 5672 -d 1.1.4.9 -m conntrack --ctstate NEW -j ACCEPT
-A app-user -o eth0 -p tcp --dport 80 -d 1.1.4.10 -m conntrack --ctstate NEW -j ACCEPT
-A app-user -o eth0 -p udp --dport 8125 -d 1.1.4.74 -m conntrack --ctstate NEW -j ACCEPT
-A app-user -j LOG --log-prefix "DROP_AFW_OUTPUT_app-user " --log-uid --log-tcp-sequence

:haproxy - [0:0]
-A OUTPUT -m owner --uid-owner 110 -m state --state NEW -j haproxy
-A INPUT -i eth0 -p tcp --dport 10097 -s 0.0.0.0/0 -m conntrack --ctstate NEW -j ACCEPT
-A haproxy -o eth0 -p tcp --dport 2003 -d 1.1.0.25 -m conntrack --ctstate NEW -j ACCEPT
-A haproxy -o eth0 -p tcp --dport 2003 -d 1.1.0.37 -m conntrack --ctstate NEW -j ACCEPT
-A haproxy -o eth0 -p tcp --dport 80 -d 1.1.4.58 -m conntrack --ctstate NEW -j ACCEPT
-A haproxy -j LOG --log-prefix "DROP_AFW_OUTPUT_haproxy " --log-uid --log-tcp-sequence

:nagios - [0:0]
-A OUTPUT -m owner --uid-owner 105 -m state --state NEW -j nagios
-A INPUT -i eth0 -p tcp --dport 5666 -s 1.1.0.33 -m conntrack --ctstate NEW -j ACCEPT
-A nagios -j LOG --log-prefix "DROP_AFW_OUTPUT_nagios " --log-uid --log-tcp-sequence

:ntp - [0:0]
-A OUTPUT -m owner --uid-owner 104 -m state --state NEW -j ntp
-A ntp -o eth0 -p udp --dport 123 -d ntp.example.net -m conntrack --ctstate NEW -j ACCEPT
-A ntp -j LOG --log-prefix "DROP_AFW_OUTPUT_ntp " --log-uid --log-tcp-sequence

:root - [0:0]
-A OUTPUT -m owner --uid-owner 0 -m state --state NEW -j root
-A INPUT  -p icmp -s 0.0.0.0/0 -m conntrack --ctstate NEW -j ACCEPT
-A root -o eth0 -p tcp --dport 514 -d 1.1.3.18 -m conntrack --ctstate NEW -j ACCEPT
-A root -o eth0 -p udp --dport 514 -d 1.1.3.18 -m conntrack --ctstate NEW -j ACCEPT
-A root -p icmp -d 0.0.0.0/0 -m conntrack --ctstate NEW -j ACCEPT
-A root -j LOG --log-prefix "DROP_AFW_OUTPUT_root " --log-uid --log-tcp-sequence

:snmp - [0:0]
-A OUTPUT -m owner --uid-owner 108 -m state --state NEW -j snmp
-A snmp -o eth0 -p udp --dport 162 -d 1.1.0.23 -m conntrack --ctstate NEW -j ACCEPT
-A snmp -j LOG --log-prefix "DROP_AFW_OUTPUT_snmp " --log-uid --log-tcp-sequence

:www-data - [0:0]
-A OUTPUT -m owner --uid-owner 33 -m state --state NEW -j www-data
-A INPUT -i eth0 -p tcp --dport 80 -s 1.1.4.4 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -i eth0 -p tcp --dport 80 -s 1.1.4.1 -m conntrack --ctstate NEW -j ACCEPT
-A www-data -j LOG --log-prefix "DROP_AFW_OUTPUT_www-data " --log-uid --log-tcp-sequence

-A INPUT -j LOG --log-prefix "DROP_AFW_INPUT " --log-uid --log-tcp-sequence
-A INPUT -j DROP

-A OUTPUT -j LOG --log-prefix "DROP_AFW_OUTPUT " --log-uid --log-tcp-sequence
COMMIT
```

The `INPUT` chain contains all of the rules for incoming connections. It does
not redirect packets to other chains, but accept or drop them directly.

The `OUTPUT` chain is a little different. Depending on the owner of the socket
emitting packets, it will direct the packets to a different chain, named after
the socket owner.
In the example above, the packet from the `snmp` user will be directed to the
chain named `snmp`. You can see in this chain that the first two rules accept
packet, while the 3rd one will `LOG` to syslog when it is reached (it shouldn't
be). Eventually, a `DROP` will follow that log rule to drop packets that aren't
suppose to be sent.

# ATTRIBUTES

* `default[:afw][:enable] = true` : enable or disable the firewall restore
command. If set the false, the rules will still be populated in 
`/etc/firewall/rules.iptables` but the restore command will not be issued.

* `default[:afw][:enable_input_drop] = true` : DROP all input packets by defaut
* `default[:afw][:enable_output_drop] = true` : DROP all output packets by defaut
* `default[:afw][:enable_input_drop_log] = true` : LOG when DROP input packets
* `default[:afw][:enable_output_drop_log] = true` : LOG when DROP output packets

## Dependencies
### Ohai network_addr
This cookbooks relies on the custom AWeber Ohai plugin which sets the two
following attributes:
`node[:network][:lanip]` is set to the IP of the node on the LAN network
`node[:network][:laniface]` is set to the network interface on the LAN
While AFW can probably run with this plugin, it makes you life easier when you
want to open rules on your LAN interface. We typically enfore `eth0` to be the
LAN interface, but feel free to use whatever you want.

Plugin source:
```
provides "network"

require_plugin "hostname"
require_plugin "#{os}::network"

network['interfaces'].each do |iface, addrs|

  addrs['addresses'].each do |ip, params|
    network["ipaddress_#{iface}"] = ip if params['family'].eql?('inet')
    network["ipaddress6_#{iface}"] = ip if params['family'].eql?('inet6')
    network["macaddress_#{iface}"] = ip if params['family'].eql?('lladdr')
  end

end

laniface = from("[ -e /vagrant ] && echo eth1 || echo eth0")

network['lanip'] = network["ipaddress_#{laniface}"]
network['laniface'] = laniface

network
```

# LICENSE
```
 +-------------------------------------------------------------------------+
 | Advanced FireWall (AFW) Cookbook for Opscode Chef                       |
 |                                                                         |
 | Copyright (C) 2012, AWeber, Julien Vehent                               |
 |                                                                         |
 | This program is free software; you can redistribute it and/or modify    |
 | it under the terms of the GNU General Public License version 2          |
 | as published by the Free Software Foundation.                           |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 |                                                                         |
 | You should have received a copy of the GNU General Public License along |
 | with this program; if not, write to the Free Software Foundation, Inc., |
 | 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.             |
 |                                                                         |
 +-------------------------------------------------------------------------+
```
