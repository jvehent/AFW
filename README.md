# The Advanced FireWall (afw) for Chef

__A__dvanced __F__ire__W__all (AFW) for Chef and Linux that uses Iptables and
to dynamically configure inbound and outbound rules on each node.

## Dependencies
### Ohai network_addr
This cookbooks depends on the custom AWeber Ohai plugin which sets the two
following attributes:
`node[:network][:lanip]` is set to the IP of the node on the LAN network
`node[:network][:laniface]` is set to the network interface on the LAN

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
Select the network interface. If undef, the default interface will be used.
if `all`, the interface parameter won't be set at all.

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

Here's an example of ruleset

```
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
 698K   35M ACCEPT     all  --  lo     any     anywhere             anywhere
34569   25M ACCEPT     all  --  any    any     anywhere             anywhere            state RELATED,ESTABLISHED
    5   220 ACCEPT     tcp  --  any    any     anywhere             anywhere            tcp dpt:ssh
    0     0 ACCEPT     udp  --  eth1   any     anywhere             anywhere            udp dpt:1514 state NEW
    0     0 ACCEPT     udp  --  eth1   any     10.212.0.233         anywhere            udp dpt:1514 state NEW
    0     0 ACCEPT     tcp  --  eth1   any     anywhere             anywhere            tcp dpts:8649:8699 state NEW
    0     0 ACCEPT     udp  --  eth1   any     239.2.11.0/24        anywhere            udp dpts:8649:8699 state NEW
    0     0 ACCEPT     tcp  --  eth1   any     10.212.0.233         anywhere            tcp dpts:8649:8699 state NEW
36743 3540K DROP       all  --  any    any     anywhere             anywhere

Chain OUTPUT (policy ACCEPT 31184 packets, 2587K bytes)
 pkts bytes target     prot opt in     out     source               destination
 698K   35M ACCEPT     all  --  any    lo      anywhere             anywhere
15851 1390K ACCEPT     all  --  any    any     anywhere             anywhere            state RELATED,ESTABLISHED
  127  7601 ACCEPT     udp  --  any    any     anywhere             anywhere            udp dpt:domain
  492 35360 ossec      all  --  any    any     anywhere             anywhere            owner UID match root state NEW
  492 35360 root       all  --  any    any     anywhere             anywhere            owner UID match root state NEW
    0     0 ganglia    all  --  any    any     anywhere             anywhere            owner UID match root state NEW

Chain ganglia (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     udp  --  any    eth1    anywhere             239.2.11.0/24       udp dpts:8649:8699 state NEW
    0     0 LOG        all  --  any    any     anywhere             anywhere            LOG level warning tcp-sequence uid prefix `ganglia DROP '

Chain ossec (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     udp  --  any    eth1    anywhere             anywhere            udp dpt:1514 state NEW
    0     0 ACCEPT     udp  --  any    eth1    anywhere             10.212.0.233        udp dpt:1514 state NEW
  492 35360 LOG        all  --  any    any     anywhere             anywhere            LOG level warning tcp-sequence uid prefix `ossec DROP '

Chain root (1 references)
 pkts bytes target     prot opt in     out     source               destination
  113  6780 ACCEPT     tcp  --  any    eth1    anywhere             chef.local.vm       tcp dpt:4000 state NEW
   14   840 ACCEPT     tcp  --  any    any     anywhere             anywhere            tcp dpts:tcpmux:65535 state NEW
  365 27740 ACCEPT     udp  --  any    any     anywhere             anywhere            udp dpts:1:65535 state NEW
    0     0 ACCEPT     icmp --  any    any     anywhere             anywhere            state NEW
    0     0 LOG        all  --  any    any     anywhere             anywhere            LOG level warning tcp-sequence uid prefix `root DROP '
```

The `INPUT` chain contains all of the rules for incoming connections. It does
not redirect packets to other chains, but accept or drop them directly.

The `OUTPUT` chain is a little different. Depending on the owner of the socket
emitting packets, it will direct the packets to a different chain, named after
the socket owner.
In the example above, the packet from the `ossec` user will be directed to the
chain named `ossec`. You can see in this chain that the first two rules accept
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
