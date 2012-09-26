module AFWCore

  # IP dummy regex, from `0.0.0.0` to `999.999.999.999`
  IP_CIDR_VALID_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b(\/[0-3]?[0-9])?/

  # fqdn hostname regex `something.somethingelse.domain.net`
  FQDN_VALID_REGEX = /^(?:(?:[0-9a-zA-Z_\-]+)\.){2,}(?:[0-9a-zA-Z_\-]+)$/

  # Port regex `0` or `12345:12345` or `servicename`
  PORT_VALID_REGEX = /\d{1,5}|\d{1,5}:\d{1,5}|[0-9a-z]{0,30}/

  # Blackhole IP is used when the search for an IP returns nothing
  BLACKHOLE_IP = "172.31.255.254"


  def process_rule(node, name, params)
    # Top level logic of AFW
    #
    # Input parameter:
    # `name` is a string that is unique for a rule and is used as a key
    # `params` is a mash that contains the rule parameters

    # If the rule is not applicable to this environment, skip it
    env = params.fetch('env', node.chef_environment)
    if env != node.chef_environment
      Chef::Log.info("AFW: rule '#{name}' is for '#{env}' environment. Skipping it")
      return true
    end

    # if this entry has a full rule predefined, take it and go to the next entry
    if rule_is_predefined?(name, params)
      node['afw']['tables'][params['table']]['rules'].push(params['rule'])
      return true
    end

    # skip the grammar check if specifically asked
    options = params.fetch('options', node.chef_environment)
    if options.include?('disable_syntax_check')
      Chef::Log.info("AFW: disabling syntax checking for rule '#{name}'")
    else
      # grammar check
      rule_validation(node, name,params)
    end

    # Parse the parameters of the rules into separate variable
    direction       = params['direction']
    user            = params['user']
    protocol        = params['protocol']
    destination     = params.fetch('destination', [])
    source          = params.fetch('source', [])
    dport           = params['dport'] if params.has_key?('dport')
    sport           = params['sport'] if params.has_key?('sport')
    interface       = node['afw']['default_iface'] || node['network']['laniface']
    if params.has_key?('interface')
      interface = case params['interface']
                  when 'default' then interface
                  when 'all' then ''
                  else
                    if node['network']['interfaces'].has_key?(params['interface'])
                      params['interface']
                    end
                  end
    end

    # rules are added into the chain of the user that needs them
    # so we make sure this user exists and initialize the chain if needed
    unless node['afw']['chains'].has_key?(user)
      uid = check_user(node, user, name)
      if uid == -1
        # if no valid user was found, skip this rule
        Chef::Log.info("AFW: no valid user was found for rule '#{name}'. skipping it.")
        return true
      end
      unless node['afw']['chains'].has_key?(user)
        node['afw']['chains'][user] = {}
      end
      node['afw']['chains'][user]['uid'] = uid
      node['afw']['chains'][user]['rules'] = []
    end

    # Rule preparation is done, launch the compilation and store in node attr
    compile_and_store_rules(node, name, options, direction, user, protocol,
                              destination, source, dport, sport, interface)
    return true
  end


  def rule_is_predefined?(name, params)
    if params.has_key?("rule") and params.has_key?("table")
      if ['nat','raw','mangle','filter'].include?(params['table'])
        unless node['afw']['tables'][params['table']]['rules'].include?(params['rule'])
          Chef::Log.info("AFW: storing predefined rule '#{name}'")
        end
      else
        Chef::Log.info("AFW: wrong table name '#{params['table']}' in rule '#{name}'")
      end
      return true
    end
    return false
  end


  def rule_validation(node, name, rule_params)
    # Verify the grammar of a rule and discard rule with invalid parameters
    # check mandatory parameters that must be presents on every rules
    %w(direction user protocol).each do |parameter|
      unless node['afw']['rules'][name].has_key?(parameter)
        raise ArgumentError,
              "Missing Mandatory Parameter '#{parameter}' in rule '#{name}'",
              caller
      end
    end

    unless rule_params['direction'] =~ /in|out/
      raise ArgumentError,
            "Invalid Direction '#{rule_params['direction']}' in rule '#{name}'",
            caller
    end

    unless rule_params['protocol'] =~ /tcp|udp|icmp|vrrp|all/
      raise ArgumentError,
            "Invalid Protocol '#{rule_params['protocol']}' in rule '#{name}'",
            caller
    end

    # an interface can be "all", "default" or a valid interface of the node
    if rule_params.has_key?('interface')
      case rule_params['interface']
      when 'default' then true
      when 'all' then true
      else
        unless node['network']['interfaces'].has_key?(rule_params['interface'])
          raise ArgumentError,
                "Invalid Interface '#{rule_params['interface']}' in rule '#{name}'",
                caller
        end
      end
    end

    # dport is mandatory for tcp and udp
    if rule_params['protocol'] =~ /tcp|udp/
      unless rule_params.has_key?('dport')
        raise ArgumentError,
              "Missing Mandatory DPort Parameter in rule '#{name}'",
              caller
      end
      check_port(rule_params['dport'], name)
    end

    # sport is optional
    if rule_params.has_key?('sport')
      check_port(rule_params['sport'], name)
    end

    # Inbound rules
    if rule_params['direction'] == "in"
      unless rule_params.has_key?('source')
        raise ArgumentError,
              "Missing Mandatory Source Parameter in rule '#{name}'",
              caller
      end
    # Outbound rules
    elsif rule_params['direction'] == "out"
      unless rule_params.has_key?('destination')
        raise ArgumentError,
              "Missing Mandatory Destination Parameter in rule '#{name}'",
              caller
      end
    end

    # options are optional, but we make sure the syntax is valid
    if rule_params.has_key?('options')
      rule_params['options'].each do |option|
        if option !~ /^(disable_env_limit)$/
          raise ArgumentError,
                "Unkown option '#{option}' in rule '#{name}'",
                caller
        end
      end
    end
  end


  def check_port(port, name)
    # check a (s|d)port against a regex
    unless port =~ PORT_VALID_REGEX
      raise ArgumentError, "Invalid Port '#{port}' in rule '#{name}'", caller
    end
    return true
  end


  def expand_sametag(search_string, name)
    # Process the SAMETAG keyword, get a list of tags the node owns
    # and limit the firewall rules to sources/destinations that share those tags
    # If SAMETAG is present, but the node has no tags, a fake tag will be returned
    # to make the search return zero result. We don't want to open the firewall
    # to everyone if SAMETAG has been explicitely added to a rule.
    if search_string =~ /SAMETAG/
      tags_list = "("
      tag_counter = 0
      node.tags.each do |tag|
        tag_counter += 1
        tags_list << "tags:#{tag}"
        if tag_counter < node.tags.count
          tags_list << " OR "
        end
      end
      if tag_counter == 0
        tags_list << "tags:afw-dummy-tag-#{rand(100000)}"
      end
      tags_list << ")"
      search_string["SAMETAG"] = tags_list
      Chef::Log.info("AFW: adding tags '#{tags_list}' to search string in rule '#{name}'")
    end
    return search_string
  end


  def check_user(node, user, name)
    # check if the user exists in the local passwd file
    # This test might fail if the user doesn't exist yet (ie, AFW starts before
    # the package that provisions this user is installed). So to prevent it from
    # failing constantly, we return user 0 if none is found.
    uid = -1
    begin
      uid = Etc.getpwnam(user)['uid']
    rescue ArgumentError
      Chef::Log.info("AFW: Discarding rule '#{name}'. no user '#{user}' could be found.")
      node.default['afw']['missing_user'] = true
    end
    return uid
  end


  def compile_and_store_rules(node, name, options, direction, user, protocol,
                              destination, source, dport, sport, interface)
    # Tranform input parameters into one or multiple iptables rules in
    # iptables-restore syntax, and store these rules into the node attributes
    sources         = []
    destinations    = []
    iptables_header = ""

    # Inbound rules
    if direction == "in"
      iptables_header = "-A INPUT "
      iptables_header << "-i #{interface}" unless interface.empty?
      sources = expand_targets(source,options,name)

    # Outbound rules
    elsif direction == "out"
      iptables_header = "-A #{user}"
      iptables_header << " -o #{interface}" unless interface.empty?
      destinations = expand_targets(destination,options,name)
    end

    iptables_header << " -p #{protocol}" unless protocol == 'all'
    iptables_header << " --sport #{sport}" if sport
    iptables_header << " --dport #{dport}" if dport

    iptables_rules = build_rule_array(iptables_header,
                                      sources,
                                      destinations)

    # the rules are built, store them in the node attributes
    iptables_rules.each do |iptables_rule|
      unless node['afw']['chains'][user]['rules'].include?(iptables_rule)
        Chef::Log.info("AFW: storing rule '#{iptables_rule}'")
        node['afw']['chains'][user]['rules'].push(iptables_rule)
      end
    end
  end


  def expand_targets(criteria, options, name)
    # Check if the criteria is an array, and call `expands_ips` for each entry
    targets = []
    if criteria.kind_of?(Array)
      criteria.each do |target|
        results = expand_ips(target, options, name)
        targets |= results
      end
    else
      targets = expand_ips(criteria, options, name)
    end
    return targets
  end


  def expand_ips(target, options, name)
    # Take a search, an IP or a hostname and return an array of IPs
    ips = []
    if target =~ IP_CIDR_VALID_REGEX
      # target is just a single ip or network
      ips.push(target)
    elsif target =~ FQDN_VALID_REGEX
      # target is a fqdn, that's valid too
      ips.push(target)
    else
      # target isn't an ip, let's try to resolve a search with it
      search_string = "("
      search_string << eval('"' + target.gsub(/"/, '\"') + '"')
      search_string << ")"

      # If there is a sametag, it will be expanded
      search_string = expand_sametag(search_string, name)

      # Add the environment scope of the search
      search_string = expand_environment(search_string, options, name)
      results = []

      # If running on Chef Solo, return an empty result
      if Chef::Config[:solo]
        Chef::Log.warn("Chef Solo does not support search.")
      else
        results = search(:node, search_string
                        ).map{|n| n['network']['lanip'] || BLACKHOLE_IP}
      end

      if (results.count < 1) \
        or (results.count == 1 and results.first == BLACKHOLE_IP)
        Chef::Log.info("AFW: rule '#{name}' search '#{search_string}' returned" +
            " empty results. Using blackhole IP '#{BLACKHOLE_IP}' instead.")
        ips.push(BLACKHOLE_IP)
      else
        # Merge results into the IPs array
        ips |= results
      end
    end
    return ips
  end


  def expand_environment(search_string, options, name)
    # Check the options `disable_env_limit`
    # if used, the search that will be used to list sources and destinations
    # will not be limited to the current environment
    if options.include?('disable_env_limit')
      Chef::Log.info("HERESY ! [disable_env_limit] used in rule '#{name}'")
    else
      search_string << " AND chef_environment:#{node.chef_environment}"
    end
    return search_string
  end


  def build_rule_array(iptables_header, sources, destinations)
    # iterate through the lists of resolved sources and destinations and
    # build as many rules as needed into `iptables_array_destination`
    iptables_array_source = []
    iptables_array_destination = []

    if sources.count < 1 and destinations.count < 1
      Chef::Log.info("AFW: no source or destination found")
      # don't create a rule that has no source and destination
      return []
    end

    if sources.count > 0
      sources.each do |this_source|
        iptables_array_source.push("#{iptables_header} -s #{this_source}")
      end
    else
      iptables_array_source.push(iptables_header)
    end

    if destinations.count > 0
      destinations.each do |this_dest|
        iptables_array_source.each do |iptables_source|
          iptables_array_destination.push(
            "#{iptables_source} -d #{this_dest} " +
            "-m conntrack --ctstate NEW -j ACCEPT"
          )
        end
      end
    else
      iptables_array_source.each do |iptables_source|
        iptables_array_destination.push(
          "#{iptables_source} -m conntrack --ctstate NEW -j ACCEPT"
        )
        Chef::Log.info("AFW: building rule '#{iptables_source} " +
            "-m conntrack --ctstate NEW -j ACCEPT'")
      end
    end

    return iptables_array_destination
  end
end
