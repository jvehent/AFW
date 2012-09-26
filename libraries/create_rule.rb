module AFW
  extend AFWCore
  module_function

  def create_rule(node, name, params)
    node['afw']['rules'][name] = params
    # Wrapper around `process_rule`
    #
    Chef::Log.info("AFW.create_rule(): processing '#{name}'")
    if process_rule(node, name, params)
      Chef::Log.info("AFW.create_rule(): finished processing '#{name}'")
    end
    return true
  end
end
