module Acceptance::Meterpreter
  # @return [Symbol] The current platform
  def self.current_platform
    host_os = RbConfig::CONFIG['host_os']
    case host_os
    when /darwin/
      :osx
    when /mingw/
      :windows
    when /linux/
      :linux
    else
      raise "unknown host_os #{host_os.inspect}"
    end
  end

  # Allows restricting the tests of a specific Meterpreter's test suite with the METERPRETER environment variable
  # @return [TrueClass, FalseClass] True if the given Meterpreter should be run, false otherwise.
  def self.run_meterpreter?(meterpreter_config)
    return true if ENV['Meterpreter'].blank?

    name = meterpreter_config[:name].to_s
    ENV['METERPRETER'].include?(name)
  end

  # @param [String] string A console string with ANSI escape codes present
  # @return [String] A string with the ANSI escape codes removed
  def self.uncolorize(string)
    string.gsub(/\e\[\d+m/, '')
  end

  # @param [Hash] payload_config
  # @return [Boolean]
  def self.supported_platform?(payload_config)
    payload_config[:platforms].include?(current_platform)
  end

  # @param [Hash] payload_config
  # @return [String] The human readable name for the given payload configuration
  def self.human_name_for_payload(payload_config)
    is_stageless = payload_config[:name].include?('meterpreter_reverse_tcp')
    is_staged = payload_config[:name].include?('meterpreter/reverse_tcp')

    details = []
    details << 'stageless' if is_stageless
    details << 'staged' if is_staged
    details << payload_config[:name]

    details.join(' ')
  end

  # @param [Object] hash A hash of key => hash
  # @return [Object] Returns a new hash with the 'key' merged into hash value and all payloads
  def self.with_meterpreter_name_merged(hash)
    hash.each_with_object({}) do |(name, config), acc|
      acc[name] = config.merge({ name: name })
    end
  end
end
