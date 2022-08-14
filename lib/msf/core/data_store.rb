# -*- coding: binary -*-
module Msf

###
#
# The data store is just a bitbucket that holds keyed values. It is used
# by various classes to hold option values and other state information.
#
###
class DataStore

  # The global framework datastore doesn't currently import options
  # For now, store an ad-hoc list of keys that the shell handles
  #
  # This can be removed after framework's bootup sequence registers
  # these as real options
  GLOBAL_KEYS = %w[
    ConsoleLogging
    LogLevel
    MinimumRank
    SessionLogging
    TimestampOutput
    Prompt
    PromptChar
    PromptTimeFormat
    MeterpreterPrompt
    SessionTlvLogging
  ]

  #
  # Initializes the data store's internal state.
  #
  def initialize
    @options     = Hash.new
    @aliases     = Hash.new
    @imported    = Hash.new
    @imported_by = Hash.new

    # default values which will be referenced when not defined by the user
    @defaults = Hash.new

    # values explicitly defined, which take precedence over default values
    @user_defined = Hash.new
  end

  # @return [Hash<String, Msf::OptBase>] The options associated with this datastore. Used for validating values/defaults/etc
  attr_accessor :options

  # These defaults will be used if the user has not explicitly defined a specific datastore value.
  # These will be checked as a priority to any options that also provide defaults.
  #
  # @return [Hash<String, Msf::OptBase>] The hash of default values
  attr_accessor :defaults

  # @return [Hash<String, String>] The key is the old option name, the value is the new option name
  attr_accessor :aliases
  attr_accessor :imported
  attr_accessor :imported_by

  #
  # Returns a hash of user-defined datastore values. The returned hash does
  # not include default option values.
  #
  # @return [Hash<String, Object>] values explicitly defined on the data store which will override any default datastore values
  attr_accessor :user_defined

  #
  # Clears the imported flag for the supplied key since it's being set
  # directly.
  #
  def []=(k, v)
    k = find_key_case(k)
    @imported[k] = false
    @imported_by[k] = nil

    opt = @options[k]
    unless opt.nil?
      # TODO: Should `merge!` validate hash values?
      if opt.validate_on_assignment?
        unless opt.valid?(v, check_empty: false)
          raise Msf::OptionValidateError.new(["Value '#{v}' is not valid for option '#{k}'"])
        end
        v = opt.normalize(v)
      end
    end

    @user_defined[k] = v
  end

  #
  # Case-insensitive wrapper around hash lookup
  #
  def [](k)
    key = find_key_case(k)
    return @user_defined[key] if @user_defined.key?(key)

    # If the key isn't present - check any additional fallbacks that have been registered with the option.
    # i.e. handling the scenario of SMBUser not being explicitly set, but the option has registered a more
    # generic 'Username' fallback
    option = @options.find { |option_name, _option| option_name.casecmp?(key) }&.last

    return nil unless option

    option.fallbacks.each do |fallback|
      # TODO: If a fallback has a default, should we choose it? If so - this won't work
      # if @user_defined.key?(find_key_case(fallback)) # || @defaults.fetch(key) || options.fetch(fallback).default.nil?
      #   return self[fallback]
      # end
      # return fetch(fallback) { next }
      if @user_defined.key?(fallback) || @imported.key?(fallback)
        return self[fallback]
      end
    end

    # If there's no registered fallbacks that matched, finally use the default option value
    @defaults.key?(key) ? @defaults[key] : option.default
  end

  # TODO: Dry this out with [](...)
  def fetch(k)
    key = find_key_case(k)
    return @user_defined[key] if @user_defined.key?(key)

    # If the key isn't present - check any additional fallbacks that have been registered with the option.
    # i.e. handling the scenario of SMBUser not being explicitly set, but the option has registered a more
    # generic 'Username' fallback
    option = @options.find { |option_name, _option| option_name.casecmp?(key) }&.last
    raise key_error_for(k) unless option

    option.fallbacks.each do |fallback|
      # TODO: If a fallback has a default, should we choose it? If so - this won't work
      # if @user_defined.key?(find_key_case(fallback)) # || @defaults.fetch(key) || options.fetch(fallback).default.nil?
      #   return self[fallback]
      # end
      # return fetch(fallback) { next }
      if @user_defined.key?(fallback) || @imported.key?(fallback)
        return self[fallback]
      end
    end

    # If there's no registered fallbacks that matched, finally use the default option value
    return @defaults[key] if @defaults.key?(key)
    return option.default unless option.default.nil?

    raise key_error_for(k)
  end

  #
  # Case-insensitive wrapper around store
  #
  def store(k,v)
    @user_defined[find_key_case(k)] = v
  end

  #
  # unset the current key from the datastore
  def unset(key)
    k = find_key_case(key)
    is_imported = @imported[k]
    @imported[k] = false
    @imported_by[k] = nil

    result = nil
    if @user_defined.key?(k)
      result = @user_defined[k]
    elsif is_imported
      # TODO: Confirm if this needs a similar lookup to the fallback mechanism
      result = @defaults.key?(k) ? @defaults[k] : @options[k]&.default
    end

    # Explicitly mark the entry as nil so that future lookups of the key are nil, instead of retrieving a default value
    @user_defined[k] = nil

    result
  end

  # @deprecated use #{unset} instead, or set the value explicitly to nil
  alias delete unset

  def reset(key)
    k = find_key_case(key)
    @user_defined.delete(k)

    nil
  end

  #
  # Removes an option and any associated value
  #
  # @param [String] name the option name
  # @return [Msf::OptBase, nil]
  def remove_option(name)
    k = find_key_case(name)
    @user_defined.delete(k)
    @aliases.delete_if { |_, v| v.casecmp(k) == 0 }
    @imported.delete(k)
    @imported_by.delete(k)
    # TODO: Should this modify @defaults too?
    @options.delete(k)
  end

  #
  # Updates a value in the datastore with the specified name, k, to the
  # specified value, v.  This update does not alter the imported status of
  # the value.
  #
  def update_value(k, v)
    self.store(k, v)
  end

  #
  # This method is a helper method that imports the default value for
  # all of the supplied options
  #
  def import_options(options, imported_by = nil, overwrite = true)
    options.each_option do |name, opt|
      # TODO: This needs fixed most likely to handle unset
      # if self[name].nil? || overwrite
      if self.options[name].nil? || overwrite
        # import_option(name, nil, true, imported_by, opt)

        key = name
        option = opt

        # Don't store the value, defer the assignment until it gets a read
        #    self.store(key, val)

        if option
          option.aliases.each do |a|
            @aliases[a.downcase] = key.downcase
          end
        end
        @options[key] = option
        @imported[key] = true
        @imported_by[key] = imported_by
      end
    end
  end

  #
  # Imports option values from a whitespace separated string in
  # VAR=VAL format.
  #
  def import_options_from_s(option_str, delim = nil)
    hash = {}

    # Figure out the delimeter, default to space.
    if (delim.nil?)
      delim = /\s/

      if (option_str.split('=').length <= 2 or option_str.index(',') != nil)
        delim = ','
      end
    end

    # Split on the delimeter
    option_str.split(delim).each { |opt|
      var, val = opt.split('=')

      next if (var =~ /^\s+$/)


      # Invalid parse?  Raise an exception and let those bastards know.
      if (var == nil or val == nil)
        var = "unknown" if (!var)

        raise Rex::ArgumentParseError, "Invalid option specified: #{var}",
          caller
      end

      # Remove trailing whitespaces from the value
      val.gsub!(/\s+$/, '')

      # Store the value
      hash[var] = val
    }

    merge!(hash)
  end

  #
  # Imports values from a hash and stores them in the datastore.
  #
  # @deprecated use {#merge!} instead
  # @return [nil]
  def import_options_from_hash(option_hash, imported = true, imported_by = nil)
    merge!(option_hash)
  end

  # Update defaults from a hash
  #
  # @param [Hash<String, Object>] hash The default values that should be used by the datastore
  # @param [Object] imported_by Who imported the defaults, not currently used
  # @return [nil]
  def import_defaults_from_hash(hash, imported_by:)
    # $stderr.puts "importing new defaults from hash: #{@defaults} for object id #{object_id}"
    # require 'pry'; binding.pry
    # TODO: Use imported_by
    @defaults.merge!(hash)
  end

  # TODO: Doesn't normalize data in the same vein as:
  # https://github.com/rapid7/metasploit-framework/pull/6644
  def import_option(key, val, imported = true, imported_by = nil, option = nil)
    raise ArgumentError, "should not be called"

    # If populated by an option - don't immediately store the value. We'll instead lazily use the option's default value on lookup
    self.store(key, val) if option.nil?

    if option
      option.aliases.each do |a|
        @aliases[a.downcase] = key.downcase
      end
    end
    @options[key] = option
    @imported[key] = imported
    @imported_by[key] = imported_by
  end

  def keys
    (@user_defined.keys + @options.keys).uniq(&:downcase)
  end

  def length
    keys.length
  end

  alias count length
  alias size length

  def key?(key)
    !find_key_case(key).nil?
  end

  alias has_key? key?
  alias include? key?
  alias member? key?

  def each_key(&block)
    self.keys.each(&block)
  end

  #
  # Serializes the options in the datastore to a string.
  #
  def to_s(delim = ' ')
    str = ''

    keys.sort.each { |key|
      str << "#{key}=#{self[key]}" + ((str.length) ? delim : '')
    }

    return str
  end

  # Override Hash's to_h method so we can include the original case of each key
  # (failing to do this breaks a number of places in framework and pro that use
  # serialized datastores)
  def to_h
    datastore_hash = {}
    self.keys.each do |k|
      datastore_hash[k.to_s] = self[k].to_s
    end
    datastore_hash
  end

  # Hack on a hack for the external modules
  def to_external_message_h
    datastore_hash = {}

    array_nester = ->(arr) do
      if arr.first.is_a? Array
        arr.map &array_nester
      else
        arr.map { |item| item.to_s.dup.force_encoding('UTF-8') }
      end
    end

    self.keys.each do |k|
      # TODO arbitrary depth
      if self[k].is_a? Array
        datastore_hash[k.to_s.dup.force_encoding('UTF-8')] = array_nester.call(self[k])
      else
        datastore_hash[k.to_s.dup.force_encoding('UTF-8')] = self[k].to_s.dup.force_encoding('UTF-8')
      end
    end
    datastore_hash
  end

  #
  # Persists the contents of the data store to a file
  #
  def to_file(path, name = 'global')
    ini = Rex::Parser::Ini.new(path)

    ini.add_group(name)

    # Save all user-defined options to the file.
    @user_defined.each_pair { |k, v|
      ini[name][k] = v
    }

    ini.to_file(path)
  end

  #
  # Imports datastore values from the specified file path using the supplied
  # name
  #
  def from_file(path, name = 'global')
    begin
      ini = Rex::Parser::Ini.from_file(path)
    rescue
      return
    end

    if ini.group?(name)
      merge!(ini[name])
    end
  end

  #
  # Return a copy of this datastore. Only string values will be duplicated, other other values
  # will share the same reference
  # @return [Msf::DataStore] a new datastore instance
  def copy
    new_instance = self.class.new
    new_instance.copy_state(self)
    new_instance
  end

  #
  # Copy the state from the other Msf::DataStore. The state will be coped in a shallow fashion, other than
  # imported and user_defined strings.
  #
  # @param [Msf::DataStore] other The other datastore to copy state from
  # @return [Msf::DataStore] the current datastore instance
  def copy_state(other)
    self.imported = other.imported.dup
    self.options = other.options.dup
    self.aliases = other.aliases.dup
    self.defaults = other.defaults.transform_values { |value| value.kind_of?(String) ? value.dup : value }
    self.user_defined = other.user_defined.transform_values { |value| value.kind_of?(String) ? value.dup : value }

    self
  end

  #
  # Override merge! so that we merge the aliases and imported hashes
  #
  # @param [Msf::Datatstore, Hash] other
  def merge!(other)
    if other.is_a? DataStore
      self.aliases.merge!(other.aliases)
      self.options.merge!(other.options)
      self.imported.merge!(other.imported)
      self.imported_by.merge!(other.imported_by)
      other.user_defined.each do |k, v|
        self.user_defined[k] = v
      end
    else
      other.each do |k, v|
        self[k] = v
      end
    end

    self
  end

  alias update merge!

  #
  # Override merge to ensure we merge the aliases and imported hashes
  #
  # @param [Msf::Datatstore, Hash] other
  def merge(other)
    ds = self.copy
    ds.merge!(other)
  end

  #
  # Remove all imported options from the data store.
  #
  def clear_non_user_defined
    # TODO
    @imported.delete_if { |k, v|
      if (v and @imported_by[k] != 'self')
        self.delete(k)
        @imported_by.delete(k)
      end

      v
    }
  end

  #
  # Completely clear all values in the hash
  # TODO: What does clear mean? In this new world? is it `reset_all` ?
  def clear
    # Clearing these values like this removes the book keeping
    # self.keys.each {|k| self.delete(k) }
    @user_defined.clear
    self
  end

  #
  # Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
  #    "can't add a new key into hash during iteration"
  #
  def each(&block)
    list = []
    self.keys.sort.each do |sidx|
      list << [sidx, self[sidx]]
    end
    list.each(&block)
  end

  #
  # Case-insensitive key lookup
  #
  def find_key_case(k)
    # Scan each alias looking for a key
    search_k = k.downcase
    if self.aliases.has_key?(search_k)
      search_k = self.aliases[search_k]
    end

    # Check to see if we have an exact key match - otherwise we'll have to search manually to check case sensitivity
    if options.key?(search_k) || @user_defined.key?(search_k)
      return search_k
    end

    # Scan each key looking for a match
    each_key do |rk|
      if rk.casecmp(search_k) == 0
        return rk
      end
    end

    # Fall through to the non-existent value
    k
  end

  protected

  # Raised when the specified key is not found
  # @param [string] k
  def key_error_for(k)
    ::KeyError.new "key not found: #{k.inspect}"
  end

end

end
