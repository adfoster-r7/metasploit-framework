# -*- coding: binary -*-
module Msf

  ###
  #
  # DataStore wrapper for modules that will attempt to back values against the
  # framework's datastore if they aren't found in the module's datastore.  This
  # is done to simulate global data store values.
  #
  ###
  class ModuleDataStore < DataStore

    # @param [Msf::Module] m
    def initialize(m)
      super()

      @_module = m
    end

    #
    # Fetch the key from the local hash first, or from the framework datastore
    # if we can't directly find it
    #
    def fetch(key)
      super
    rescue KeyError
      raise key_error_for(key) if @_module&.framework.nil?

      @_module.framework.datastore.fetch(key)
    end

    #
    # Same as fetch
    #
    def [](key)
      fetch(key)
    rescue KeyError
      nil
    end

    def unset(key)
      super(key)

      # @user_defined.delete(key)
    end

    #
    # Return a copy of this datastore. Only string values will be duplicated, other values
    # will share the same reference
    # @return [Msf::DataStore] a new datastore instance
    def copy
      new_instance = self.class.new(@_module)
      new_instance.copy_state(self)
      new_instance
    end

    # Search for a value within the current datastore, taking into consideration any registered aliases, fallbacks, etc.
    #
    # @param [String] k The key to search for
    # @return [SearchResult]
    def search_for(k)
      key = find_key_case(k)
      return search_result(:not_found, nil) if key.nil?
      return search_result(:user_defined, @user_defined[key]) if @user_defined.key?(key)

      # If the key isn't present - check any additional fallbacks that have been registered with the option.
      # i.e. handling the scenario of SMBUser not being explicitly set, but the option has registered a more
      # generic 'Username' fallback
      option = @options.find { |option_name, _option| option_name.casecmp?(key) }&.last
      return search_result(:not_found, nil) unless option

      option.fallbacks.each do |fallback|
        fallback_search = search_for(fallback)
        if fallback_search.found?
          return search_result(:fallback, fallback_search.value, fallback_key: fallback)
        end
      end

      return search_result(:default, @defaults[key]) if @defaults.key?(key)
      return search_result(:default, option.default) unless option.default.nil?

      search_result(:not_found, nil)
    end

    protected

    def search_framework_datastore(k)
      search_result(:not_found, nil) if @_module&.framework.nil?

      @_module.framework.datastore.search_for(key)
    end
  end
end
