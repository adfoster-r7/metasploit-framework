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
    # Return a copy of this datastore. Only string values will be duplicated, other values
    # will share the same reference
    # @return [Msf::DataStore] a new datastore instance
    def copy
      new_instance = self.class.new(@_module)
      new_instance.copy_state(self)
      new_instance
    end

    # Search for a value within the current datastore, taking into consideration any registered aliases, fallbacks, etc.
    # If a value is not present in the current datastore, the global parent store will be referenced instead
    #
    # @param [String] k The key to search for
    # @return [DataStoreSearchResult]
    def search_for(k)
      key = find_key_case(k)
      return search_result(:module_user_defined, @_user_defined[key]) if @_user_defined.key?(key)

      # Preference globally set values over a module's option default
      framework_datastore_search = search_framework_datastore(k)
      return framework_datastore_search if framework_datastore_search.found? && !framework_datastore_search.default?

      # If the key isn't present - check any additional fallbacks that have been registered with the option.
      # i.e. handling the scenario of SMBUser not being explicitly set, but the option has registered a more
      # generic 'Username' fallback
      option = @options.find { |option_name, _option| option_name.casecmp?(key) }&.last
      return search_framework_datastore(k) unless option

      option.fallbacks.each do |fallback|
        fallback_search = search_for(fallback)
        if fallback_search.found?
          return search_result(:module_option_fallback, fallback_search.value, fallback_key: fallback)
        end
      end

      return search_result(:module_default, @defaults[key]) if @defaults.key?(key)
      search_result(:module_option_default, option.default)
    end

    protected

    # Search the framework datastore
    #
    # @param [String] key The key to search for
    # @return [DataStoreSearchResult]
    def search_framework_datastore(key)
      return search_result(:not_found, nil) if @_module&.framework.nil?

      @_module.framework.datastore.search_for(key)
    end

    def search_result(result, value, fallback_key: nil)
      DataStoreSearchResult.new(result, value, namespace: :module_data_store, fallback_key: fallback_key)
    end
  end
end
