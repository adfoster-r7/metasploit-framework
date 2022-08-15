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
    # Was this entry actually set or just using its default
    #
    # @return [TrueClass, FalseClass]
    def default?(key)
      search_result = search_for(key)
      search_result.result == :default || search_result.result == :not_found
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
  end
end
