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

    def delete(key, also_delete: false)
      super(key)

      # TODO: Add tests for delete and implement this properly so there's graceful fallback support
      @user_defined.delete(key) if also_delete
    end

    #
    # Was this entry actually set or just using its default
    #
    def default?(key)
      (@imported_by[key] == 'self')
    end

    #
    # Return a copy of this datastore. Only string values will be duplicated, other other values
    # will share the same refeqrence
    #
    def copy
      new_instance = self.class.new(@_module)
      new_instance.copy_state(self)
      new_instance
    end
  end
end
