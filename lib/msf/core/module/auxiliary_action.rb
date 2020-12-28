# -*- coding: binary -*-

###
#
# TODO: Not sure if this definition needs changed now
# A target for an exploit.
#
###
#

# TOOD: Add a module action? Not sure how this will impact the internals.
class Msf::Module::AuxiliaryAction

  #
  # Serialize from an array to an Action instance.
  #
  def self.from_a(ary)
    return nil if ary.nil?
    self.new(*ary)
  end

  #
  # Transforms the supplied source into an array of AuxiliaryActions.
  #
  def self.transform(src)
    Rex::Transformer.transform(src, Array, [ self, String ], 'AuxiliaryAction')
  end

  #
  # Creates a new action definition
  #
  def initialize(name, opts={})
    self.name        = name
    self.opts        = opts
    self.description = opts['Description'] || ''
    self.module_name = opts['ModuleName']
    self.associated_tags = opts['AssociatedTags'] || []
    self.invokes_tags = opts['InvokesTags']
  end

  #
  # Index the options directly.
  #
  def [](key)
    opts[key]
  end

  #
  # The name of the action ('info')
  #
  attr_reader :name
  #
  # The action's description
  #
  attr_reader :description
  #
  # If the action is powered by another module
  #
  attr_reader :module_name
  #
  # Action specific parameters
  #
  attr_reader :opts

  attr_reader :invokes_tags, :associated_tags

protected

  attr_writer :name, :opts, :description, :module_name, :invokes_tags, :associated_tags # :nodoc:

end
