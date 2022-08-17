# -*- coding:binary -*-

require 'spec_helper'
require 'rex/text'

RSpec.describe Msf::Serializer::ReadableText do
  # The described_class API takes a mix of strings and whitespace character counts
  let(:indent_string) { '' }
  let(:indent_length) { indent_string.length }

  let(:aux_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      def initialize
        super(
          'Name' => 'mock module',
          'Description' => 'mock module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE,
          'DefaultOptions' => {
            'OptionWithModuleDefault' => false,
            'foo' => 'foo_from_module',
            'baz' => 'baz_from_module'
          },
        )

        register_options(
          [
            Msf::Opt::RHOSTS,
            Msf::Opt::RPORT(3000),
            Msf::OptString.new(
              'foo',
              [true, 'Foo option', 'bar']
            ),
            Msf::OptString.new(
              'fizz',
              [true, 'fizz option', 'buzz']
            ),
            Msf::OptString.new(
              'baz',
              [true, 'baz option', 'qux']
            ),
            Msf::OptString.new(
              'OptionWithModuleDefault',
              [true, 'option with module default', true]
            ),
            Msf::OptFloat.new('FloatValue', [false, 'A FloatValue ', 3.5]),
            Msf::OptString.new(
              'NewOptionName',
              [true, 'An option with a new name. Aliases ensure the old and new names are synchronized', 'default_value'],
              aliases: ['OLD_OPTION_NAME']
            ),
            Msf::OptString.new(
              'SMBUser',
              [true, 'The SMB username'],
              fallbacks: ['username']
            ),
            Msf::OptString.new(
              'SMBDomain',
              [true, 'The SMB username', 'WORKGROUP'],
              fallbacks: ['domain']
            )
          ]
        )
      end
    end

    mod = mod_klass.new
    allow(mod).to receive(:framework).and_return(nil)
    mod
  end

  let(:aux_mod_with_set_options) do
    mod = aux_mod.replicant
    mod.datastore.unset('FloatValue')
    mod.datastore.unset('foo')
    mod.datastore['OLD_OPTION_NAME'] = nil
    mod.datastore['username'] = 'username'
    mod.datastore['fizz'] = 'new_fizz'
    mod
  end

  before(:each) do
    allow(Rex::Text::Table).to receive(:wrapped_tables?).and_return(true)
  end

  describe '.dump_datastore' do
    context 'when the datastore is empty' do
      it 'returns the datastore as a table' do
        expect(described_class.dump_datastore('Table name', Msf::DataStore.new, indent_length)).to match_table <<~TABLE
          Table name
          ==========
  
          No entries in data store.
        TABLE
      end
    end

    context 'when the datastore has values' do
      it 'returns the datastore as a table' do
        expect(described_class.dump_datastore('Table name', aux_mod_with_set_options.datastore, indent_length)).to match_table <<~TABLE
          Table name
          ==========
  
          Name                     Value
          ----                     -----
          FloatValue
          NewOptionName
          OptionWithModuleDefault  false
          RHOSTS
          RPORT                    3000
          SMBDomain                WORKGROUP
          SMBUser                  username
          VERBOSE                  false
          WORKSPACE
          baz                      baz_from_module
          fizz                     new_fizz
          foo
          username                 username
        TABLE
      end
    end
  end

  describe '.dump_options' do
    context 'when missing is false' do
      it 'returns the options as a table' do
        expect(described_class.dump_options(aux_mod_with_set_options, indent_string, false)).to match_table <<~TABLE
          Name                     Current Setting  Required  Description
          ----                     ---------------  --------  -----------
          FloatValue                                no        A FloatValue
          NewOptionName                             yes       An option with a new name. Aliases ensure the old and new names are synchronized
          OptionWithModuleDefault  false            yes       option with module default
          RHOSTS                                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
          RPORT                    3000             yes       The target port
          SMBDomain                WORKGROUP        yes       The SMB username
          SMBUser                  username         yes       The SMB username
          baz                      baz_from_module  yes       baz option
          fizz                     new_fizz         yes       fizz option
          foo                                       yes       Foo option
        TABLE
      end
    end

    context 'when missing is true' do
      it 'returns the options as a table' do
        expect(described_class.dump_options(aux_mod_with_set_options, indent_string, true)).to match_table <<~TABLE
          Name           Current Setting  Required  Description
          ----           ---------------  --------  -----------
          NewOptionName                   yes       An option with a new name. Aliases ensure the old and new names are synchronized
          RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
          foo                             yes       Foo option
        TABLE
      end
    end
  end
end
