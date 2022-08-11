# -*- coding:binary -*-

require 'spec_helper'

RSpec::Matchers.define :match_table do |expected|
  diffable

  match do |actual|
    @actual = actual.to_s.strip
    @expected = expected.to_s.strip

    @actual == @expected
  end

  failure_message do |actual|
    <<~MSG
      Expected:
      #{with_whitespace_highlighted(expected.to_s.strip)}
      Received:
      #{with_whitespace_highlighted(actual.to_s.strip)}
      Raw Result:
      #{actual}
    MSG
  end

  def with_whitespace_highlighted(string)
    string.lines.map { |line| "'#{line.gsub("\n", '')}'" }.join("\n")
  end
end

RSpec.describe Msf::Serializer::ReadableText do
  let(:indent) { '' }
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

  describe '.dump_options' do
    before(:each) do
      aux_mod.datastore.delete('FloatValue')
      aux_mod.datastore.delete('foo')
      aux_mod.datastore['OLD_OPTION_NAME'] = nil
      aux_mod.datastore['username'] = 'username'
      aux_mod.datastore['fizz'] = 'new_fizz'
    end

    context 'when missing is false' do
      it 'returns the options as a table' do
        expect(described_class.dump_options(aux_mod, indent, false)).to match_table <<~TABLE
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
        expect(described_class.dump_options(aux_mod, indent, true)).to match_table <<~TABLE
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
