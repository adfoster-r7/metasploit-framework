# -*- coding:binary -*-

require 'spec_helper'

RSpec.shared_examples_for 'a datastore with lookup support' do |opts = {}|
  describe '#[]' do
    it 'should have default keyed values' do
      expect(subject['foo']).to eq 'bar'
      expect(subject['fizz']).to eq 'buzz'
    end

    it 'should have case-insensitive lookups' do
      # Sorted by gray code, just for fun
      expect(subject['foo']).to eq 'bar'
      expect(subject['Foo']).to eq 'bar'
      expect(subject['FOo']).to eq 'bar'
      expect(subject['fOo']).to eq 'bar'
      expect(subject['fOO']).to eq 'bar'
      expect(subject['FOO']).to eq 'bar'
      expect(subject['FoO']).to eq 'bar'
      expect(subject['foO']).to eq 'bar'
    end
  end

  describe '#fetch' do
    it 'should have default keyed values' do
      expect(subject.fetch('foo')).to eq 'bar'
      expect(subject.fetch('fizz')).to eq 'buzz'
    end

    it 'should have case-insensitive lookups' do
      # Sorted by gray code, just for fun
      expect(subject.fetch('foo')).to eq 'bar'
      expect(subject.fetch('Foo')).to eq 'bar'
      expect(subject.fetch('FOo')).to eq 'bar'
      expect(subject.fetch('fOo')).to eq 'bar'
      expect(subject.fetch('fOO')).to eq 'bar'
      expect(subject.fetch('FOO')).to eq 'bar'
      expect(subject.fetch('FoO')).to eq 'bar'
      expect(subject.fetch('foO')).to eq 'bar'
    end

    it 'should raise an exception if the value is not present' do
      expect { subject.fetch('missing') }.to raise_exception KeyError, 'key not found: "missing"'
    end

    context 'when the option does not have a default value' do
      before(:each) do
        options = Msf::OptionContainer.new(
          [
            Msf::OptString.new(
              'OptionWithoutDefault',
              [true, 'option without default']
            )
          ]
        )

        subject.import_options(options)
      end

      it 'should return the value if it is imported with a default value' do
        subject.import_defaults_from_hash({ 'OptionWithoutDefault' => 'default_value' }, imported_by: 'self')
        expect(subject.fetch('OptionWithoutDefault')).to eq('default_value')
      end

      it 'should raise an exception if the value is not present' do
        expect { subject.fetch('OptionWithoutDefault') }.to raise_exception KeyError, 'key not found: "OptionWithoutDefault"'
      end
    end
  end

  describe '#length' do
    it 'should return a number' do
      expect(subject.length).to be > 0
    end
  end

  describe '#count' do
    it 'should return a number' do
      expect(subject.length).to be > 0
    end
  end

  context '#to_h' do
    it 'should return a Hash with correct values' do
      expected_to_h = opts.fetch(:expected_to_h) do
        { 'foo' => 'bar', 'fizz' => 'buzz' }
      end
      expect(subject.to_h).to eq(expected_to_h)
    end
  end

  context '#delete' do
    it 'should delete the specified case-insensitive key' do
      expect(subject.delete('foo')).to eq 'bar'
      expect(subject.delete('foo')).to be nil

      expect(subject.delete('Fizz')).to eq 'buzz'
      expect(subject.delete('Fizz')).to be nil
    end
  end
end

RSpec.shared_examples_for 'a datastore' do |opts|
  describe '#import_options' do
    context 'when importing simple options' do
      subject do
        s = instance_eval &opts[:default_subject]
        options = Msf::OptionContainer.new(
          [
            Msf::OptString.new(
              'foo',
              [true, 'Foo option', 'bar']
            ),
            Msf::OptString.new(
              'fizz',
              [true, 'fizz option', 'buzz']
            )
          ]
        )
        s.import_options(options)
        s
      end
      it_behaves_like 'a datastore with lookup support'
    end

    context 'when importing options with aliases' do
      subject(:datastore_with_aliases) do
        s = instance_eval &opts[:default_subject]

        options = Msf::OptionContainer.new(
          [
            Msf::OptString.new(
              'foo',
              [true, 'Foo option', 'bar']
            ),
            Msf::OptString.new(
              'fizz',
              [true, 'fizz option', 'buzz']
            ),
            Msf::OptString.new(
              'NewOptionName',
              [true, 'An option with a new name. Aliases ensure the old and new names are synchronized', 'default_value'],
              aliases: ['OLD_OPTION_NAME']
            )
          ]
        )

        s.import_options(options)
        s
      end

      describe '#[]' do
        it 'should have default keyed values' do
          expect(subject['NewOptionName']).to eq('default_value')
          expect(subject['OLD_OPTION_NAME']).to eq('default_value')
        end

        it 'should have case-insensitive lookups' do
          expect(subject['NEWOPTIONNAME']).to eq('default_value')
          expect(subject['Old_Option_Name']).to eq('default_value')
        end
      end

      describe '#[]=' do
        [
          nil,
          false,
          '',
          'new_value'
        ].each do |value|
          context "when the value is #{value.inspect}" do
            it 'should allow setting datastore values with the new option name' do
              subject['NewOptionName'] = value

              expect(subject['NewOptionName']).to eq(value)
              expect(subject.fetch('NewOptionName')).to eq(value)

              expect(subject['OLD_OPTION_NAME']).to eq(value)
              expect(subject.fetch('OLD_OPTION_NAME')).to eq(value)
            end

            it 'should allow setting datastore values with the old option name' do
              subject['OLD_OPTION_NAME'] = value

              expect(subject['NewOptionName']).to eq(value)
              expect(subject.fetch('NewOptionName')).to eq(value)

              expect(subject['OLD_OPTION_NAME']).to eq(value)
              expect(subject.fetch('OLD_OPTION_NAME')).to eq(value)
            end
          end
        end
      end

      describe '#fetch' do
        it 'should have default keyed values' do
          expect(subject['NewOptionName']).to eq('default_value')
          expect(subject['OLD_OPTION_NAME']).to eq('default_value')
        end

        it 'should have case-insensitive lookups' do
          expect(subject['NEWOPTIONNAME']).to eq('default_value')
          expect(subject['Old_Option_Name']).to eq('default_value')
        end

        it 'should raise an exception if the value is not present' do
          expect { subject.fetch('missing') }.to raise_exception KeyError, 'key not found: "missing"'
        end
      end

      describe '#import_defaults_from_hash' do
        subject do
          datastore_with_aliases.import_defaults_from_hash(
            {
              'foo' => 'overridden_default_foo',
              'NewOptionName' => 'overridden_default_new_option_name',
              # TODO: Add alias/old_option_name test as well
              # 'old_option_name' => 'overridden_default_old_option_name'
            },
            imported_by: 'self'
          )

          datastore_with_aliases
        end

        it 'should have default keyed values' do
          expect(subject['foo']).to eq 'overridden_default_foo'
          expect(subject['fizz']).to eq 'buzz'
          expect(subject['NewOptionName']).to eq('overridden_default_new_option_name')
          expect(subject['OLD_OPTION_NAME']).to eq('overridden_default_new_option_name')
        end

        # TODO: Add tests for setting / deleting
      end

      it_behaves_like 'a datastore with lookup support',
                      expected_to_h: {
                        'NewOptionName' => 'default_value',
                        'foo' => 'bar',
                        'fizz' => 'buzz'
                      }
    end

    context 'when importing options with fallbacks' do
      subject do
        s = instance_eval &opts[:default_subject]

        options = Msf::OptionContainer.new(
          [
            Msf::OptString.new(
              'foo',
              [true, 'Foo option', 'bar']
            ),
            Msf::OptString.new(
              'fizz',
              [true, 'fizz option', 'buzz']
            ),
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
            ),

            Msf::OptString.new(
              'USER_ATTR',
              [true, 'The SMB username'],
              fallbacks: ['username']
            ),
          ]
        )

        s.import_options(options)
        s.copy
      end

      context 'when no options have been set' do
        describe '#[]' do
          it 'should have default keyed values' do
            expect(subject['SMBUser']).to be(nil)
            expect(subject['SMBDomain']).to eq('WORKGROUP')
            expect(subject['USER_ATTR']).to be(nil)
            expect(subject['username']).to be(nil)
          end
        end

        describe '#[]=' do
          it 'should allow setting a key with fallbacks' do
            subject['SMBUser'] = 'username'
            expect(subject['SMBUser']).to eq('username')
            expect(subject['USER_ATTR']).to be(nil)
            expect(subject['username']).to be(nil)
          end

          it 'should allow setting a generic key' do
            subject['username'] = 'username'
            expect(subject['SMBUser']).to eq('username')
            expect(subject['USER_ATTR']).to eq('username')
            expect(subject['username']).to eq('username')
          end

          it 'should allow setting multiple keys with fallbacks' do
            subject['username'] = 'username_generic'
            subject['user_attr'] = 'username_attr'
            subject['smbuser'] = 'username_smb'
            expect(subject['SMBUser']).to eq('username_smb')
            expect(subject['USER_ATTR']).to eq('username_attr')
            expect(subject['username']).to eq('username_generic')
          end

          it 'should use the fallback in preference of the option default value' do
            subject['domain'] = 'example.local'
            expect(subject['SMBDomain']).to eq('example.local')
          end
        end
      end

      it_behaves_like 'a datastore with lookup support',
                      expected_to_h: {
                        'NewOptionName' => 'default_value',
                        'SMBDomain' => 'WORKGROUP',
                        'SMBUser' => '',
                        'USER_ATTR' => '',
                        'foo' => 'bar',
                        'fizz' => 'buzz'
                      }
      end
  end

  describe '#import_options_from_hash' do
    subject do
      hash = { 'foo' => 'bar', 'fizz' => 'buzz' }
      s = instance_eval &opts[:default_subject]
      s.import_options_from_hash(hash)
      s
    end
    it_behaves_like 'a datastore with lookup support'
  end

  describe '#import_options_from_s' do
    subject do
      str = 'foo=bar fizz=buzz'
      s = instance_eval &opts[:default_subject]
      s.import_options_from_s(str)
      s
    end
    it_behaves_like 'a datastore with lookup support'
  end

  describe '#from_file' do
    subject do
      ini_instance = double group?: true,
                            :[] => {
                              'foo' => 'bar',
                              'fizz' => 'buzz'
                            }
      ini_class = double from_file: ini_instance

      stub_const('Rex::Parser::Ini', ini_class)

      s = instance_eval &opts[:default_subject]
      s.from_file('path')
      s
    end

    it_behaves_like 'a datastore with lookup support'
  end

  describe '#user_defined' do
    subject do
      s = instance_eval &opts[:default_subject]

      options = Msf::OptionContainer.new(
        [
          Msf::OptString.new(
            'foo',
            [true, 'Foo option', 'bar']
          ),
          Msf::OptString.new(
            'fizz',
            [true, 'fizz option', 'buzz']
          ),
          Msf::OptString.new(
            'NewOptionName',
            [true, 'An option with a new name. Aliases ensure the old and new names are synchronized', 'default_value'],
            aliases: ['OLD_OPTION_NAME']
          )
        ]
      )

      s.import_options(options)
      s
    end

    context 'when no options have been set' do
      it 'should return an empty hash' do
        expect(subject.user_defined).to eq({})
      end
    end

    context 'when a value has been deleted' do
      before(:each) do
        subject.delete('foo')
      end

      it 'should explicitly include the deleted value' do
        expect(subject.user_defined).to eq({ 'foo' => nil})
      end
    end

    context 'when value have been explicitly set' do
      before(:each) do
        subject['foo'] = 'foo_value'
        subject['custom_key'] = 'custom_key_value'
        subject['OLD_OPTION_NAME'] = 'old_option_name_value'
      end

      it 'should return the set values' do
        expected_values = {
          "NewOptionName" => "old_option_name_value",
          "custom_key" => "custom_key_value",
          "foo" => "foo_value",
        }
        expect(subject.user_defined).to eq(expected_values)
      end
    end

    context 'when values have been merged with a hash' do
      before(:each) do
        subject.merge!(
          {
            "NewOptionName" => "old_option_name_value",
            "custom_key" => "custom_key_value",
            "foo" => "foo_value"
          }
        )
      end

      it 'should return the set values' do
        expected_values = {
          "NewOptionName" => "old_option_name_value",
          "custom_key" => "custom_key_value",
          "foo" => "foo_value",
        }
        expect(subject.user_defined).to eq(expected_values)
      end
    end

    context 'when values have been merged with a datastore' do
      before(:each) do
        other_datastore = subject.copy
        subject.delete('foo')
        subject['fizz'] = 'fizz_value'

        options = Msf::OptionContainer.new(
          Msf::Opt::stager_retry_options + Msf::Opt::http_proxy_options
        )

        other_datastore.import_options(options)
        other_datastore['fizz'] = 'new_fizz_value'
        other_datastore['HttpProxyPass'] = 'http_proxy_pass_value'
        other_datastore['HttpProxyType'] = 'SOCKS'

        subject.merge!(other_datastore)
      end

      it 'should return the set values' do
        expected_values = {
          "HttpProxyPass" => "http_proxy_pass_value",
          "HttpProxyType" => "SOCKS",
          "foo" => nil,
          "fizz" => "new_fizz_value"
        }
        expect(subject.user_defined).to eq(expected_values)
      end
    end
  end
end

RSpec.describe Msf::DataStore do
  it_behaves_like 'a datastore',
                  default_subject: proc { described_class.new }
end

# RSpec.describe Msf::ModuleDataStore do
#   return
#   let(:framework_datastore) do
#     Msf::DataStore.new
#   end
#   let(:mod) do
#     framework = instance_double(Msf::Framework, datastore: framework_datastore)
#     instance_double(
#       Msf::Exploit,
#       framework: framework
#     )
#   end
#
#   context 'when the framework datastore is empty' do
#     it_behaves_like 'a datastore',
#                     default_subject: proc {
#                       described_class.new mod
#                     }
#   end
#
#   context 'when the global framework datastore has values' do
#     describe '#default?' do
#       # TODO
#     end
#
#     describe '#[]' do
#       context 'when the option has a default value' do
#         subject do
#           s = described_class.new mod
#           options = Msf::OptionContainer.new(
#             [
#               Msf::OptString.new(
#                 'foo',
#                 [true, 'Foo option', 'bar']
#               ),
#             ]
#           )
#           s.import_options(options)
#           s
#         end
#
#         before(:each) do
#           framework_datastore['foo'] = 'global_foo_value'
#         end
#
#         it 'should return the default value' do
#           expect(subject['foo']).to eq('fizz')
#         end
#
#         it 'should return the value if it is imported with a default value' do
#           subject.import_defaults_from_hash({ 'foo' => 'default_value' }, imported_by: 'self')
#           expect(subject['foo']).to eq('default_value')
#         end
#
#         it 'should return the default option value, and not the framework datastore value' do
#           subject.delete('foo', also_delete: true)
#           expect(subject['foo']).to eq('bar')
#         end
#       end
#
#       context 'when the option does not have a default value' do
#         subject do
#           s = described_class.new mod
#           options = Msf::OptionContainer.new(
#             [
#               Msf::OptString.new(
#                 'OptionWithoutDefault',
#                 [true, 'option without default']
#               )
#             ]
#           )
#           s.import_options(options)
#           s
#         end
#
#         before(:each) do
#           framework_datastore['OptionWithoutDefault'] = 'global_default_value'
#         end
#
#         it 'should return the value if it is imported with a default value' do
#           subject.import_defaults_from_hash({ 'OptionWithoutDefault' => 'default_value' }, imported_by: 'self')
#           expect(subject['OptionWithoutDefault']).to eq('default_value')
#         end
#
#         it 'should return the parent datastore value if the value is not set' do
#           expect(subject['OptionWithoutDefault']).to eq('global_default_value')
#         end
#
#         it 'should return the default option value, and not the framework datastore value' do
#           subject.delete('foo', also_delete: true)
#           expect(subject['foo']).to eq('bar')
#         end
#       end
#     end
#
#     describe '#fetch' do
#       context 'when the option does not have a default value' do
#         subject do
#           s = described_class.new mod
#           options = Msf::OptionContainer.new(
#             [
#               Msf::OptString.new(
#                 'OptionWithoutDefault',
#                 [true, 'option without default']
#               )
#             ]
#           )
#           s.import_options(options)
#           s
#         end
#
#         before(:each) do
#           framework_datastore['OptionWithoutDefault'] = 'global_default_value'
#         end
#
#         it 'should return the value if it is imported with a default value' do
#           subject.import_defaults_from_hash({ 'OptionWithoutDefault' => 'default_value' }, imported_by: 'self')
#           expect(subject.fetch('OptionWithoutDefault')).to eq('default_value')
#         end
#
#         it 'should return the parent datastore value if the value is not set' do
#           expect(subject.fetch('OptionWithoutDefault')).to eq('global_default_value')
#         end
#
#         it 'should return the parent datastore value if the value is deleted' do
#           subject.delete('OptionWithoutDefault', also_delete: true)
#           expect { subject.fetch('OptionWithoutDefault') }.to raise_exception KeyError, 'key not found: "missing"'
#         end
#       end
#     end
#   end
# end

# Global FrameworkDatastore
#   Note: Metasploit doesn't _currently_ have any options registered insthe global store by default, but the
#   implementation will support it
#
#   #fetch(k) / #[k]
#     - Checking in order from top to bottom, attempts to return one of:
#         - User defined value (nil if the option has been explicitly unset)
#         - imported default
#         - option default
#         - nil or KeyError
#   #unset(k) / #delete(k)
#     - unsets the value entirely
#     - Future lookups will always return nil, defaults won't be used
#   #reset(k)
#     - Clears whatever user set value/unset was previously present
#     - Future
#   #default?(k)
#     - return true if user_defined is not set
#
# ModuleDatastore
#   #fetch(k) / #[k]
#     - Checking in order from top to bottom, attempts to return one of:
#         - User defined value (nil if the option has been explicitly unset)
#         - imported default
#         - option default
#         - framework datastore call
#         - nil or KeyError
#   #unset(k) / #delete(k)
#     - Clears any user defined value
#     - Future lookups will:
#         - look up the framework datastore
#   #reset(k)
#     - Clears any user defined value, or explicit unset
#     - Future lookups will return defaults again
#   #default?(k)
#     - Return true is user_defined is not set, and super is default?(k)
