# -*- coding:binary -*-

require 'spec_helper'

RSpec.shared_context 'datastore subjects', :shared_context => :metadata do
  subject(:default_subject) do
    described_class.new
  end

  subject(:datastore_with_simple_options) do
    s = default_subject.copy
    options = Msf::OptionContainer.new(
      [
        Msf::OptString.new(
          'foo',
          [true, 'foo option', 'default_foo_value']
        ),
        Msf::OptString.new(
          'bar',
          [true, 'bar option', 'default_bar_value']
        ),
        Msf::OptString.new(
          'baz',
          [false, 'baz option']
        )
      ]
    )
    s.import_options(options)
    s
  end

  subject(:datastore_with_aliases) do
    s = default_subject.copy

    options = Msf::OptionContainer.new(
      [
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

  subject(:datastore_with_fallbacks) do
    s = default_subject.copy

    options = Msf::OptionContainer.new(
      [
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
          [true, 'The ldap username'],
          fallbacks: ['username']
        ),
      ]
    )

    s.import_options(options)
    s
  end

  subject(:complex_datastore) do
    datastore_with_simple_options
      .merge(datastore_with_aliases)
      .merge(datastore_with_fallbacks)
  end

  subject(:complex_datastore_with_imported_defaults) do
    s = complex_datastore.copy
    s.import_defaults_from_hash(
      {
        'foo' => 'overridden_default_foo',
        'NewOptionName' => 'overridden_default_new_option_name',
        # TODO: Add alias/old_option_name test as well
        # 'old_option_name' => 'overridden_default_old_option_name'
      },
      imported_by: 'self'
    )
    s
  end
end

RSpec.shared_examples_for 'a datastore with lookup support' do |opts = {}|
  describe '#[]' do
    it 'should have default keyed values' do
      expect(subject['foo']).to eq 'foo_value'
      expect(subject['bar']).to eq 'bar_value'
    end

    it 'should have case-insensitive lookups' do
      # Sorted by gray code, just for fun
      expect(subject['foo']).to eq 'foo_value'
      expect(subject['Foo']).to eq 'foo_value'
      expect(subject['FOo']).to eq 'foo_value'
      expect(subject['fOo']).to eq 'foo_value'
      expect(subject['fOO']).to eq 'foo_value'
      expect(subject['FOO']).to eq 'foo_value'
      expect(subject['FoO']).to eq 'foo_value'
      expect(subject['foO']).to eq 'foo_value'
    end
  end

  describe '#fetch' do
    it 'should have default keyed values' do
      expect(subject.fetch('foo')).to eq 'foo_value'
      expect(subject.fetch('bar')).to eq 'bar_value'
    end

    it 'should have case-insensitive lookups' do
      # Sorted by gray code, just for fun
      expect(subject.fetch('foo')).to eq 'foo_value'
      expect(subject.fetch('Foo')).to eq 'foo_value'
      expect(subject.fetch('FOo')).to eq 'foo_value'
      expect(subject.fetch('fOo')).to eq 'foo_value'
      expect(subject.fetch('fOO')).to eq 'foo_value'
      expect(subject.fetch('FOO')).to eq 'foo_value'
      expect(subject.fetch('FoO')).to eq 'foo_value'
      expect(subject.fetch('foO')).to eq 'foo_value'
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
        { 'foo' => 'foo_value', 'bar' => 'bar_value' }
      end
      expect(subject.to_h).to eq(expected_to_h)
    end
  end

  describe '#unset' do
    it 'should delete the specified case-insensitive key' do
      expect(subject.unset('foo')).to eq 'foo_value'
      expect(subject.unset('foo')).to eq nil

      expect(subject.unset('bar')).to eq 'bar_value'
      expect(subject.unset('bar')).to eq nil
    end
  end
end

RSpec.shared_examples_for 'a datastore' do
  describe '#import_options' do
    let(:foo_option) do
      Msf::OptString.new(
        'foo',
        [true, 'foo option', 'default_foo_value']
      )
    end
    let(:bar_option) do
      Msf::OptString.new(
        'bar',
        [true, 'bar option', 'default_bar_value']
      )
    end
    subject do
      s = default_subject
      options = Msf::OptionContainer.new(
        [
          foo_option,
          bar_option
        ]
      )
      s.import_options(options)
      s
    end

    it 'should import the given options' do
      expected_options = {
        'foo' => foo_option,
        'bar' => bar_option
      }

      expect(subject.options).to eq(expected_options)
    end
  end

  describe '#import_options_from_hash' do
    subject do
      hash = { 'foo' => 'foo_value', 'bar' => 'bar_value' }
      s = default_subject
      s.import_options_from_hash(hash)
      s
    end
    it_behaves_like 'a datastore with lookup support'
  end

  describe '#import_options_from_s' do
    subject do
      str = 'foo=foo_value bar=bar_value'
      s = default_subject
      s.import_options_from_s(str)
      s
    end
    it_behaves_like 'a datastore with lookup support'
  end

  describe '#from_file' do
    subject do
      ini_instance = double group?: true,
                            :[] => {
                              'foo' => 'foo_value',
                              'bar' => 'bar_value'
                            }
      ini_class = double from_file: ini_instance

      stub_const('Rex::Parser::Ini', ini_class)

      s = default_subject
      s.from_file('path')
      s
    end

    it_behaves_like 'a datastore with lookup support'
  end

  describe '#user_defined' do
    subject do
      complex_datastore
    end

    context 'when no options have been set' do
      it 'should return an empty hash' do
        expect(subject.user_defined).to eq({})
      end
    end

    context 'when a value has been unset' do
      before(:each) do
        subject.unset('foo')
      end

      it 'should explicitly include the unset value' do
        expect(subject.user_defined).to eq({ 'foo' => nil })
      end
    end

    context 'when values have been explicitly set' do
      before(:each) do
        subject['foo'] = 'foo_value'
        subject['custom_key'] = 'custom_key_value'
        subject['OLD_OPTION_NAME'] = 'old_option_name_value'
        subject['SMBUser'] = 'smbuser_user'
      end

      it 'should return the set values' do
        expected_values = {
          "NewOptionName" => "old_option_name_value",
          "custom_key" => "custom_key_value",
          "foo" => "foo_value",
          'SMBUser' => 'smbuser_user'
        }
        expect(subject.user_defined).to eq(expected_values)
      end
    end

    context 'when a fallback has been set' do
      before(:each) do
        subject.merge!(
          {
            "username" => "username",
          }
        )
      end

      it 'should not return SMBUser/USER_ATTR etc' do
        expected_values = {
          "username" => "username"
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
        subject.unset('foo')
        subject['bar'] = 'bar_value'

        options = Msf::OptionContainer.new(
          Msf::Opt::stager_retry_options + Msf::Opt::http_proxy_options
        )

        other_datastore.import_options(options)
        other_datastore['bar'] = 'new_bar_value'
        other_datastore['HttpProxyPass'] = 'http_proxy_pass_value'
        other_datastore['HttpProxyType'] = 'SOCKS'

        subject.merge!(other_datastore)
      end

      it 'should return the set values' do
        expected_values = {
          "HttpProxyPass" => "http_proxy_pass_value",
          "HttpProxyType" => "SOCKS",
          "foo" => nil,
          "bar" => "new_bar_value"
        }
        expect(subject.user_defined).to eq(expected_values)
      end
    end
  end

  describe '#[]' do
    context 'when the datastore has no options registered' do
      subject do
        default_subject
      end

      it 'should reset the specified key' do
        expect(subject['foo']).to eq nil
        expect(subject['bar']).to eq nil
      end
    end

    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

      it 'should have default keyed values' do
        expect(subject['NewOptionName']).to eq('default_value')
        expect(subject['OLD_OPTION_NAME']).to eq('default_value')
      end

      it 'should have case-insensitive lookups' do
        expect(subject['NEWOPTIONNAME']).to eq('default_value')
        expect(subject['Old_Option_Name']).to eq('default_value')
      end
    end

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

      it 'should have default keyed values' do
        expect(subject['SMBUser']).to be(nil)
        expect(subject['SMBDomain']).to eq('WORKGROUP')
        expect(subject['USER_ATTR']).to be(nil)
        expect(subject['username']).to be(nil)
      end
    end
  end

  describe '#fetch' do
    context 'when the datastore has simple options' do
      subject do
        datastore_with_simple_options
      end

      context 'when the default value is nil' do
        before(:each) do
          subject.options['foo'].send(:default=, nil)
        end

        it 'should handle the nil value' do
          expect(subject['foo']).to eq(nil)
          expect { subject.fetch('foo') }.to raise_exception KeyError, 'key not found: "foo"'
        end
      end

      context 'when there is a default value' do
        [
          false,
          '',
          'new_value'
        ].each do |value|
          context "when the default value is #{value.inspect}" do
            before(:each) do
              subject.options['foo'].send(:default=, value)
            end

            it 'should return the default value' do
              expect(subject['foo']).to eq(value)
              expect(subject.fetch('foo')).to eq(value)
            end
          end
        end
      end
    end

    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

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
  end

  describe '#[]=' do
    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

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

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

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

  describe '#import_defaults_from_hash' do
    subject do
      complex_datastore.import_defaults_from_hash(
        {
          'foo' => 'overridden_default_foo',
          'NewOptionName' => 'overridden_default_new_option_name',
          # TODO: Add alias/old_option_name test as well
          # 'old_option_name' => 'overridden_default_old_option_name'
        },
        imported_by: 'self'
      )

      complex_datastore
    end

    it 'should have default keyed values' do
      expect(subject['foo']).to eq 'overridden_default_foo'
      expect(subject['bar']).to eq 'default_bar_value'
      expect(subject['NewOptionName']).to eq('overridden_default_new_option_name')
      expect(subject['OLD_OPTION_NAME']).to eq('overridden_default_new_option_name')
    end
  end

  describe '#unset' do
    context 'when the datastore has no options registered' do
      subject do
        default_subject
      end

      it 'should delete the value when it has been user defined' do
        subject['foo'] = 'new_value'

        expect(subject.unset('foo')).to eq 'new_value'
        expect(subject.unset('fool')).to eq nil
      end

      it 'should delete the value when it has not been user defined' do
        expect(subject.unset('foo')).to eq nil
        expect(subject.unset('foo')).to eq nil
      end
    end

    context 'when the datastore has simple options' do
      subject do
        datastore_with_simple_options
      end

      it 'should delete the value when it has been user defined' do
        subject['foo'] = 'new_value'

        expect(subject.unset('foo')).to eq 'new_value'
        expect(subject.unset('foo')).to eq nil
      end

      it 'should delete the value when it has not been user defined' do
        expect(subject.unset('foo')).to eq 'default_foo_value'
        expect(subject.unset('foo')).to eq nil
      end
    end

    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

      # Ensure that both the new name and old name can be used interchangeably
      [
        { set_key: 'NewOptionName', delete_key: 'NewOptionName' },
        { set_key: 'OLD_OPTION_NAME', delete_key: 'OLD_OPTION_NAME' },
        { set_key: 'NewOptionName', delete_key: 'OLD_OPTION_NAME' },
        { set_key: 'OLD_OPTION_NAME', delete_key: 'NewOptionName' },
      ].each do |test|
        context "when using #{test[:delete_key].inspect} to set the value and deleting with #{test[:delete_key].inspect}" do
          it 'should delete the value when it has been user defined' do
            subject[test[:set_key]] = 'new_value'

            expect(subject.unset(test[:delete_key])).to eq 'new_value'
            expect(subject.unset(test[:delete_key])).to eq nil
          end

          it 'should delete the value when it has not been user defined' do
            expect(subject.unset(test[:delete_key])).to eq 'default_value'
            expect(subject.unset(test[:delete_key])).to eq nil
          end
        end
      end
    end

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

      context 'when using the option name' do
        it 'should delete the value when it has been user defined' do
          subject['SMBDomain'] = 'new_value'

          expect(subject.unset('SMBDomain')).to eq 'new_value'
          expect(subject.unset('SMBDomain')).to eq nil
        end

        it 'should delete the value when it has not been user defined' do
          expect(subject.unset('SMBDomain')).to eq 'WORKGROUP'
          expect(subject.unset('SMBDomain')).to eq nil
        end
      end

      context 'when using the fallback option name' do
        it 'should delete the value when it has been user defined' do
          subject['domain'] = 'new_value'

          # Explicitly unsetting SMBDomain shouldn't unset domain
          expect(subject['SMBDomain']).to eq 'new_value'
          expect(subject.unset('SMBDomain')).to eq 'new_value'
          expect(subject.unset('SMBDomain')).to eq nil

          expect(subject['domain']).to eq 'new_value'
          expect(subject.unset('domain')).to eq 'new_value'
          expect(subject.unset('domain')).to eq nil
        end

        it 'should delete the value when it has not been user defined' do
          expect(subject.unset('domain')).to eq nil
          expect(subject.unset('SMBDomain')).to eq 'WORKGROUP'
          expect(subject['domain']).to eq nil
        end
      end
    end

    context 'when the datastore has imported defaults' do
      subject do
        complex_datastore_with_imported_defaults
      end

      it 'should reset the specified key' do
        subject['foo'] = 'new_value'
        subject.reset('foo')

        expect(subject['foo']).to eq 'overridden_default_foo'
      end
    end
  end

  context '#to_h' do
    context 'when the datastore has no options registered' do
      subject do
        default_subject
      end

      it 'should return a Hash with correct values' do
        expected_to_h = {
        }
        expect(subject.to_h).to eq(expected_to_h)
      end
    end

    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

      it 'should return a Hash with correct values' do
        expected_to_h = {
          "NewOptionName" => "default_value"
        }
        expect(subject.to_h).to eq(expected_to_h)
      end
    end

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

      it 'should return a Hash with correct values' do
        expected_to_h = {
          "SMBDomain"=>"WORKGROUP",
          "SMBUser"=>"",
          "USER_ATTR"=>""
        }
        expect(subject.to_h).to eq(expected_to_h)
      end
    end

    context 'when the datastore has imported defaults' do
      subject do
        complex_datastore_with_imported_defaults
      end

      it 'should return a Hash with correct values' do
        expected_to_h = {
          "NewOptionName" => "overridden_default_new_option_name",
          "SMBDomain" => "WORKGROUP",
          "SMBUser" => "",
          "USER_ATTR" => "",
          "foo" => "overridden_default_foo",
          "bar" => "default_bar_value",
          "baz" => ""
        }
        expect(subject.to_h).to eq(expected_to_h)
      end
    end
  end

  describe '#reset' do
    context 'when the datastore has no options registered' do
      subject do
        default_subject
      end

      before(:each) do
        subject['foo'] = 'new_value'
        subject.reset('foo')
      end

      it 'should reset the specified key' do
        expect(subject['foo']).to eq nil
        expect(subject['bar']).to eq nil
      end
    end

    context 'when the datastore has simple options' do
      subject do
        datastore_with_simple_options
      end

      before(:each) do
        subject['foo'] = 'new_value'
        subject.reset('foo')
      end

      it 'should reset the specified key' do
        expect(subject['foo']).to eq 'default_foo_value'
      end
    end

    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

      context 'when resetting the new name' do
        before(:each) do
          subject['NewOptionName'] = 'new_value'
          subject.reset('NewOptionName')
        end

        it 'should reset the specified key' do
          expect(subject['NewOptionName']).to eq 'default_value'
        end
      end

      context 'when resetting the old name 'do
        before(:each) do
          subject['NewOptionName'] = 'new_value'
          subject.reset('old_option_name')
        end

        it 'should reset the specified key' do
          expect(subject['NewOptionName']).to eq 'default_value'
        end
      end
    end

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

      it 'should reset the specified key' do
        subject['SMBUser'] = 'new_value'
        subject.reset('SMBDomain')

        expect(subject['SMBDomain']).to eq 'WORKGROUP'
      end
    end

    context 'when the datastore has imported defaults' do
      subject do
        complex_datastore_with_imported_defaults
      end

      it 'should reset the specified key' do
        subject['foo'] = 'new_value'
        subject.reset('foo')

        expect(subject['foo']).to eq 'overridden_default_foo'
      end
    end
  end
end

RSpec.describe Msf::DataStore do
  include_context 'datastore subjects'

  subject(:default_subject) do
    described_class.new
  end

  subject { default_subject }

  it_behaves_like 'a datastore'
end

RSpec.describe Msf::ModuleDataStore do
  include_context 'datastore subjects'

  let(:framework_datastore) do
    Msf::DataStore.new
  end
  let(:mod) do
    framework = instance_double(Msf::Framework, datastore: framework_datastore)
    instance_double(
      Msf::Exploit,
      framework: framework
    )
  end
  subject(:default_subject) do
    described_class.new mod
  end
  subject { default_subject }

  context 'when the framework datastore is empty' do
    it_behaves_like 'a datastore'
  end

  context 'when the global framework datastore has values' do
    describe '#default?' do
      context 'when the datastore has no options registered' do
        subject do
          default_subject
        end

        it 'should return true when the value is not set' do
          expect(subject.default?('foo')).to be true
        end

        it 'should return false if the value is set' do
          subject['foo'] = 'bar'

          expect(subject.default?('foo')).to be false
        end

        it 'should return false if the value has been unset' do
          subject.unset('foo')

          expect(subject.default?('foo')).to be false
        end

        it 'should return true if the value has been reset' do
          subject.unset('foo')
          subject.reset('foo')

          expect(subject.default?('foo')).to be true
        end
      end

      context 'when the datastore has aliases' do
        subject do
          datastore_with_aliases
        end

        # Ensure that both the new name and old name can be used interchangeably
        [
          { set_key: 'NewOptionName', read_key: 'NewOptionName' },
          { set_key: 'OLD_OPTION_NAME', read_key: 'OLD_OPTION_NAME' },
          { set_key: 'NewOptionName', read_key: 'OLD_OPTION_NAME' },
          { set_key: 'OLD_OPTION_NAME', read_key: 'NewOptionName' },
        ].each do |test|
          context "when using #{test[:set_key].inspect} to set the value and reading with #{test[:read_key].inspect}" do
            it 'should return true when the value is not set' do
              expect(subject.default?(test[:read_key])).to be true
            end

            it 'should return false if the value is set' do
              subject[test[:set_key]] = 'bar'

              expect(subject.default?(test[:read_key])).to be false
            end

            it 'should return false if the value has been unset' do
              subject.unset(test[:set_key])

              expect(subject.default?(test[:read_key])).to be false
            end

            it 'should return true if the value has been reset' do
              subject.unset(test[:set_key])
              subject.reset(test[:set_key])

              expect(subject.default?(test[:read_key])).to be true
            end
          end
        end
      end

      context 'when the datastore has fallbacks' do
        subject do
          datastore_with_fallbacks
        end

        it 'should return true when the value is not set' do
          expect(subject.default?('SMBDomain')).to be true
        end

        it 'should return false if the value is set' do
          subject['SMBDomain'] = 'bar'

          expect(subject.default?('SMBDomain')).to be false
        end

        it 'should return false if the value has been unset' do
          subject.unset('SMBDomain')

          expect(subject.default?('SMBDomain')).to be false
        end

        it 'should return true if the value has been reset' do
          subject.unset('SMBDomain')
          subject.reset('SMBDomain')

          expect(subject.default?('SMBDomain')).to be true
        end

        it 'should return false if the fallback value has been set' do
          subject['domain'] = 'foo'

          expect(subject.default?('SMBDomain')).to be false
        end
      end
    end

    # describe '#[]' do
    #   context 'when the datastore has no options registered' do
    #     subject do
    #       default_subject
    #     end
    #
    #     it 'should reset the specified key' do
    #       expect(subject['foo']).to eq nil
    #       expect(subject['bar']).to eq nil
    #     end
    #   end
    #
    #   context 'when the datastore has aliases' do
    #     subject do
    #       datastore_with_aliases
    #     end
    #
    #     it 'should have default keyed values' do
    #       expect(subject['NewOptionName']).to eq('default_value')
    #       expect(subject['OLD_OPTION_NAME']).to eq('default_value')
    #     end
    #
    #     it 'should have case-insensitive lookups' do
    #       expect(subject['NEWOPTIONNAME']).to eq('default_value')
    #       expect(subject['Old_Option_Name']).to eq('default_value')
    #     end
    #   end
    #
    #   context 'when the datastore has fallbacks' do
    #     subject do
    #       datastore_with_fallbacks
    #     end
    #
    #     it 'should have default keyed values' do
    #       expect(subject['SMBUser']).to be(nil)
    #       expect(subject['SMBDomain']).to eq('WORKGROUP')
    #       expect(subject['USER_ATTR']).to be(nil)
    #       expect(subject['username']).to be(nil)
    #     end
    #   end
    # end
    #
    # describe '#fetch' do
    #   context 'when the datastore has simple options' do
    #     subject do
    #       datastore_with_simple_options
    #     end
    #
    #     context 'when the default value is nil' do
    #       before(:each) do
    #         subject.options['foo'].send(:default=, nil)
    #       end
    #
    #       it 'should handle the nil value' do
    #         expect(subject['foo']).to eq(nil)
    #         expect { subject.fetch('foo') }.to raise_exception KeyError, 'key not found: "foo"'
    #       end
    #     end
    #
    #     context 'when there is a default value' do
    #       [
    #         false,
    #         '',
    #         'new_value'
    #       ].each do |value|
    #         context "when the default value is #{value.inspect}" do
    #           before(:each) do
    #             subject.options['foo'].send(:default=, value)
    #           end
    #
    #           it 'should return the default value' do
    #             expect(subject['foo']).to eq(value)
    #             expect(subject.fetch('foo')).to eq(value)
    #           end
    #         end
    #       end
    #     end
    #   end
    #
    #   context 'when the datastore has aliases' do
    #     subject do
    #       datastore_with_aliases
    #     end
    #
    #     it 'should have default keyed values' do
    #       expect(subject['NewOptionName']).to eq('default_value')
    #       expect(subject['OLD_OPTION_NAME']).to eq('default_value')
    #     end
    #
    #     it 'should have case-insensitive lookups' do
    #       expect(subject['NEWOPTIONNAME']).to eq('default_value')
    #       expect(subject['Old_Option_Name']).to eq('default_value')
    #     end
    #
    #     it 'should raise an exception if the value is not present' do
    #       expect { subject.fetch('missing') }.to raise_exception KeyError, 'key not found: "missing"'
    #     end
    #   end
    # end

    # describe '#[]' do
    #   context 'when the option has a default value' do
    #     subject do
    #       s = described_class.new mod
    #       options = Msf::OptionContainer.new(
    #         [
    #           Msf::OptString.new(
    #             'foo',
    #             [true, 'Foo option', 'bar']
    #           ),
    #         ]
    #       )
    #       s.import_options(options)
    #       s
    #     end
    #
    #     before(:each) do
    #       framework_datastore['foo'] = 'global_foo_value'
    #     end
    #
    #     it 'should return the default value' do
    #       expect(subject['foo']).to eq('bar')
    #     end
    #
    #     it 'should return the value if it is imported with a default value' do
    #       subject.import_defaults_from_hash({ 'foo' => 'default_value' }, imported_by: 'self')
    #       expect(subject['foo']).to eq('default_value')
    #     end
    #
    #     it 'should return the default option value, and not the framework datastore value' do
    #       subject.unset('foo', also_delete: true)
    #       expect(subject['foo']).to eq('bar')
    #     end
    #   end
    #
    #   context 'when the option does not have a default value' do
    #     subject do
    #       s = described_class.new mod
    #       options = Msf::OptionContainer.new(
    #         [
    #           Msf::OptString.new(
    #             'OptionWithoutDefault',
    #             [true, 'option without default']
    #           )
    #         ]
    #       )
    #       s.import_options(options)
    #       s
    #     end
    #
    #     before(:each) do
    #       framework_datastore['OptionWithoutDefault'] = 'global_default_value'
    #     end
    #
    #     it 'should return the value if it is imported with a default value' do
    #       subject.import_defaults_from_hash({ 'OptionWithoutDefault' => 'default_value' }, imported_by: 'self')
    #       expect(subject['OptionWithoutDefault']).to eq('default_value')
    #     end
    #
    #     it 'should return the parent datastore value if the value is not set' do
    #       expect(subject['OptionWithoutDefault']).to eq('global_default_value')
    #     end
    #
    #     it 'should return the default option value, and not the framework datastore value' do
    #       subject.unset('foo', also_delete: true)
    #       expect(subject['foo']).to eq('bar')
    #     end
    #   end
    # end
    #
    # describe '#fetch' do
    #   context 'when the option does not have a default value' do
    #     subject do
    #       s = described_class.new mod
    #       options = Msf::OptionContainer.new(
    #         [
    #           Msf::OptString.new(
    #             'OptionWithoutDefault',
    #             [true, 'option without default']
    #           )
    #         ]
    #       )
    #       s.import_options(options)
    #       s
    #     end
    #
    #     before(:each) do
    #       framework_datastore['OptionWithoutDefault'] = 'global_default_value'
    #     end
    #
    #     it 'should return the value if it is imported with a default value' do
    #       subject.import_defaults_from_hash({ 'OptionWithoutDefault' => 'default_value' }, imported_by: 'self')
    #       expect(subject.fetch('OptionWithoutDefault')).to eq('default_value')
    #     end
    #
    #     it 'should return the parent datastore value if the value is not set' do
    #       expect(subject.fetch('OptionWithoutDefault')).to eq('global_default_value')
    #     end
    #
    #     it 'should return the parent datastore value if the value is deleted' do
    #       subject.unset('OptionWithoutDefault', also_delete: true)
    #       expect { subject.fetch('OptionWithoutDefault') }.to raise_exception KeyError, 'key not found: "missing"'
    #     end
    #   end
    # end
  end
end

# Global FrameworkDatastore
#   Note: Metasploit doesn't _currently_ have any options registered in the global store by default, but the
#   implementation will now support it
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
