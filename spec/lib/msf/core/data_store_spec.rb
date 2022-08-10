# -*- coding:binary -*-

require 'spec_helper'

RSpec.shared_examples_for 'a datastore with lookup support' do |opts = {}|
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
  describe '#import_option' do
    subject do
      s = opts[:default_subject].call
      s.import_option('foo', 'bar')
      s.import_option('fizz', 'buzz')
      s
    end
    it_behaves_like 'a datastore with lookup support'
  end

  describe '#import_options_from_hash' do
    subject do
      hash = { 'foo' => 'bar', 'fizz' => 'buzz' }
      s = opts[:default_subject].call
      s.import_options_from_hash(hash)
      s
    end
    it_behaves_like 'a datastore with lookup support'
  end

  describe '#import_options_from_s' do
    subject do
      str = 'foo=bar fizz=buzz'
      s = opts[:default_subject].call
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

      s = opts[:default_subject].call
      s.from_file('path')
      s
    end

    it_behaves_like 'a datastore with lookup support'
  end

  describe '#user_defined' do
    subject do
      s = opts[:default_subject].call
      s.import_option('foo', 'bar')
      s.import_option('fizz', 'buzz')

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

    context 'when no options have been set' do
      it 'should return an empty hash' do
        expect(subject.user_defined).to eq({})
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
        require 'pry'; binding.pry

        options = Msf::OptionContainer.new(
          Msf::Opt::stager_retry_options + Msf::Opt::http_proxy_options
        )

        other_datastore.import_options(options)
        other_datastore['HttpProxyPass'] = 'http_proxy_pass_value'
        other_datastore['HttpProxyType'] = 'SOCKS'

        subject.merge!(other_datastore)
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
  end

  describe '#import_options' do
    context 'when importing options with aliases' do
      subject do
        s = opts[:default_subject].call

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
          subject

          expect(subject['NewOptionName']).to eq('default_value')
          expect(subject['OLD_OPTION_NAME']).to eq('default_value')
        end

        it 'should have case-insensitive lookups' do
          expect(subject['NEWOPTIONNAME']).to eq('default_value')
          expect(subject['Old_Option_Name']).to eq('default_value')
        end
      end

      describe '#[]=' do
        it 'should allow setting datastore values with the new option name' do
          subject['NewOptionName'] = 'new_value_1'
          expect(subject['NewOptionName']).to eq('new_value_1')
          expect(subject['OLD_OPTION_NAME']).to eq('new_value_1')
        end

        it 'should allow setting datastore values with the old option name' do
          subject['OLD_OPTION_NAME'] = 'new_value_2'
          expect(subject['NewOptionName']).to eq('new_value_2')
          expect(subject['OLD_OPTION_NAME']).to eq('new_value_2')
        end
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
        s = opts[:default_subject].call

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
end

RSpec.describe Msf::DataStore do
  it_behaves_like 'a datastore',
                  default_subject: -> { described_class.new }
end

RSpec.describe Msf::ModuleDataStore do
  it_behaves_like 'a datastore',
                  default_subject: lambda {
                    described_class.new nil
                  }
end
