require 'spec_helper'

RSpec.describe Msf::AggregateModule do

  include_context 'Msf::Simple::Framework'

  # TODO: Seems sus, threads were only left over at the end - pointing to rspec leaking threads?
  include_context 'Msf::Framework#threads cleaner'
  # include_context 'Metasploit::Framework::Spec::Constants cleaner'

  def create_mod
    described_class = self.described_class
    mod_klass = Class.new(Msf::Auxiliary) do
      include described_class

      def initialize(module_actions)
        super(
          'Name' => 'Mock aggregate module name',
          'Description' => 'Mock aggregate module description',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE,
          'Actions' => module_actions
        )
      end
    end
    mod_klass.framework = framework
    instance = mod_klass.new(module_actions)
    Msf::Simple::Framework.simplify_module(instance, false)
    instance
  end

  before :each do
    framework.modules.add_module_path(File.join(FILE_FIXTURES_PATH, 'modules'))
  end

  describe 'scanner module support' do
    let(:module_actions) do
      [
        [
          'scan',
          {
            'Description' => 'Scan the target',
            'ModuleName' => 'auxiliary/scanner',
            'AssociatedTags' => []
          }
        ]
      ]
    end

    context 'when there is one RHOST value' do
      it 'returns one result' do
        mod = create_mod
        result = mod.run_simple(
          'Action' => 'scan',
          'Options' => {
            'RHOSTS' => '192.0.2.0',
          },
          'RunAsJob' => false,
          'Quiet' => true
        )

        expected_result = {
          "auxiliary/scanner" => {
            "192.0.2.0" => "scanner result for 192.0.2.0"
          }
        }

        expect(mod.error).to be_nil
        expect(result).to eq(expected_result)
      end
    end

    context 'when there are multiple RHOSTS' do
      it 'returns all results' do
        mod = create_mod
        result = mod.run_simple(
          'Action' => 'scan',
          'Options' => {
            'RHOSTS' => '192.0.2.0/30',
          },
          'RunAsJob' => false,
          'Quiet' => true
        )

        expected_result = {
          "auxiliary/scanner" => {
            "192.0.2.0" => "scanner result for 192.0.2.0",
            "192.0.2.1" => "scanner result for 192.0.2.1",
            "192.0.2.2" => "scanner result for 192.0.2.2",
            "192.0.2.3" => "scanner result for 192.0.2.3"
          }
        }

        expect(mod.error).to be_nil
        expect(result).to eq(expected_result)
      end
    end
  end

  describe 'action validation' do
    context 'when duplicate actions are present' do
      let(:module_actions) do
        [
          [
            'scan',
            {
              'Description' => 'Scan the target',
              'ModuleName' => 'auxiliary/scanner',
              'AssociatedTags' => []
            }
          ],
          [
            'scan',
            {
              'Description' => 'Scan the target',
              'ModuleName' => 'auxiliary/simple',
              'AssociatedTags' => []
            }
          ]
        ]
      end

      it 'creates a validation error' do
        expected_message = "Module 'Mock aggregate module name' has duplicate actions: scan"
        expect { create_mod }.to raise_error Msf::ValidationError, expected_message
      end
    end

    context 'when the target module does not exist' do
      let(:module_actions) do
        [
          [
            'scan',
            {
              'Description' => 'Scan the target',
              'ModuleName' => 'auxiliary/typoed_module_name',
              'AssociatedTags' => []
            }
          ]
        ]
      end

      it 'creates a validation error' do
        expected_message = "Aggregate module unable to load dependency 'auxiliary/typoed_module_name' for action 'scan'"
        expect { create_mod }.to raise_error Msf::ValidationError, expected_message
      end
    end

    context 'when attempting to configure an exploit module' do
      let(:module_actions) do
        [
          [
            'exploit',
            {
              'Description' => 'Scan the target',
              'ModuleName' => 'exploit/auto_target_linux',
              'AssociatedTags' => []
            }
          ]
        ]
      end

      it 'creates a validation error' do
        expected_message = "Action 'exploit' depends on a non-auxiliary module 'exploit/auto_target_linux', this functionality is not supported"
        expect { create_mod }.to raise_error Msf::ValidationError, expected_message
      end
    end
  end
end
