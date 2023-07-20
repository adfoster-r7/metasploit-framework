require 'rspec'

RSpec.describe 'singles/osx/aarch64/exec' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'osx/aarch64/exec',
      ancestor_reference_names: [
        'singles/osx/aarch64/exec'
      ]
    )
  end
  let(:cmd) { nil }
  let(:datastore_values) { { 'CMD' => cmd } }

  before(:each) do
    subject.datastore.merge!(datastore_values)
  end

  describe '#generate' do
    context 'when the CMD is /bin/bash' do
      let(:cmd) { 'ABCD' }

      it 'generates' do
        expect(subject.generate).to eq('ABCD')
      end
    end
  end
end
