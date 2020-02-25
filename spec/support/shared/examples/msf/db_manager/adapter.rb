RSpec.shared_examples_for 'Msf::DBManager::Adapter' do
  if ENV['REMOTE_DB']
    before { skip("Not used for remote data service") }
  end

  context 'CONSTANTS' do
    context 'ADAPTER' do
      subject(:adapter) do
        described_class::ADAPTER
      end

      it { is_expected.to eq('postgresql') }
    end
  end

  it { is_expected.to respond_to :driver }
  it { is_expected.to respond_to :drivers }
  it { is_expected.to respond_to :drivers= }
  it { is_expected.to respond_to :initialize_adapter }
end
