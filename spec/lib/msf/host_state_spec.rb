RSpec.describe Msf::HostState do
  context 'CONSTANTS' do
    context 'Alive' do
      subject(:alive) do
        described_class::Alive
      end

      it { is_expected.to eq('alive') }
    end

    context 'Dead' do
      subject(:dead) do
        described_class::Dead
      end

      it { is_expected.to eq('down') }
    end

    context 'Unknown' do
      subject(:unknown) do
        described_class::Unknown
      end

      it { is_expected.to eq('unknown') }
    end
  end
end
