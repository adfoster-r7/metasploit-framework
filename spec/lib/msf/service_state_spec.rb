RSpec.describe Msf::ServiceState do
  context 'CONSTANTS' do
    context 'Closed' do
      subject(:closed) do
        described_class::Closed
      end

      it { is_expected.to eq('closed') }
    end

    context 'Filtered' do
      subject(:filtered) do
        described_class::Filtered
      end

      it { is_expected.to eq('filtered') }
    end

    context 'Open' do
      subject(:open) do
        described_class::Open
      end

      it { is_expected.to eq('open') }
    end

    context 'Unknown' do
      subject(:unknown) do
        described_class::Unknown
      end

      it { is_expected.to eq('unknown') }
    end
  end
end
