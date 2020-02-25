require 'spec_helper'

RSpec.describe Msf::Module::Failure do
  context 'CONSTANTS' do
    context 'None' do
      subject(:none) do
        described_class::None
      end
      it { is_expected.to eq('none') }
    end

    context 'Unknown' do
      subject(:unknown) do
        described_class::Unknown
      end
      it { is_expected.to eq('unknown') }
    end
    context 'Unreachable' do
      subject(:unreachable) do
        described_class::Unreachable
      end
      it { is_expected.to eq('unreachable') }
    end

    context 'BadConfig' do
      subject(:bad_config) do
        described_class::BadConfig
      end
      it { is_expected.to eq('bad-config') }
    end

    context 'Disconnected' do
      subject(:disconnected) do
        described_class::Disconnected
      end
      it { is_expected.to eq('disconnected') }
    end

    context 'NotFound' do
      subject(:not_found) do
        described_class::NotFound
      end
      it { is_expected.to eq('not-found') }
    end

    context 'UnexpectedReply' do
      subject(:unexpected_reply) do
        described_class::UnexpectedReply
      end

      it { is_expected.to eq('unexpected-reply') }
    end

    context 'TimeoutExpired' do
      subject(:timeout_expired) do
        described_class::TimeoutExpired
      end

      it { is_expected.to eq('timeout-expired') }
    end

    context 'UserInterrupt' do
      subject(:user_interrupt) do
        described_class::UserInterrupt
      end

      it { is_expected.to eq('user-interrupt') }
    end

    context 'NoAccess' do
      subject(:no_access) do
        described_class::NoAccess
      end

      it { is_expected.to eq('no-access') }
    end

    context 'NoTarget' do
      subject(:no_target) do
        described_class::NoTarget
      end

      it { is_expected.to eq('no-target') }
    end

    context 'NotVulnerable' do
      subject(:not_vulnerable) do
        described_class::NotVulnerable
      end

      it { is_expected.to eq('not-vulnerable') }
    end

    context 'PayloadFailed' do
      subject(:payload_failed) do
        described_class::PayloadFailed
      end

      it { is_expected.to eq('payload-failed') }
    end
  end
end
