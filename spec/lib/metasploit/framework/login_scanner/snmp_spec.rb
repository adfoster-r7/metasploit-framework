require 'spec_helper'
require 'metasploit/framework/login_scanner/snmp'

RSpec.describe Metasploit::Framework::LoginScanner::SNMP do
  let(:public) { 'public' }
  let(:private) { nil }

  let(:pub_comm) do
    Metasploit::Framework::Credential.new(
      paired: false,
      public: public,
      private: private
    )
  end

  let(:invalid_detail) do
    Metasploit::Framework::Credential.new(
      paired: true,
      public: nil,
      private: nil
    )
  end

  let(:detail_group) do
    [ pub_comm ]
  end

  subject(:snmp_scanner) do
    described_class.new
  end
end
