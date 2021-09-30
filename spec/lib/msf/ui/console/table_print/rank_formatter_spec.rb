require 'spec_helper'

RSpec.describe Msf::Ui::Console::TablePrint::RankFormatter do
  def format(formatter, value)
    formatter.format(value, 0, [value])
  end

  describe '#format' do
    it 'should return the plaintext equivalent of all numerical rankings' do
      formatter = described_class.new

      expect(format(formatter, Msf::ManualRanking)).to eql Msf::RankingName[Msf::ManualRanking]
      expect(format(formatter, Msf::LowRanking)).to eql Msf::RankingName[Msf::LowRanking]
      expect(format(formatter, Msf::AverageRanking)).to eql Msf::RankingName[Msf::AverageRanking]
      expect(format(formatter, Msf::NormalRanking)).to eql Msf::RankingName[Msf::NormalRanking]
      expect(format(formatter, Msf::GoodRanking)).to eql Msf::RankingName[Msf::GoodRanking]
      expect(format(formatter, Msf::GreatRanking)).to eql Msf::RankingName[Msf::GreatRanking]
      expect(format(formatter, Msf::ExcellentRanking)).to eql Msf::RankingName[Msf::ExcellentRanking]
    end

    it 'should return an unrecognized numerical ranking unchanged' do
      formatter = described_class.new

      expect(format(formatter, 42)).to eql 42
      expect(format(formatter, [])).to eql []
      expect(format(formatter, {})).to eql Hash.new
    end
  end
end
