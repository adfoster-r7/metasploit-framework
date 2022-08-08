# -*- coding:binary -*-

require 'spec_helper'

RSpec.shared_examples "datastore" do |opts = {}|
  it "should have options" do
    expect(subject["foo"]).to eq "bar"
    expect(subject["fizz"]).to eq "buzz"
  end

  it "should have case-insensitive lookups" do
    # Sorted by gray code, just for fun
    expect(subject["foo"]).to eq "bar"
    expect(subject["Foo"]).to eq "bar"
    expect(subject["FOo"]).to eq "bar"
    expect(subject["fOo"]).to eq "bar"
    expect(subject["fOO"]).to eq "bar"
    expect(subject["FOO"]).to eq "bar"
    expect(subject["FoO"]).to eq "bar"
    expect(subject["foO"]).to eq "bar"
  end

  context "#to_h" do
    it "should return a Hash with correct values" do
      expected_to_h = opts.fetch(:expected_to_h) do
        { "foo" => "bar", "fizz" => "buzz" }
      end
      expect(subject.to_h).to eq(expected_to_h)
    end
  end

  context "#delete" do
    it "should delete the specified case-insensitive key" do
      expect(subject.delete("foo")).to eq "bar"
      expect(subject.delete("Fizz")).to eq "buzz"
    end
  end
end

RSpec.describe Msf::DataStore do
  describe "#import_option" do
    subject do
      s = described_class.new
      s.import_option("foo", "bar")
      s.import_option("fizz", "buzz")
      s
    end
    it_behaves_like "datastore"
  end

  describe "#import_options_from_hash" do
    subject do
      hash = { "foo" => "bar", "fizz" => "buzz" }
      s = described_class.new
      s.import_options_from_hash(hash)
      s
    end
    it_behaves_like "datastore"
  end

  describe "#import_options_from_s" do
    subject do
      str = "foo=bar fizz=buzz"
      s = described_class.new
      s.import_options_from_s(str)
      s
    end
    it_behaves_like "datastore"
  end

  describe "#from_file" do
    subject do
      ini_instance = double group?: true,
                            :[] => {
                              "foo" => "bar",
                              "fizz" => "buzz"
                            }
      ini_class = double from_file: ini_instance

      stub_const("Rex::Parser::Ini", ini_class)

      s = described_class.new
      s.from_file("path")
      s
    end

    it_behaves_like "datastore"
  end

  context 'when importing options with aliases' do
    subject do
      s = described_class.new
      s.import_option("foo", "bar")
      s.import_option("fizz", "buzz")

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

    describe '#[]' do
      it 'should have default options' do
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

    it_behaves_like "datastore",
                    expected_to_h: { 'NewOptionName' => 'default_value', "foo" => "bar", "fizz" => "buzz" }
  end
end
