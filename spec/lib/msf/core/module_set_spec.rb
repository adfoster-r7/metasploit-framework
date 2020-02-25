require 'spec_helper'

RSpec.describe Msf::ModuleSet do
  subject(:module_set) do
    described_class.new(module_type)
  end

  let(:module_type) do
    FactoryBot.generate :mdm_module_detail_mtype
  end

  context '#rank_modules' do
    subject(:rank_modules) do
      module_set.send(:rank_modules)
    end

    context 'with Msf::SymbolicModule' do
      before(:example) do
        module_set['a'] = Msf::SymbolicModule
        module_set['b'] = Msf::SymbolicModule
        module_set['c'] = Msf::SymbolicModule
      end

      context 'create' do
        #
        # lets
        #

        let(:b_class) do
          Class.new
        end

        let(:c_class) do
          Class.new
        end

        context 'returns nil' do
          before(:example) do
            hide_const('A::Rank')
            allow(module_set).to receive(:create).with('a').and_return(nil)

            stub_const('B', b_class)
            stub_const('B::Rank', Msf::LowRanking)
            allow(module_set).to receive(:create).with('b').and_return(b_class.new)

            stub_const('C', c_class)
            stub_const('C::Rank', Msf::AverageRanking)
            allow(module_set).to receive(:create).with('c').and_return(c_class.new)
          end

          specify do
            expect do
              rank_modules
            end.not_to raise_error
          end

          it 'is ranked as Manual' do
            expect(rank_modules).to eq(
              [
                ['c', Msf::SymbolicModule],
                ['b', Msf::SymbolicModule],
                ['a', Msf::SymbolicModule]
              ]
            )
          end
        end

        context 'does not return nil' do
          #
          # lets
          #

          let(:a_class) do
            Class.new
          end

          #
          # Callbacks
          #

          before(:example) do
            allow(module_set).to receive(:create).with('a').and_return(a_class.new)
            allow(module_set).to receive(:create).with('b').and_return(b_class.new)
            allow(module_set).to receive(:create).with('c').and_return(c_class.new)
          end

          context 'with Rank' do
            before(:example) do
              stub_const('A', a_class)
              stub_const('A::Rank', Msf::LowRanking)

              stub_const('B', b_class)
              stub_const('B::Rank', Msf::AverageRanking)

              stub_const('C', c_class)
              stub_const('C::Rank', Msf::GoodRanking)
            end

            it 'is ranked using Rank' do
              expect(rank_modules).to eq(
                [
                  ['c', Msf::SymbolicModule],
                  ['b', Msf::SymbolicModule],
                  ['a', Msf::SymbolicModule]
                ]
              )
            end
          end

          context 'without Rank' do
            before(:example) do
              stub_const('A', a_class)
              hide_const('A::Rank')

              stub_const('B', b_class)
              stub_const('B::Rank', Msf::AverageRanking)

              stub_const('C', c_class)
              stub_const('C::Rank', Msf::GoodRanking)
            end

            it 'is ranked as Normal' do
              expect(rank_modules).to eq(
                [
                  ['c', Msf::SymbolicModule],
                  ['a', Msf::SymbolicModule],
                  ['b', Msf::SymbolicModule]
                ]
              )
            end
          end
        end
      end
    end

    context 'without Msf::SymbolicModule' do
      #
      # lets
      #

      let(:a_class) do
        Class.new
      end

      let(:b_class) do
        Class.new
      end

      let(:c_class) do
        Class.new
      end

      #
      # Callbacks
      #

      before(:example) do
        module_set['a'] = a_class
        module_set['b'] = b_class
        module_set['c'] = c_class
      end

      context 'with Rank' do
        before(:example) do
          stub_const('A', a_class)
          stub_const('A::Rank', Msf::LowRanking)

          stub_const('B', b_class)
          stub_const('B::Rank', Msf::AverageRanking)

          stub_const('C', c_class)
          stub_const('C::Rank', Msf::GoodRanking)
        end

        it 'is ranked using Rank' do
          expect(rank_modules).to eq(
            [
              ['c', c_class],
              ['b', b_class],
              ['a', a_class]
            ]
          )
        end
      end

      context 'without Rank' do
        before(:example) do
          stub_const('A', a_class)
          hide_const('A::Rank')

          stub_const('B', b_class)
          stub_const('B::Rank', Msf::AverageRanking)

          stub_const('C', c_class)
          stub_const('C::Rank', Msf::GoodRanking)
        end

        it 'is ranked as Normal' do
          expect(rank_modules).to eq(
            [
              ['c', c_class],
              ['a', a_class],
              ['b', b_class]
            ]
          )
        end
      end
    end
  end
end
