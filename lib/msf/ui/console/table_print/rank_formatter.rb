# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      module TablePrint
        class RankFormatter

          def format(rank, _index, _row)
            if (rank.respond_to? :to_i) && (Msf::RankingName.key?(rank.to_i))
              Msf::RankingName[rank.to_i]
            else
              rank
            end
          end
        end
      end
    end
  end
end
