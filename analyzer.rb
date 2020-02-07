require 'json'
class Analyzer
  def initialize(filename)
    @filename = filename
  end

  def analyze
    data = []
    File.open(@filename) do |f|
        f.each_line do |line|
          data << (parsed=JSON.parse(line))
        end
    end

    data.group_by{|row| row["generation"]}
        .sort{|a,b| a[0].to_i <=> b[0].to_i}
        .each do |k,v|
          puts "generation #{k} objects #{v.count}"
        end
  end
end

Analyzer.new(ARGV[0]).analyze
