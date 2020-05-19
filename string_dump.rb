require 'json'

puts "Reading file"
dump = File.read(ARGV[0]); nil

puts "Parsing JSON"
json_doc = dump.lines.flat_map { |line| JSON.parse(line) }; nil

# require 'pry'; binding.pry

puts "Computing allocations"
allocations = json_doc.lazy.map { |obj| obj["type"] }.tally.sort_by { |k, v| -v }
puts "Allocations"
puts "-----------"
pp allocations

puts "Computing address lookup"
json_lookup = json_doc.each_with_object({}) { |obj, hash| hash[obj['address']] = obj }

puts "Computing top_strings"
top_strings = json_doc.lazy.select { |obj| obj["type"] == 'STRING' }.map { |obj| obj["value"] }.tally.sort_by { |k, v| -v }.take(100)
puts "top_strings"
puts "-----------"
pp top_strings


string_references_tally = json_doc.select { |obj| obj["type"] == "STRING" && obj["value"] == nil }.flat_map { |obj| obj["references"] }.tally
top_referenced_strings = string_references_tally.sort_by { |k, v| -v }.take(30).map { |k, v| [k, v, json_lookup[k]['value']] }
puts "top_referenced_strings"
puts "-----------"
pp top_referenced_strings

require 'pry'; binding.pry
puts "Finished"