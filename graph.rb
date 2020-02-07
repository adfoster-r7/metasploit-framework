#!/usr/bin/env ruby
require 'date'
require 'yaml'
require 'gnuplot'
require_relative 'db'


### Parse arguments

type = ARGV[0]
type == 'type' and type = 'type-mem'

case type
when 'type-count'
  ylabel = 'count'
  query, ycolumn, group = nil, 'COUNT(id)', :type
  key_pos = 'left top'
when 'type-mem'
  query, ycolumn, group = nil, 'SUM(memsize)', :type
  ylabel, yscale = 'memsize [MB]', 1024*1024
  key_pos = 'left top'
when 'string-count'
  ylabel = 'count'
  query, ycolumn, group = {type: 'STRING'}, 'COUNT(id)', :file
when 'string-mem'
  query, ycolumn, group = {type: 'STRING'}, 'SUM(memsize)', :file
  ylabel, yscale = 'memsize [MB]', 1024*1024
when 'data-count'
  ylabel = 'count'
  query, ycolumn, group = {type: 'DATA'}, 'COUNT(id)', :file
when 'data-mem'
  query, ycolumn, group = {type: 'DATA'}, 'SUM(memsize)', :file
  ylabel, yscale = 'memsize [MB]', 1024*1024
else
  STDERR.puts "Usage: graph <type>"
  exit 1
end

xoffset = 60*60 # GMT+1
graph_basename = File.dirname(File.expand_path(__FILE__)) + '/graph-' + type


### Read cache or execute query

if File.exists?(graph_basename + '.yml')
  data = YAML.load(File.read(graph_basename + '.yml'))
else
  scope = SpaceObject
  scope = scope.where(**query) if query
  scope = scope.order(ycolumn + ' DESC NULLS LAST')
  scope = scope.group(:time, group)
  data = scope.limit(500).pluck(group, :time, ycolumn)
  File.open(graph_basename + '.yml', 'w') do |f|
    f.write(data.to_yaml)
  end
end


### Then plot

Gnuplot.open(persist: true) do |gp|
  Gnuplot::Plot.new(gp) do |plot|
    plot.terminal 'png large'
    plot.output graph_basename + '.png'

    plot.xdata :time
    plot.timefmt '"%s"'
    plot.format 'x "%H:%M"'

    plot.xlabel "time"
    plot.ylabel ylabel
    plot.key key_pos if key_pos

    grouped_data = data.group_by(&:first)
    keys = grouped_data.keys.sort_by {|key| -grouped_data[key].reduce(0) {|sum,d| sum + (d[2]||0) } }
    keys[0,10].each do |key|
      data = grouped_data[key]
      data.sort_by!{|d| d[1] }
      x = data.map{|d| d[1].to_i + (xoffset||0) }
      y = data.map{|d| d[2] }
      y = data.map{|d| (d[2]||0) / (yscale||1) }
      plot.data << Gnuplot::DataSet.new( [x, y]  ) do |ds|
        ds.using = '1:2'
        ds.with = "linespoints"
        ds.title = key || '(empty)'
      end
    end

  end
end
