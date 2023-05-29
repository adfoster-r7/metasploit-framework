require_relative 'spec/support/acceptance/child_process.rb'
require_relative 'spec/support/acceptance/countdown.rb'

process = Acceptance::PayloadProcess.new(
  ['/bin/bash', '-c', 'echo whoami'],
  {
    out: File.open('./test_output.txt', 'w+')
  }
)

require 'pry-byebug'; binding.pry

process.run

puts 123
