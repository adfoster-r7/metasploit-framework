# msf-json-rpc.ru
# Start using thin:
# thin --rackup msf-json-rpc.ru --address localhost --port 8081 --environment development --tag msf-json-rpc start
#

require 'pathname'
require 'rbtrace'

class Object
  def run_dump
    dump_location = "/tmp/ruby-heap-#{Time.now.to_i}.dump"
    Thread.new do
      GC.start
      require "objspace"
      ObjectSpace.trace_object_allocations_start
      io = File.open(dump_location, "w")
      ObjectSpace.dump_all(output: io)
      io.close

      dump_location
    end
    "Kicked off, #{dump_location}"
  end
end

@framework_path = '.'
root = Pathname.new(@framework_path).expand_path
@framework_lib_path = root.join('lib')
$LOAD_PATH << @framework_lib_path unless $LOAD_PATH.include?(@framework_lib_path)

require 'msfenv'

if ENV['MSF_LOCAL_LIB']
  $LOAD_PATH << ENV['MSF_LOCAL_LIB'] unless $LOAD_PATH.include?(ENV['MSF_LOCAL_LIB'])
end

# Note: setup Rails environment before calling require
require 'msf/core/web_services/json_rpc_app'

run Msf::WebServices::JsonRpcApp
