# msf-json-rpc.ru
# Start using thin:
# thin --rackup msf-json-rpc.ru --address localhost --port 8081 --environment development --tag msf-json-rpc start
#

require 'pathname'
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

class LoggingMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    req = Rack::Request.new(env)
    request_body = req.body.read
    req.body.rewind

    $stderr.puts "Request: #{request_body}"
    response_status, response_headers, response_body = @app.call(env)
    $stderr.puts "Response (Status code #{response_status}): #{response_body}"
    [response_status, response_headers, response_body]
  end
end

use LoggingMiddleware
run Msf::WebServices::JsonRpcApp
