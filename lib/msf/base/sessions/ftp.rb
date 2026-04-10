# -*- coding: binary -*-

require 'rex/post/ftp'

class Msf::Sessions::FTP
  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic
  include Msf::Sessions::Scriptable

  # @return [Rex::Post::FTP::Ui::Console] The interactive console
  attr_accessor :console
  # @return [Rex::Proto::FTP::Client] The FTP client
  attr_accessor :client
  attr_accessor :keep_alive_thread
  # @return [Integer] Seconds between keepalive NOOP commands
  attr_accessor :keepalive_seconds
  attr_accessor :platform, :arch
  attr_reader :framework

  # @param[Rex::IO::Stream] rstream
  # @param [Hash] opts
  # @option opts [Rex::Proto::FTP::Client] :client
  # @option opts [Integer] :keepalive_seconds (60) Seconds between keepalive NOOPs
  def initialize(rstream, opts = {})
    @client = opts.fetch(:client)
    @keepalive_seconds = opts.fetch(:keepalive_seconds, 60)
    self.console = Rex::Post::FTP::Ui::Console.new(self)
    super(rstream, opts)
  end

  def cleanup
    stop_keep_alive_loop
    super
  end

  def bootstrap(datastore = {}, handler = nil)
    session = self
    session.init_ui(user_input, user_output)

    @info = "FTP #{datastore['USERNAME']} @ #{@peer_info}"
  end

  def execute_file(full_path, args)
    if File.extname(full_path) == '.rb'
      Rex::Script::Shell.new(self, full_path).run(args)
    else
      console.load_resource(full_path)
    end
  end

  def process_autoruns(datastore)
    ['InitialAutoRunScript', 'AutoRunScript'].each do |key|
      next if datastore[key].nil? || datastore[key].empty?

      args = Shellwords.shellwords(datastore[key])
      print_status("Session ID #{sid} (#{tunnel_to_s}) processing #{key} '#{datastore[key]}'")
      execute_script(args.shift, *args)
    end
  end

  def type
    self.class.type
  end

  # Returns the type of session.
  #
  def self.type
    'ftp'
  end

  def self.can_cleanup_files
    false
  end

  #
  # Returns the session description.
  #
  def desc
    'FTP'
  end

  def address
    @address ||= client.peerhost
  end

  def port
    @port ||= client.peerport
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Initializes the console's I/O handles.
  #
  def init_ui(input, output)
    self.user_input = input
    self.user_output = output
    console.init_ui(input, output)
    console.set_log_source(log_source)

    super
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Resets the console's I/O handles.
  #
  def reset_ui
    console.unset_log_source
    console.reset_ui
  end

  def exit
    console.stop
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  def _interact
    framework.events.on_session_interact(self)
    framework.history_manager.with_context(name: type.to_sym) do
      _interact_stream
    end
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  def _interact_stream
    framework.events.on_session_interact(self)

    console.framework = framework
    # Call the console interaction of the FTP client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    console.interact { interacting != true }
    console.framework = nil

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise EOFError if (console.stopped? == true)
  end

  def on_registered
    start_keep_alive_loop
  end

  # Start a background thread that sends NOOP to keep the FTP connection alive
  def start_keep_alive_loop
    self.keep_alive_thread = framework.threads.spawn("FTP-session-keepalive-#{sid}", false) do
      loop do
        remaining_sleep = if client.last_interaction.nil?
                            @keepalive_seconds
                          else
                            @keepalive_seconds - (Process.clock_gettime(Process::CLOCK_MONOTONIC) - client.last_interaction)
                          end
        sleep([remaining_sleep, 1].max)
        if (Process.clock_gettime(Process::CLOCK_MONOTONIC) - client.last_interaction) >= @keepalive_seconds
          client.send_cmd(['NOOP'])
        end
      end
    rescue ::StandardError
      # Session is dead, let it go
    end
  end

  # Stop the keepalive background thread
  def stop_keep_alive_loop
    keep_alive_thread&.kill
  end
end
