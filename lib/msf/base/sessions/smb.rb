# -*- coding: binary -*-

require 'rex/post/smb'

class Msf::Sessions::SMB # < Msf::Sessions::CommandShell
  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  # @return [Rex::Post::SMB::Ui::Console] The interactive console
  attr_accessor :console
  # @return [RubySMB::Client] The SMB client
  attr_accessor :client
  attr_accessor :platform
  attr_accessor :arch

  # TODO: Confirm existig terminology, smb_client vs client vs dispatcher vs something else
  # @param [RubySMB::Client] client
  def initialize(rstream, opts={})
    @client = opts.fetch(:client)
    # @info = "SMB TODO"
    self.console = Rex::Post::SMB::Ui::Console.new(self)
    super(rstream, opts)
  end

  def bootstrap(datastore = {}, handler = nil)
    # this won't work after the rstream is initialized, so do it first
    # @platform = 'windows' # Metasploit::Framework::Ssh::Platform.get_platform(ssh_connection)
    # super

    session = self
    session.init_ui(self.user_input, self.user_output)

    @info = "SMB #{datastore['USERNAME']} @ #{@peer_info}"
  end

  def process_autoruns(datastore)
    # TODO - Implemented for now to keep things happy
  end

  def type
    self.class.type
  end

  # Returns the type of session.
  #
  def self.type
    'SMB'
  end

  def self.can_cleanup_files
    false
  end

  #
  # Returns the session description.
  #
  def desc
    'SMB'
  end

  protected

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

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  def _interact
    framework.events.on_session_interact(self)
    Rex::Ui::Text::Shell::HistoryManager.with_context(name: self.type.to_sym) {
      _interact_stream
    }
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  def _interact_stream
    framework.events.on_session_interact(self)

    console.framework = framework
    # if framework.datastore['MeterpreterPrompt']
    #   console.update_prompt(framework.datastore['MeterpreterPrompt'])
    # end
    # Call the console interaction of the smb client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    console.interact { self.interacting != true }
    console.framework = nil

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise EOFError if (console.stopped? == true)
  end

end
