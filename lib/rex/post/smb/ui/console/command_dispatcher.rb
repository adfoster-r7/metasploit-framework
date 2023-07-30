# -*- coding: binary -*-

require 'rex/ui/text/dispatcher_shell'

module Rex
module Post
module SMB
module Ui

###
#
# Base class for all command dispatchers within the SMB console user
# interface.
#
###
module Console::CommandDispatcher

  include Rex::Ui::Text::DispatcherShell::CommandDispatcher

  #
  # The hash of file names to class names after a module has already been
  # loaded once on the client side.
  #
  # @@file_hash = {}
  #
  # #
  # # Checks the file name to hash association to see if the module being
  # # requested has already been loaded once.
  # #
  # def self.check_hash(name)
  #   @@file_hash[name]
  # end
  #
  # #
  # # Sets the file path to class name association for future reference.
  # #
  # def self.set_hash(name, klass)
  #   @@file_hash[name] = klass
  # end

  #
  # Initializes an instance of the core command set using the supplied session and client
  # for interactivity.
  #
  # @param [Rex::Post::SMB::Ui::Console] console
  def initialize(console)
    super
    @msf_loaded = nil
    @filtered_commands = []
  end

  #
  # Returns the smb client context.
  #
  # @return [RubySMB::Client]
  def client
    console = shell
    console.client
  end

  #
  # Returns the smb session context.
  #
  # @return [Msf::Sessions::SMB]
  def session
    console = shell
    console.session
  end

  # TODO: Rename - required for most of RubySMB's APIs, i.e. "path = "\\\\#{address}\\share"
  def address
    # TOOD: How do we accurately get the target smb address when pivoting? Also Needs ipv6 support
    address, port = client.dispatcher.tcp_socket.peerinfo.split(':')
    address
  end

  #
  # Returns the active share
  #
  # TODO Add smb1 share data type
  # @return [RubySMB::SMB2::Tree]
  def active_share
    console = shell
    console.active_share
  end

  #
  # Returns the commands that meet the requirements
  #
  def filter_commands(all, reqs)
    all.delete_if do |cmd, _desc|
      if reqs[cmd]&.any? { |req| !client.commands.include?(req) }
        @filtered_commands << cmd
        true
      end
    end
  end

  def unknown_command(cmd, line)
    if @filtered_commands.include?(cmd)
      print_error("The \"#{cmd}\" command is not supported by this session type (#{client.session_type})")
      return :handled
    end

    super
  end

  #
  # Return the subdir of the `documentation/` directory that should be used
  # to find usage documentation
  #
  def docs_dir
    File.join(super, 'meterpreter')
  end

  #
  # Returns true if the client has a framework object.
  #
  # Used for firing framework session events
  #
  def msf_loaded?
    return @msf_loaded unless @msf_loaded.nil?
    # if we get here we must not have initialized yet

    @msf_loaded = !!(client.framework)
    @msf_loaded
  end

  #
  # Log that an error occurred.
  #
  def log_error(msg)
    print_error(msg)

    elog(msg, 'smb')

    dlog("Call stack:\n#{$@.join("\n")}", 'smb')
  end

end

end
end
end
end
