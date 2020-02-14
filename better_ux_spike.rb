# TODO: Learn why metasploit doesn't use concrete error objects, and this is a string
UnexpectedReply = 'unexpected-reply'
class Failed < RuntimeError

end

class Step
  attr_reader :id
  # attr_reader :description
  attr_reader :block
  attr_accessor :status

  def initialize(id:, description:, block:, status: :pending)
    @id = id
    @description = description
    @block = block
    @status = status
  end

  def description
    @description[0].upcase + @description[1..]
  end
end

class BaseModule
  def initialize
    @dry_run = false
    # TOOD: Most likely lives else where, but i'm not sure where to get a good ID from just yet
    @steps = []
    @step_id = nil
    @step_listeners = []
  end

  def set_output(output)
    @output = output
  end

  def add_step_listener(listener)
    @step_listeners << listener
  end

  def remove_step_listener(listener)
    @step_listeners.delete(listener)
  end

  def step(description, &block)
    step = Step.new(id: @steps.size, description: description, block: block)
    @steps << Step.new(id: @steps.size, description: description, block: block)

    unless @dry_run
      on_step(step)
    end
  end

  def on_step(step)
    @step_listeners.each do |listener|
      listener.on_start_step(step)
    end

    begin
      @step_id = step.id
      step.block.call
    rescue => e
      @step_listeners.each do |listener|
        listener.on_error_step(step, e)
      end
      raise
    end

    @step_listeners.each do |listener|
      listener.on_exit_step(step)
    end
  end

  def dry_run
    @steps = []
    old_value = @dry_run
    @dry_run = true
    run
    @dry_run = old_value
  end

  def run
    raise NotImplementedError
  end

  def steps
    dry_run

    @steps
  end

  def output
    @output
  end

  def print_status(msg = '')
    output.print_status(@step_id, msg) if output
  end

  def fail_with(reason, msg)
    raise Failed, "#{reason} - #{msg}"
  end

  def datastore
     { 'target' => '192.168.0.1' }
  end
end

class KewlHaxingModule < BaseModule
  def run
    @steps = []

    step "create payload" do
      print_status "inside creation of payload"
      sleep 1
    end

    step "send payload to \e[33m#{self.datastore['target']}\e[0m" do
      print_status "inside creation of payload"
      print_status "using encoding \e[33mfoo bar baz\e[0m"
      sleep 2
    end

    step "some other useful thing" do
      print_status "doing something else that's useful"
      if rand > 0.5
        fail_with UnexpectedReply, "Connection terminated"
      end
      print_status "connected to the thing"
      sleep 1
    end

    step "shell poppin'" do
      print_status "inside the shell popping"
      sleep 1
    end
  end
end

def cursor_up(amount = 1)
  print "\e[#{amount}A"
end

def cursor_down(amount = 1)
  print "\e[#{amount}B"
end

def clear_line
  print "\e[K"
end


class ProgressIndicator
  def initialize
    @progress_indicator = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    @tick_count = 0

  end

  def next
    @tick_count += 1
    indicator_symbol = @progress_indicator[@tick_count % @progress_indicator.size]

    indicator_symbol
  end
end

class StatusLine
  def initialize
    @progress_indicator = ProgressIndicator.new
    @has_printed = false
  end

  def update
    if @has_printed
      cursor_up
    end
    puts "#{@progress_indicator.next} Running..."
    @has_printed = true
  end

  def remove
    if @has_printed
      cursor_up
    end
    puts "⏰  Job finished."
    puts
    @has_printed = true
  end
end

class CLI
  def run(mod)
    mod.set_output(self)

    @last_error = nil
    @mod = mod # required for gh_details
    @module_steps = mod.steps
    @logs = Hash.new { |hash, key| hash[key] = []  }

    @event_queue = Queue.new

    puts "Running module:"
    puts "\n"

    @module_steps.each do |step|
      puts "  o  #{step.description}"
    end

    puts "\n"

    mod.add_step_listener(self)
    @job = Thread.new do
      mod.run
    end
    @job.report_on_exception = false

    @progress_indicator = ProgressIndicator.new
    status_line = StatusLine.new
    while @job.alive?
      status_line.update
      update_status
      render_status
      sleep 0.1
    end

    update_status
    render_status
    status_line.remove
    @job.join
    puts "\e[32mh4xed successfully\e[0m"
  rescue => e
    @last_error = e
    puts "\e[31mExplosion occurred...\e[0m"
    puts "Use the \e[33mdetails\e[0m command to learn more"
  ensure
    mod.remove_step_listener(self)
    @done = false
  end

  def print_status(id, msg)
    @logs[id] << msg
  end

  def on_start_step(step)
    queue_status_event(:started, step)
  end

  def on_exit_step(step)
    queue_status_event(:success, step)
  end

  def on_error_step(step, e)
    queue_status_event(:error, step)
  end

  def queue_status_event(status, step)
    @event_queue.push({ type: 'event', status: status, step: step.clone })
  end

  def update_status
    # Update our internal state from events that the job has published
    until @event_queue.empty?
      event = @event_queue.pop(true)
      step = event[:step]
      @current_step_id = step.id
      @module_steps[step.id].status = event[:status]
    end
  end

  def render_status
    cursor_up @module_steps.size + 2
    @module_steps.each do |step|
      puts "  #{status_as_icon(step.status)}  #{step.description}"
    end
    cursor_down 2
  end

  def status_as_icon(status)
    mapping = {
        started: "⌛",
        success: "✅",
        error: "❌",
        pending: " "
    }

    mapping.fetch(status, " ")
  end

  def details
    if @module_steps.nil? || @module_steps.empty?
      log_error(@last_error)
      return
    end

    puts "\e[1;36mExploit details\e[0m"
    puts "\e[1;36m---------------\e[0m"

    @module_steps.each do |step|
      if step.status != :pending
        icon = status_as_icon(step.status)
        puts "#{icon}  #{step.description}"
        log_entries = @logs[step.id]
        if log_entries.empty?
          puts "  - No logs were output"
        end

        log_entries.each do |log|
          puts "  - #{log}"
        end
      else
        icon = "👆"
        puts "#{icon} #{step.description}"
        puts "  - this step did not run"
      end
    end

    log_error(@last_error)
  end

  # Markdown friendly generation
  def gh_details
    issue = <<~GITHUB_ISSUE
      ## Steps to reproduce

      How'd you do it?

      1. ...
      2. ...

      This section should also tell us any relevant information about the
      environment; for example, if an exploit that used to work is failing,
      tell us the victim operating system and service versions.

      ## Versions

      Console: v5.0.73-dev-15fcb5e1e4
      Ruby: #{RUBY_VERSION}
      OS: #{RUBY_PLATFORM}

      ## Module

      #{@mod.class.name}

      ## Logs

      #{
        @module_steps.map do |step|
          title = "- #{step.description} (#{step.status})"
          logs = ""
          log_entries = @logs[step.id]
          if log_entries.empty?
            logs += "  - No logs were output\n"
          end

          log_entries.map do |log|
             logs += "  - #{log}\n"
          end
              
          title + "\n" + logs
        end.join("\n")
      }

    GITHUB_ISSUE

    if @last_error.nil?
      issue += "No error occurred"
    else
      issue += <<~ERROR_DETAILS
      ## Exception

      <details>
      <summary>Trace</summary>

      ```
      \e[1mTraceback\e[0m (most recent call last):
      #{
        @last_error.backtrace.map do |line|
          "\t#{line}"
        end.join("\n")
      }

      \e[1m#{@last_error.class}\e[0m (#{@last_error.message})
      ```
      </details>
      ERROR_DETAILS
    end


    puts
    puts "vvvvvvvvvvvvvvvvvvvvvv"
    puts
    puts issue
    puts
    puts "^^^^^^^^^^^^^^^^^^^^^^"
    puts
    puts "Please raise an issue with the above output at https://github.com/rapid7/metasploit-framework/issues"
  end

  def log_error(e)
    unless e
      puts
      puts "No error occurred"
      puts
      return
    end

    puts
    puts "An error occurred when runing this job:"
    puts
    puts "\e[1mTraceback\e[0m (most recent call last):"
    e.backtrace.each do |line|
      puts "\t#{line}"
    end
    puts "\e[1m#{e.class}\e[0m (#{e.message})"
    puts
    puts "Use the \e[33mdetails -gh\e[0m command to output a github friendly version of this.\nPlease raise issues at https://github.com/rapid7/metasploit-framework/issues"
  end

  def dry_run(mod)
    mod.set_output(self)
    module_steps = mod.steps
    puts "The module steps are:"
    module_steps.each do |step|
      puts "  o  #{step.description}"
    end
    puts "Use the \e[33mrun\e[0m command execute these steps"
  end
end

mod = KewlHaxingModule.new
command = ARGV[0] || "run"
cli = CLI.new

while command != 'exit'
  # target, args = command.split(" ", 2)

  print "exploit(\e[1;31m#{mod.class.name}\e[0m) > "
  command = $stdin.gets.chomp

  case command
  when 'run'
    cli.run(mod)
  when 'dry_run'
    cli.dry_run(mod)
  when 'details'
    cli.details
  when 'details -gh'
    cli.gh_details
  when 'exit'
    return
  else
    # Try to find the command line and send the string to it
    # ENV['PATH'].split(":").each do |path|
    #   if File.exist? File.join(path, target)
    #     puts `#{File.join(path, target)} #{args}`
    #   end
    # end

    puts "invalid command: #{command.inspect}"
  end
end
# #
# #
# progress_indicator = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
# progress = 0
# has_printed_first_line = false
#
#
# while true
#   progress = (progress + 1) % progress_indicator.size
#   indicator = progress_indicator[progress]
#
#   if has_printed_first_line
#     cursor_up
#   end
#   print "#{indicator} Doing things\n"
#
#   has_printed_first_line = true
#
#   sleep 0.1
# end