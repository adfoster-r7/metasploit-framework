require 'time'

count = 0
log = File.open("./my_script.log.txt", "w")

begin
  loop do
    puts "hello world #{count}"
    log.seek(0)
    log.puts(count.to_s + "\n")
    log.flush
    count += 1
  end
rescue => e
  log.puts "#{e.message}"
end

log.close
