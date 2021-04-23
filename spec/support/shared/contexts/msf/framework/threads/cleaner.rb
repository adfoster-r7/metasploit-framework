RSpec.shared_context 'Msf::Framework#threads cleaner' do
  after(:example) do |example|
    # unless framework.threads?
    #   fail RuntimeError.new(
    #            "framework.threads was never initialized. There are no threads to clean up. " \
    #            "Remove `include_context Msf::Framework#threads cleaner` from context around " \
    #            "'#{example.full_description}'"
    #        )
    # end

    # explicitly kill threads so that they don't exhaust connection pool
    thread_manager = framework.threads

    thread_manager.each do |thread|
      begin
        thread.kill
        # ensure killed thread is cleaned up by VM
        thread.join
      rescue => e
        $stderr.puts "Thread manager had a thread that was dead #{e.inspect}"
      end
    end

    thread_manager.monitor.kill
    # ensure killed thread is cleaned up by VM
    thread_manager.monitor.join
  end
end
