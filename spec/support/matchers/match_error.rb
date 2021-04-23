RSpec::Matchers.define :match_error do |expected|
  match do |actual|
    actual.class == expected.class && actual.message == expected.message
  end

  failure_message do |actual|
    "\nexpected: #{expected.inspect}\n     got: #{actual.inspect}\n\n(compared using ==)\n"
  end

  failure_message_when_negated do |_actual|
    "\nexpected: value != #{expected.inspect}\n     got: #{actual.inspect}\n\n(compared using ==)\n"
  end

  description do
    "match_error #{expected.inspect}"
  end
end
