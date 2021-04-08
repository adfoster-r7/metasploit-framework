require 'rubygems'
require 'rspec/core/rake_task'

# Spec::Rake::SpecTask.new do |t|
# 	t.ruby_opts = ['-rtest/unit']
# 	t.spec_files = FileList['*_test.rb']
# end

RSpec::Core::RakeTask.new do |t|
	# t.rspec_opts = ["-c", "-f progress", "-r ./spec/spec_helper.rb"]
	t.pattern = 'spec/**/*_test.rb'
end
