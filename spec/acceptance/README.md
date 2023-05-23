## Acceptance Tests

A slower test suite that ensures high level functionality works as expected,
such as verifying msfconsole opens successfully, and can generate Meterpreter payloads,
create handlers, etc.

### Examples

Running Meterpreter test suite:

```
SPEC_OPTS='--tag acceptance' bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

Skip loading of Rails/Metasplotit with:

```
SPEC_OPTS='--tag acceptance' SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec ./spec/acceptance
```

Run only the PHP Meterpreter test suite on Unix / Windows:
```
SPEC_OPTS='--tag acceptance' METERPRETER=php bundle exec rspec './spec/acceptance/meterpreter_spec.rb'

$env:SPEC_OPTS='--tag acceptance'; $env:METERPRETER = 'php'; bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

Generate allure reports locally:

```
# 1) Run the test suite with the allure formatter
bundle exec rspec --format documentation --format AllureRspec::RSpecFormatter './spec/acceptance/meterpreter_spec.rb'

# 2) Generate allure report
cd metasploit-framework/tmp
docker run -it -w $(pwd) -v $(pwd):$(pwd) ubuntu:20.04 /bin/bash

# In the container
export VERSION=2.17.2

apt update
apt install -y curl openjdk-11-jdk-headless

curl -o allure-$VERSION.tgz -Ls https://github.com/allure-framework/allure2/releases/download/$VERSION/allure-$VERSION.tgz
tar -zxvf allure-$VERSION.tgz -C .

./allure-$VERSION/bin/allure generate --clean allure-raw-data/ -o ./allure-report

# Serve the assets from the host machine, available at http://127.0.0.1:8000
cd allure-report
ruby -run -e httpd . -p 9090
```

### Debugging

If a test has failed you can enter into an interactive breakpoint with:
```
require 'pry'; binding.pry
```

To interact with a console instance, forwarding the current stdin to the console's stdin,
and writing the console's output to stdout:

```
console.interact
```

Once inside the console, the following 'commands' can be used within the context of
the interactive msfconsole:

- `!continue` - Continue, similar to Pry's continue functionality
- `!exit` - Exit the Ruby process entirely, similar to Pry's exit functionality
