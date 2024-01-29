require 'reline'

module SqlPrompt
  class Lexer
    module Literals
      LCURLY = '{'
      RCURLY = '}'
      LPAREN = '('
      RPAREN = ')'
      LBRACKET = '['
      RBRACKET = ']'
      SEMICOLON = ';'
    end
    include Literals

    WHITESPACE = %r{ [, \c\r\n\t]+ }x

    PUNCTUATION = Regexp.union(Literals.constants.map { |name|
      Literals.const_get(name)
    })

    PUNCTUATION_TABLE = Literals.constants.each_with_object({}) { |x, o|
      o[Literals.const_get(x)] = x
    }

    # @param [String] string The sql string value to lex
    def initialize(string)
      @string = string
      @scan = StringScanner.new(@string)
    end

    def next_token
      return if @scan.eos?

      case
      when s = @scan.scan(WHITESPACE) then [:WHITESPACE, s]
      when s = @scan.scan(PUNCTUATION) then [PUNCTUATION_TABLE[s], s]
      else
        [:UNKNOWN, @scan.getch]
      end
    end
  end

  class Parser
    # @param [String] string The sql string value to parse
    def initialize(string)
      @string = string
      @lexer = Lexer.new(string)
      @parsed = false
      @stack = []
    end

    def parse
      parse!

      token_pairs = {
        :LPAREN => :RPAREN,
        :LCURLY => :RCURLY,
        :LBRACKET => :RBRACKET
      }
      expected_token_type = token_pairs[@stack[-1]] || :SEMICOLON
      expected_token = { type: expected_token_type, lexeme: Lexer::PUNCTUATION_TABLE.invert[expected_token_type] }
      {
        string: @string,
        expected_token: expected_token,
        stack: @stack,
        end_of_expression?: @stack[-1] == :SEMICOLON
      }
    end

    private

    def parse!
      return if @parsed

      loop do
        next_token = @lexer.next_token
        break if next_token.nil?

        token_type, _lexeme = next_token
        if Lexer::PUNCTUATION_TABLE.value?(token_type)
          @stack.push(token_type)
        end
      end
      @parsed = true
    end
  end
end

require 'spec_helper'

RSpec.describe SqlPrompt::Lexer do
  describe '#next_token' do
    [
      { value: "{", expected: [ :LCURLY, '{' ] },
      { value: "}", expected: [ :RCURLY, '}'] },
      { value: "(", expected: [ :LPAREN, '(' ] },
      { value: ")", expected: [ :RPAREN, ')' ] },
      { value: "[", expected: [ :LBRACKET, '[' ] },
      { value: "]", expected: [ :RBRACKET, ']' ]  },
      { value: ";", expected: [ :SEMICOLON, ';' ] },
      { value: " ", expected: [ :WHITESPACE, ' ' ] },
      { value: 'f', expected: [ :UNKNOWN, 'f'] }
    ].each do |test|
      it "parses #{test[:value].inspect} as #{test[:expected]}" do
        expect(described_class.new(test[:value]).next_token).to eq(test[:expected])
      end
    end
  end
end

RSpec.describe SqlPrompt::Parser do

  describe '#parse' do
    [
      # { value: "", expected: { expected_token: nil, end_of_expression?: false } },
      # { value: "  ", expected: { expected_token: nil, end_of_expression?: false } },
      # { value: "select ", expected: { expected_token: nil, end_of_expression?: false } },
      # { value: "select *\nfrom table\nwhere foo = 123\n", expected: { expected_token: nil, end_of_expression?: false } },
      # { value: "select *\nfrom table\nwhere foo = 123\n;", expected: { expected_token: nil, end_of_expression?: true } },
    ].each do |test|
      it "when the value is #{test[:value].inspect} the result is #{test[:expected]}" do
        expect(described_class.new(test[:value]).parse).to eq(test[:expected])
      end
    end
  end
end

use_history = true
loop do
  ::Reline.prompt_proc = proc do |line_buffer|
    # parse_result = SqlPrompt::Parser.new(line_buffer.join).parse
    # prompt_multiline_indicator = '*'
    # if parse_result[:expected_token]
    #   # && parse_result[:expected_token] != :SEMICOLON
    #   # prompt_multiline_indicator = parse_result[:expected_token][:lexeme]
    #   prompt_multiline_indicator = '?'
    # end
    prompt_multiline_indicator = '?'
    line_buffer.each_with_index.map { |_line, i| i > 0 ? "SQL #{prompt_multiline_indicator}> " : 'SQL >> ' }
  end

  text = Reline.readmultiline('sql >> ', use_history) do |multiline_input|
    next true if multiline_input.blank?

    # Accept the input until an end of expression is reached
    parse_result = SqlPrompt::Parser.new(multiline_input).parse
    # $stdout.puts parse_result
    parse_result[:end_of_expression?]
  end

  puts "User input:: #{text.inspect}"
  break if text&.strip == 'quit' || text&.strip == 'exit'
end


=begin

Only edgecase I can think of that a naive rstrip.end_with?(':") can't solve:

1)
postgres=# select ";
postgres"# ";

2)

# a stray 'help' should override things? Postgres handles the individual line in its own way

> select * from
> help

postgres-# select * from
postgres-# help
Use \? for help or press control-C to clear the input buffer.
postgres-# ;
ERROR:  syntax error at or near "select"
LINE 4: select * from
        ^
Maybe a naive approach without reline could work

=end
