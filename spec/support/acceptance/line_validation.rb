module Acceptance
  ###
  # A utility object representing the validation of a a line of output generated
  # by the acceptance test suite.
  ###
  class LineValidation
    # @param [string|Array<String>] values A line string, or array of lines
    # @param [Object] options Additional options for configuring this failure, i.e. if it's a known flaky test result etc.
    def initialize(values, options = {})
      @values = Array(values)
      @options = options
    end

    def flatten
      @values.map { |value| self.class.new(value, @options) }
    end

    def value
      raise StandardError, 'More than one value present' if @values.length > 1

      @values[0]
    end

    # @return [boolean] returns true if the current failure applies under the current environment or the result is flaky, false otherwise.
    # @param [Hash] environment The current execution environment
    # @return [TrueClass, FalseClass] True if the line is flaky - and may not always be present, false otherwise
    def flaky?(environment = {})
      value = @options.fetch(:flaky, false)

      evaluate_predicate(value, environment)
    rescue => e
      require 'pry-byebug'; binding.pry
    end

    # @return [boolean] returns true if the current failure applies under the current environment or the result is flaky, false otherwise.
    # @param [Hash] environment
    # @return [TrueClass, FalseClass] True if the line should be considered valid, false otherwise
    def if?(environment = {})
      value = @options.fetch(:if, true)
      evaluate_predicate(value, environment)
    end

    private

    # Evaluates a simple predicate; Similar to Msf::OptCondition.eval_condition
    # @param [TrueClass,FalseClass,Array] value
    # @param [Hash] environment
    # @return [TrueClass, FalseClass] True or false
    def evaluate_predicate(value, environment)
      case value
      when Array
        left_operand, operator, right_operand = value
        # Map values such as `:meterpreter_name` to the runtime value
        left_operand = environment[left_operand] if environment.key?(left_operand)
        right_operand = environment[right_operand] if environment.key?(right_operand)

        case operator.to_sym
        when :==
          evaluate_predicate(left_operand, environment) == evaluate_predicate(right_operand, environment)
        when :!=
          evaluate_predicate(left_operand, environment) != evaluate_predicate(right_operand, environment)
        when :or
          evaluate_predicate(left_operand, environment) != evaluate_predicate(right_operand, environment)
        else
          raise "unexpected operator #{operator.inspect}"
        end
      else
        value
      end
    end
  end
end
