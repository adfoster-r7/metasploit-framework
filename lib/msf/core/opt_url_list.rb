# -*- coding: binary -*-

module Msf

###
#
# URL list option.
#
###
  class OptUrlList < OptBase
    def type
      return 'addressrange'
    end

    def validate_on_assignment?
      false
    end

    def normalize(value)
      return nil unless value.kind_of?(String)
      # accept both "file://<path>" and "file:<path>" syntax
      if (value =~ /^file:\/\/(.*)/) || (value =~ /^file:(.*)/)
        path = $1
        return false if not File.exist?(path) or File.directory?(path)
        return File.readlines(path).map{ |s| s.strip}.join(" ")
      end
      return value
    end

    def valid?(value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      return false unless value.kind_of?(String) or value.kind_of?(NilClass)

      # todo: validate that each one parses properly as a url

      return super
    end
  end

end
