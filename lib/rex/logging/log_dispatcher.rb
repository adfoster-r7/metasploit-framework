# -*- coding: binary -*-
require 'rex/sync'
require 'rex/logging/log_sink'

module Rex
module Logging

###
#
# The log dispatcher associates log sources with log sinks.  A log source
# is a unique identity that is associated with one and only one log sink.
# For instance, the framework-core registers the 'core'
#
###
class LogDispatcher

  #
  # Creates the global log dispatcher instance and initializes it for use.
  #
  def initialize()
    self.log_sinks      = {}
    self.log_levels     = {}
    self.log_sinks_lock = Mutex.new
  end

  #
  # Returns the sink that is associated with the supplied source.
  #
  def [](src)
    sink = nil

    log_sinks_lock.synchronize {
      sink = log_sinks[src]
    }

    return sink
  end

  #
  # Calls the source association routie.
  #
  def []=(src, sink)
    store(src, sink)
  end

  #
  # Associates the supplied source with the supplied sink.  If a log level
  # has already been defined for the source, the level argument is ignored.
  # Use set_log_level to alter it.
  #
  def store(src, sink, level = 0)
    log_sinks_lock.synchronize {
      if (log_sinks[src] == nil)
        log_sinks[src] = sink

        set_log_level(src, level) if (log_levels[src] == nil)
      else
        raise(
          RuntimeError,
          "The supplied log source #{src} is already registered.",
          caller)
      end
    }
  end

  #
  # Removes a source association if one exists.
  #
  def delete(src)
    sink = nil

    log_sinks_lock.synchronize {
      sink = log_sinks[src]

      log_sinks.delete(src)
    }

    if (sink)
      sink.cleanup

      return true
    end

    return false
  end

  #
  # Performs the actual log operation against the supplied source
  #
  def log(sev, src, level, msg)
    log_sinks_lock.synchronize {
      if ((sink = log_sinks[src]))
        next if (log_levels[src] and level > log_levels[src])

        sink.log(sev, src, level, msg)
      end
    }
  end

  #
  # This method sets the log level threshold for a given source.
  #
  def set_level(src, level)
    log_levels[src] = level.to_i
  end

  #
  # This method returns the log level threshold of a given source.
  #
  def get_level(src)
    log_levels[src]
  end

  attr_accessor :log_sinks, :log_sinks_lock # :nodoc:
  attr_accessor :log_levels # :nodoc:
end

end
end

###
#
# An instance of the log dispatcher exists in the global namespace, along
# with stubs for many of the common logging methods.  Various sources can
# register themselves as a log sink such that logs can be directed at
# various targets depending on where they're sourced from.  By doing it
# this way, things like sessions can use the global logging stubs and
# still be directed at the correct log file.
#
###
ExceptionCallStack = "__EXCEPTCALLSTACK__"

def dlog(msg, src = 'core', level = 0)
  $dispatcher.log(LOG_DEBUG, src, level, msg)
end

# Logs errors in a standard format for each Log Level.
#
# @param msg [String] Contains message from the developer explaining why an error was encountered. Log Levels 0-3.
#
# @param src [String] Used to indicate where the error is originating from. Most commonly set to 'core' to ensure logs
# are place in 'framework.log'.
#
# @param error [Exception] Exception of an error that needs to be logged. Mandatory in Log Levels 1-2. Optional in Log Level 3.
#
# (Eg Loop Iterations, Variables, Function Calls).
#
# @return [NilClass].
def elog(msg='', src='core', log_level: 0, error: nil)
  if error.nil?
    $dispatcher.log(LOG_ERROR, src, get_log_level(src), msg)
    return
  else

    global_log_level = get_log_level(src)

    # If the source has no associated log_level, the default log level is used
    unless global_log_level
      global_log_level = LEV_3
    end

    if log_level <= global_log_level
      error_details = "#{error.class} #{error.message}"
      if global_log_level >= LEV_3
        error_details << "\nCall stack:\n#{error.backtrace.join("\n")}"
      end
    end

    dispatcher_msg = msg.empty? ? "#{error_details}" : "#{msg} - #{error_details}"

    $dispatcher.log(LOG_ERROR, src, get_log_level(src), dispatcher_msg)
  end
end

def wlog(msg, src = 'core', level = 0)
  $dispatcher.log(LOG_WARN, src, level, msg)
end

def ilog(msg, src = 'core', level = 0)
  $dispatcher.log(LOG_INFO, src, level, msg)
end

def rlog(msg, src = 'core', level = 0)
  $dispatcher.log(LOG_RAW, src, level, msg)
end

def log_source_registered?(src)
  ($dispatcher[src] != nil)
end

def register_log_source(src, sink, level = nil)
  $dispatcher[src] = sink

  set_log_level(src, level) if (level)
end

def deregister_log_source(src)
  $dispatcher.delete(src)
end

def set_log_level(src, level)
  $dispatcher.set_level(src, level)
end

def get_log_level(src)
  $dispatcher.get_level(src)
end

# Creates the global log dispatcher
$dispatcher = Rex::Logging::LogDispatcher.new
