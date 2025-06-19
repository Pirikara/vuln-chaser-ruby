require "vuln_chaser/version"
require "vuln_chaser/config"
require "vuln_chaser/data_sanitizer"
require "vuln_chaser/execution_tracer"
require "vuln_chaser/trace_context"
require "vuln_chaser/trace_buffer"
require "vuln_chaser/async_trace_sender"
require "vuln_chaser/enhanced_middleware"
require 'rails/generators'
require 'generators/vuln_chaser/install_generator'

module VulnChaser
  class << self
    def configure
      yield(Config)
    end

    def logger
      return Rails.logger if defined?(Rails) && Rails.respond_to?(:logger)
      @logger ||= Logger.new($stdout)
    end

    def logger=(logger)
      @logger = logger
    end

    def trace_buffer
      @trace_buffer ||= TraceBuffer.new
    end
  end

  class VulnChaserTraceError < StandardError; end
end
