require "vuln_chaser/version"
require "vuln_chaser/config"
require "vuln_chaser/flow_tracer"
require "vuln_chaser/trace_context"
require "vuln_chaser/trace_store"
require "vuln_chaser/middleware"
require 'rails/generators'
require 'generators/vuln_chaser/install_generator'

module VulnChaser
  class << self
    def configure
      yield(Config)
    end
  end

  class VulnChaserTraceError < StandardError; end
end
