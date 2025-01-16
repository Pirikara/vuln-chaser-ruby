require "vuln_chaser/version"
require "vuln_chaser/flow_tracer"

module VulnChaser
  def self.start(base_path: nil)
    @base_path = base_path || default_base_path
    @tracer = FlowTracer.new(base_path: @base_path)
    @tracer.start
  end

  def self.stop
    @tracer.stop
  end

  def self.traces
    @tracer.traces
  end

  private

  def self.default_base_path
    defined?(Rails) && Rails.respond_to?(:root) ? Rails.root.to_s : Dir.pwd
  end
end
