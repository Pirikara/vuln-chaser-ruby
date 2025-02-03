require "json"
require "method_source"

module VulnChaser
  class FlowTracer
    def initialize(base_path:)
      @base_path = base_path
      @trace_data = []
      @current_context = nil
    end

    def start(context = nil)
      @current_context = context
      Rails.logger.info "VulnChaser: Starting flow tracer for request: #{context&.request_id}"
      @trace_point = TracePoint.new(:call, :return) do |tp|
        if relevant?(tp)
          record_trace(tp)
        end
      end
      @trace_point.enable
    end

    def stop
      Rails.logger.info "VulnChaser: Stopping flow tracer..."
      @trace_point.disable
      traces = @trace_data
      @trace_data = []
      traces
    end

    private

    def relevant?(tp)
      return true if VulnChaser::Config.custom_paths && VulnChaser::Config.custom_paths.any? { |path| tp.path.include?(path) }
      tp.path.start_with?(@base_path)
    end

    def record_trace(tp)
      return unless tp.event == :call

      method = tp.defined_class.instance_method(tp.method_id)
      
      trace_entry = {
        request_id: @current_context&.request_id,
        event: tp.event,
        defined_class: tp.defined_class.to_s,
        method_id: tp.method_id.to_s,
        source_code: method.source,
        source_location: method.source_location,
        timestamp: Time.current
      }
      @trace_data << trace_entry
    rescue MethodSource::SourceNotFoundError => e
      puts "Failed to get source for #{tp.defined_class}##{tp.method_id}: #{e.message}"
    end
    
    def process_arguments(parameters, binding)
      return {} unless defined?(Rails) && binding.local_variable_defined?(:params)
      
      params = binding.local_variable_get(:params)
      {
        "params": params.to_h
      }
    end

    def summarize_params(params)
      return params.class.to_s unless params.respond_to?(:to_h)
      
      params.to_h.transform_values do |value|
        case value
        when String, Numeric, Symbol
          value
        else
          "#{value.class} (size: #{value.size})" rescue value.class.to_s
        end
      end
    end
  end
end