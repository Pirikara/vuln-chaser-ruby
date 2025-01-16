module VulnChaser
  class FlowTracer
    def initialize(base_path:)
      @base_path = base_path
      @trace_data = []
    end

    def start
      @trace_point = TracePoint.new(:call, :return) do |tp|
        if relevant?(tp)
          record_trace(tp)
        end
      end
      @trace_point.enable
    end
  
    def stop
      @trace_point.disable
      @trace_data
    end
  
    def traces
      @trace_data
    end
  
    private

    def relevant?(tp)
      tp.path.start_with?(@base_path)
    end

    def record_trace(tp)
      case tp.event
      when :call
        @trace_data << {
          event: "call",
          method: tp.method_id,
          class: tp.defined_class,
          file: tp.path,
          line: tp.lineno,
          timestamp: Time.now
        }
      when :return
        @trace_data << {
          event: "return",
          method: tp.method_id,
          class: tp.defined_class,
          file: tp.path,
          line: tp.lineno,
          timestamp: Time.now
        }
      end
    end
  end
end