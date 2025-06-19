module VulnChaser
  class Middleware
    def initialize(app)
      @app = app
      @flow_tracer = FlowTracer.new(base_path: Rails.root.to_s)
    end

    def call(env)
      request = ActionDispatch::Request.new(env)
      context = TraceContext.new(request)
      
      puts "Starting chaser..."
      @flow_tracer.start(context)
      response = @app.call(env)
      puts "Stopping chaser..."
      traces = @flow_tracer.stop

      VulnChaser.trace_buffer.add_trace(context.to_hash(traces)) if response[0].to_i == 200
      
      response
    end

    private

    def store_trace(context)
      TraceStore.instance.store(context.to_hash)
    end
  end
end