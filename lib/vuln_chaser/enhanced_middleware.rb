require 'securerandom'

module VulnChaser
  class EnhancedMiddleware
    def initialize(app)
      @app = app
      @tracer = ExecutionTracer.new
    end

    def call(env)
      return @app.call(env) unless should_trace?(env)
      
      trace_id = SecureRandom.uuid
      @tracer.start_trace(trace_id, env)
      response = @app.call(env)
      
      if response[0] == 200
        trace_data = @tracer.finish_trace(trace_id)
        VulnChaser.trace_buffer.add_trace(trace_data) if trace_data
      else
        @tracer.finish_trace(trace_id)
      end
      
      response
    rescue => e
      VulnChaser.logger&.error("VulnChaser: Middleware error: #{e.message}")
      @tracer.finish_trace(trace_id) if trace_id
      raise e
    end

    private

    def should_trace?(env)
      request = ActionDispatch::Request.new(env) if defined?(ActionDispatch)
      return false unless request
      
      # Skip excluded paths
      return false if excluded_path?(request.path)
      
      # Only trace relevant HTTP methods
      return false unless traceable_method?(request.method)
      
      true
    end

    def excluded_path?(path)
      excluded_patterns = [
        '/health_check', '/health', '/ping',
        '/assets/', '/favicon.ico',
        '/_internal/', '/system/'
      ]
      
      # Add configured excluded paths
      if VulnChaser::Config.excluded_paths
        excluded_patterns.concat(VulnChaser::Config.excluded_paths)
      end
      
      excluded_patterns.any? { |pattern| path.start_with?(pattern) }
    end

    def traceable_method?(method)
      %w[GET POST PUT PATCH DELETE].include?(method.upcase)
    end
  end
end