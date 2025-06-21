require "json"
require "method_source"

module VulnChaser
  class ExecutionTracer

    def initialize
      @traces = {}
      @data_sanitizer = DataSanitizer.new
      @current_request = nil
    end

    def start_trace(trace_id, env)
      request = ActionDispatch::Request.new(env) if defined?(ActionDispatch)
      @current_request = request
      
      @traces[trace_id] = {
        trace_id: trace_id,
        timestamp: Time.now.iso8601,
        request_info: {
          method: request&.method || 'UNKNOWN',
          path: request&.path || 'unknown',
          params: @data_sanitizer.sanitize_params(request&.params || {})
        },
        # SOR Framework: Enhanced context collection
        request_context: extract_request_context,
        execution_trace: []
      }

      @trace_point = TracePoint.new(:call) do |tp|
        record_enhanced_method_call(tp, trace_id) if relevant_method?(tp)
      end
      @trace_point.enable
    end

    def finish_trace(trace_id)
      @trace_point&.disable
      trace_data = @traces.delete(trace_id)
      
      if trace_data && !trace_data[:execution_trace].empty?
        return {
          request_id: trace_data[:trace_id],
          endpoint: "#{trace_data[:request_info][:method]} #{trace_data[:request_info][:path]}",
          method: trace_data[:request_info][:method],
          params: trace_data[:request_info][:params],
          traces: trace_data[:execution_trace]
        }
      end
      
      nil
    end

    private

    def relevant_method?(tp)
      # Rails application code
      return true if rails_app_code?(tp.path)
      
      # App-specific paths
      return true if tp.path.include?('/app/')
      
      false
    end

    def rails_app_code?(path)
      return false unless defined?(Rails)
      path.start_with?(Rails.root.to_s)
    end

    # SOR Framework: Enhanced context extraction methods
    def extract_request_context
      return {} unless @current_request
      
      {
        env: extract_env_context,
        session: extract_session_context,
        headers: extract_headers_context,
        remote_ip: @current_request.remote_ip,
        user_agent: @current_request.user_agent
      }
    end

    def extract_execution_context(tp)
      {
        method_name: tp.method_id.to_s,
        class_name: tp.defined_class&.name || '',
        source_location: [tp.path, tp.lineno],
        local_variables: extract_local_variables(tp),
        instance_variables: extract_instance_variables(tp)
      }
    end

    def extract_resource_context(tp)
      {
        accessed_constants: extract_accessed_constants(tp),
        file_operations: detect_file_operations(tp),
        database_operations: detect_database_operations(tp),
        network_operations: detect_network_operations(tp),
        environment_access: detect_environment_access(tp)
      }
    end

    private

    def extract_env_context
      return {} unless @current_request&.env
      
      # Extract security-relevant environment variables
      env_keys = %w[
        REQUEST_METHOD PATH_INFO QUERY_STRING SERVER_NAME SERVER_PORT
        HTTP_HOST HTTP_USER_AGENT HTTP_ACCEPT HTTP_ACCEPT_LANGUAGE
        HTTP_ACCEPT_ENCODING HTTP_CONNECTION HTTP_CACHE_CONTROL
        REMOTE_ADDR REMOTE_HOST REMOTE_USER CONTENT_TYPE CONTENT_LENGTH
      ]
      
      extracted = {}
      env_keys.each do |key|
        extracted[key] = @current_request.env[key] if @current_request.env[key]
      end
      
      @data_sanitizer.sanitize_env(extracted)
    end

    def extract_session_context
      return {} unless @current_request&.session
      
      # Extract non-sensitive session data
      session_data = @current_request.session.to_hash
      @data_sanitizer.sanitize_session(session_data)
    end

    def extract_headers_context
      return {} unless @current_request&.headers
      
      # Extract security-relevant headers
      header_keys = %w[
        Authorization Content-Type Accept User-Agent Referer
        X-Forwarded-For X-Real-IP X-Requested-With
        X-CSRF-Token X-API-Key
      ]
      
      extracted = {}
      header_keys.each do |key|
        extracted[key] = @current_request.headers[key] if @current_request.headers[key]
      end
      
      @data_sanitizer.sanitize_headers(extracted)
    end

    def extract_local_variables(tp)
      return [] unless tp.binding
      
      begin
        tp.binding.local_variables.map(&:to_s)
      rescue => e
        VulnChaser.logger&.debug("Failed to extract local variables: #{e}")
        []
      end
    end

    def extract_instance_variables(tp)
      return [] unless tp.self
      
      begin
        tp.self.instance_variables.map(&:to_s)
      rescue => e
        VulnChaser.logger&.debug("Failed to extract instance variables: #{e}")
        []
      end
    end

    def extract_accessed_constants(tp)
      # Extract referenced constants from the source
      source_code = extract_source_code(tp)
      constants = source_code.scan(/[A-Z][A-Za-z0-9_]*::[A-Za-z0-9_]+|[A-Z][A-Za-z0-9_]*/)
      constants.uniq
    end

    def detect_file_operations(tp)
      method_name = tp.method_id.to_s
      file_patterns = %w[open read write delete copy move mkdir rmdir glob]
      
      operations = []
      file_patterns.each do |pattern|
        operations << pattern if method_name.include?(pattern)
      end
      
      operations
    end

    def detect_database_operations(tp)
      method_name = tp.method_id.to_s
      source_code = extract_source_code(tp)
      
      operations = []
      
      # SQL keywords
      sql_keywords = %w[SELECT INSERT UPDATE DELETE FROM WHERE JOIN]
      sql_keywords.each do |keyword|
        operations << keyword.downcase if source_code.upcase.include?(keyword)
      end
      
      # ActiveRecord methods
      ar_methods = %w[find where create update destroy save]
      ar_methods.each do |method|
        operations << method if method_name.include?(method)
      end
      
      operations.uniq
    end

    def detect_network_operations(tp)
      method_name = tp.method_id.to_s
      network_patterns = %w[http https ftp tcp udp socket connect request]
      
      operations = []
      network_patterns.each do |pattern|
        operations << pattern if method_name.include?(pattern)
      end
      
      operations
    end

    def detect_environment_access(tp)
      source_code = extract_source_code(tp)
      env_patterns = %w[ENV Rails.env RAILS_ENV]
      
      accesses = []
      env_patterns.each do |pattern|
        accesses << pattern if source_code.include?(pattern)
      end
      
      accesses
    end

    def record_enhanced_method_call(tp, trace_id)
      source_code = extract_source_code(tp)
      
      # SOR Framework: Enhanced context collection
      execution_context = extract_execution_context(tp)
      resource_context = extract_resource_context(tp)
      
      # Analyze parameter usage in the method
      param_usage = analyze_parameter_usage(tp, source_code, trace_id)
      
      @traces[trace_id][:execution_trace] << {
        method: "#{tp.defined_class}##{tp.method_id}",
        file: normalize_file_path(tp.path),
        line: tp.lineno,
        source: source_code,
        # Legacy context for backward compatibility
        context: build_security_context(tp, source_code),
        parameter_usage: param_usage,
        risk_level: assess_risk_level(tp, source_code, param_usage),
        # SOR Framework: Enhanced context data
        execution_context: execution_context,
        resource_context: resource_context,
        timestamp: Time.now.iso8601(3)
      }
    rescue => e
      VulnChaser.logger&.debug("VulnChaser: Failed to record enhanced method call: #{e}")
    end

    def extract_source_code(tp)
      method = tp.self.method(tp.method_id)
      source = method.source
      @data_sanitizer.sanitize_source_code(source)
    rescue MethodSource::SourceNotFoundError, NameError
      # Fallback: read source line from file
      read_source_line(tp.path, tp.lineno)
    rescue => e
      VulnChaser.logger&.debug("VulnChaser: Failed to extract source: #{e.message}")
      "[SOURCE_NOT_AVAILABLE]"
    end

    def read_source_line(file_path, line_number)
      return "[FILE_NOT_FOUND]" unless File.exist?(file_path)

      line = File.readlines(file_path)[line_number - 1]&.strip
      @data_sanitizer.sanitize_source_code(line || "[EMPTY_LINE]")
    rescue => e
      VulnChaser.logger&.debug("VulnChaser: Failed to read source line: #{e.message}")
      "[READ_ERROR]"
    end

    def normalize_file_path(path)
      return path unless defined?(Rails)
      
      # Make paths relative to Rails root for consistency
      if path.start_with?(Rails.root.to_s)
        path.sub(Rails.root.to_s, "")
      else
        path
      end
    end

    def build_security_context(tp, source_code)
      # Simplified context for backward compatibility
      # SOR Framework will handle detailed analysis on Core side
      context = []
      method_name = tp.method_id.to_s
      class_name = tp.defined_class&.name || ''

      # Basic pattern detection for immediate context
      context << "SQL-related" if source_code.match?(/SELECT|INSERT|UPDATE|DELETE|FROM|WHERE/i)
      context << "File operation" if method_name.match?(/open|read|write|delete|file/i)
      context << "System command" if source_code.match?(/system|exec|spawn|`/i)
      context << "Authentication" if method_name.match?(/auth|login|sign|current_user/i)
      context << "Cryptographic" if method_name.match?(/encrypt|decrypt|hash|digest/i)
      context << "Dynamic evaluation" if source_code.match?(/eval|send|define_method/i)

      context.empty? ? "General method execution" : context.join(", ")
    end


    def analyze_parameter_usage(tp, source_code, trace_id)
      # Get request parameters for this trace
      request_params = @traces[trace_id][:request_info][:params] || {}
      
      usage_info = {
        uses_request_params: false,
        param_keys_used: [],
        sanitization_detected: false,
        direct_interpolation: false
      }
      
      # Check if source code uses params
      if source_code.include?('params[') || source_code.include?('params.')
        usage_info[:uses_request_params] = true
        
        # Extract which param keys are used
        request_params.keys.each do |key|
          if source_code.include?(key.to_s)
            usage_info[:param_keys_used] << key.to_s
          end
        end
        
        # Check for direct string interpolation
        if source_code.match?(/#\{.*params.*\}/)
          usage_info[:direct_interpolation] = true
        end
        
        # Check for sanitization methods
        sanitization_patterns = [
          'sanitize', 'escape', 'quote', 'validate', 'permit', 'allow',
          'strip_tags', 'html_escape', 'sql_escape', 'filter'
        ]
        
        if sanitization_patterns.any? { |pattern| source_code.include?(pattern) }
          usage_info[:sanitization_detected] = true
        end
      end
      
      usage_info
    end
    
    def assess_risk_level(tp, source_code, param_usage)
      method_name = tp.method_id.to_s
      
      # High risk: Direct param interpolation in potentially dangerous operations
      if param_usage[:direct_interpolation] && !param_usage[:sanitization_detected]
        if source_code.match?(/SELECT|INSERT|UPDATE|DELETE|WHERE/i) ||
           source_code.match?(/system|exec|spawn|`/i) ||
           method_name.match?(/open|read|write|delete|file/i)
          return 'high'
        end
      end
      
      # Medium risk: Param usage without sanitization in potentially dangerous operations
      if param_usage[:uses_request_params] && !param_usage[:sanitization_detected]
        if source_code.match?(/SELECT|INSERT|UPDATE|DELETE|WHERE/i) ||
           source_code.match?(/system|exec|spawn|`/i)
          return 'medium'
        end
      end
      
      # Low risk: General param usage
      if param_usage[:uses_request_params]
        return 'low'
      end
      
      'none'
    end
  end
end