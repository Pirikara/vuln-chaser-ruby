require "json"
require "method_source"

module VulnChaser
  class ExecutionTracer
    # Security-relevant method patterns
    DANGEROUS_SQL_METHODS = [
      'find_by_sql', 'execute', 'exec_query', 'exec_insert', 'exec_update', 'exec_delete',
      'connection.execute', 'where', 'select', 'update_all', 'delete_all', 'from'
    ].freeze

    DANGEROUS_SYSTEM_METHODS = [
      'system', 'exec', 'spawn', '`', 'eval', 'instance_eval', 'class_eval',
      'module_eval', 'define_method', 'send', '__send__'
    ].freeze

    DANGEROUS_FILE_METHODS = [
      'open', 'File.open', 'IO.popen', 'File.read', 'File.write', 'File.delete',
      'FileUtils.rm', 'FileUtils.cp', 'Dir.glob'
    ].freeze

    AUTH_METHODS = [
      'authenticate', 'sign_in', 'sign_out', 'current_user', 'login', 'logout',
      'authorize', 'can?', 'cannot?', 'ability', 'permitted?'
    ].freeze

    CRYPTO_METHODS = [
      'encrypt', 'decrypt', 'digest', 'hash', 'sign', 'verify',
      'BCrypt', 'Digest', 'OpenSSL', 'Base64'
    ].freeze

    def initialize
      @traces = {}
      @data_sanitizer = DataSanitizer.new
    end

    def start_trace(trace_id, env)
      request = ActionDispatch::Request.new(env) if defined?(ActionDispatch)
      
      @traces[trace_id] = {
        trace_id: trace_id,
        timestamp: Time.now.iso8601,
        request_info: {
          method: request&.method || 'UNKNOWN',
          path: request&.path || 'unknown',
          params: @data_sanitizer.sanitize_params(request&.params || {})
        },
        execution_trace: []
      }

      @trace_point = TracePoint.new(:call) do |tp|
        record_method_call(tp, trace_id) if relevant_method?(tp)
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
      
      # Dangerous framework methods
      return true if dangerous_framework_method?(tp)
      
      # Important gem methods (Rails external support)
      return true if important_gem_method?(tp)
      
      # App methods
      return true if tp.path.include?('/app/')
      
      false
    end

    def rails_app_code?(path)
      return false unless defined?(Rails)
      path.start_with?(Rails.root.to_s)
    end

    def dangerous_framework_method?(tp)
      method_name = tp.method_id.to_s
      
      DANGEROUS_SQL_METHODS.any? { |pattern| method_name.include?(pattern) } ||
      DANGEROUS_SYSTEM_METHODS.include?(method_name) ||
      DANGEROUS_FILE_METHODS.any? { |pattern| method_name.include?(pattern) } ||
      AUTH_METHODS.any? { |pattern| method_name.include?(pattern) } ||
      CRYPTO_METHODS.any? { |pattern| method_name.include?(pattern) }
    end

    def important_gem_method?(tp)
      path = tp.path
      
      # Main security-related gems
      security_gems = [
        'devise', 'omniauth', 'cancancan', 'pundit', 'doorkeeper',
        'bcrypt', 'jwt', 'rack-attack', 'secure_headers'
      ]
      
      security_gems.any? { |gem| path.include?("gems/#{gem}") }
    end

    def record_method_call(tp, trace_id)
      source_code = extract_source_code(tp)
      
      # Analyze parameter usage in the method
      param_usage = analyze_parameter_usage(tp, source_code, trace_id)
      
      @traces[trace_id][:execution_trace] << {
        method: "#{tp.defined_class}##{tp.method_id}",
        file: normalize_file_path(tp.path),
        line: tp.lineno,
        source: source_code,
        context: build_security_context(tp, source_code),
        parameter_usage: param_usage,
        risk_level: assess_risk_level(tp, source_code, param_usage),
        timestamp: Time.now.iso8601(3)
      }
    rescue => e
      VulnChaser.logger&.debug("VulnChaser: Failed to record method call: #{e}")
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
      context = []
      method_name = tp.method_id.to_s
      class_name = tp.defined_class&.name || ''

      # SQL-related context
      if sql_related_method?(method_name, source_code)
        context << "SQL execution detected"
        context << "Potential SQL injection" if potential_sql_injection?(source_code)
      end

      # Authentication-related context
      if auth_related_method?(method_name, class_name)
        context << "Authentication method"
      end

      # File operation context
      if file_operation_method?(method_name)
        context << "File operation detected"
      end

      # System command context
      if system_command_method?(method_name, source_code)
        context << "System command execution"
        context << "Potential command injection" if potential_command_injection?(source_code)
      end

      # Cryptographic context
      if crypto_method?(method_name, class_name)
        context << "Cryptographic operation"
      end

      # Eval-based context
      if eval_method?(method_name, source_code)
        context << "Dynamic code evaluation"
        context << "Potential code injection"
      end

      context.join(", ")
    end

    def sql_related_method?(method_name, source_code)
      DANGEROUS_SQL_METHODS.any? { |pattern| method_name.include?(pattern) } ||
        source_code.match?(/SELECT|INSERT|UPDATE|DELETE|FROM|WHERE/i)
    end

    def potential_sql_injection?(source_code)
      # Look for string interpolation in SQL-like strings
      source_code.match?(/#\{.*\}/) && source_code.match?(/SELECT|INSERT|UPDATE|DELETE|WHERE/i)
    end

    def auth_related_method?(method_name, class_name)
      AUTH_METHODS.any? { |pattern| method_name.include?(pattern) } ||
        class_name.match?(/Auth|User|Session|Login/i)
    end

    def file_operation_method?(method_name)
      DANGEROUS_FILE_METHODS.any? { |pattern| method_name.include?(pattern) }
    end

    def system_command_method?(method_name, source_code)
      DANGEROUS_SYSTEM_METHODS.include?(method_name) ||
        source_code.match?(/system|exec|spawn|`/)
    end

    def potential_command_injection?(source_code)
      # Look for user input in system commands
      source_code.match?(/#\{.*\}/) && source_code.match?(/system|exec|spawn|`/)
    end

    def crypto_method?(method_name, class_name)
      CRYPTO_METHODS.any? { |pattern| 
        method_name.include?(pattern) || class_name.include?(pattern) 
      }
    end

    def eval_method?(method_name, source_code)
      method_name.match?(/eval/) || source_code.match?(/eval|send|__send__/)
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
      # High risk: Direct param interpolation in dangerous methods
      if param_usage[:direct_interpolation] && !param_usage[:sanitization_detected]
        if sql_related_method?(tp.method_id.to_s, source_code) ||
           system_command_method?(tp.method_id.to_s, source_code) ||
           file_operation_method?(tp.method_id.to_s)
          return 'high'
        end
      end
      
      # Medium risk: Param usage in dangerous methods with some checks
      if param_usage[:uses_request_params] && !param_usage[:sanitization_detected]
        if sql_related_method?(tp.method_id.to_s, source_code) ||
           system_command_method?(tp.method_id.to_s, source_code)
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