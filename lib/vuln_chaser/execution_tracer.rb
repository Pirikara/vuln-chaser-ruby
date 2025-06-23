require "json"
require "method_source"
require_relative "raw_data_collector"
require_relative "semantic_analyzer"
require_relative "context_enricher"

module VulnChaser
  class ExecutionTracer

    def initialize
      @traces = {}
      @data_sanitizer = DataSanitizer.new
      @current_request = nil
      # Phase 1: Pattern-free information collectors
      @raw_data_collector = RawDataCollector.new
      @semantic_analyzer = SemanticAnalyzer.new
      @context_enricher = ContextEnricher.new
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
        # Phase 1: Collect comprehensive raw data without pattern matching
        enhanced_data = collect_comprehensive_execution_data(trace_data)
        
        return {
          request_id: enhanced_data[:trace_id],
          endpoint: "#{enhanced_data[:request_info][:method]} #{enhanced_data[:request_info][:path]}",
          method: enhanced_data[:request_info][:method],
          params: enhanced_data[:request_info][:params],
          execution_trace: enhanced_data[:execution_trace],  # Fixed: Core expects 'execution_trace'
          
          # Phase 1: Rich structured data for LLM analysis
          code_structure: enhanced_data[:code_structure],
          data_flow_info: enhanced_data[:data_flow_info],
          external_interactions: enhanced_data[:external_interactions],
          semantic_analysis: enhanced_data[:semantic_analysis],
          execution_context: enhanced_data[:execution_context]
        }
      end
      
      nil
    end

    private

    def collect_comprehensive_execution_data(trace_data)
      execution_trace = trace_data[:execution_trace]
      
      # Collect raw structured data
      raw_data = @raw_data_collector.collect_execution_data(execution_trace)
      
      # Perform semantic analysis
      semantic_data = @semantic_analyzer.analyze_semantic_structure(execution_trace)
      
      # Enrich with context
      enriched_context = @context_enricher.enrich_execution_context(trace_data, execution_trace)
      
      trace_data.merge({
        execution_trace: execution_trace,
        code_structure: raw_data[:code_structure],
        data_flow_info: raw_data[:data_flow],
        external_interactions: raw_data[:external_interactions],
        semantic_analysis: semantic_data,
        execution_context: enriched_context
      })
    end

    def relevant_method?(tp)
      # Rails application code
      return true if rails_app_code?(tp.path)
      
      # App-specific paths
      return true if tp.path.include?('/app/')
      
      false
    end

    def rails_app_code?(path)
      return false unless defined?(Rails) && Rails.respond_to?(:root) && Rails.root
      
      begin
        path.start_with?(Rails.root.to_s)
      rescue => e
        false
      end
    end

    # SOR Framework: Enhanced context extraction methods
    def extract_request_context
      return {} unless @current_request
      
      begin
        {
          env: extract_env_context,
          session: extract_session_context,
          headers: extract_headers_context,
          remote_ip: @current_request.respond_to?(:remote_ip) ? @current_request.remote_ip : nil,
          user_agent: @current_request.respond_to?(:user_agent) ? @current_request.user_agent : nil
        }
      rescue => e
        VulnChaser.logger&.debug("VulnChaser: Failed to extract request context: #{e.message}")
        {}
      end
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
      return {} unless @current_request&.respond_to?(:env) && @current_request.env
      
      begin
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
      rescue => e
        VulnChaser.logger&.debug("VulnChaser: Failed to extract env context: #{e.message}")
        {}
      end
    end

    def extract_session_context
      return {} unless @current_request&.respond_to?(:session) && @current_request.session
      
      begin
        # Extract non-sensitive session data
        session_data = @current_request.session.to_hash
        @data_sanitizer.sanitize_session(session_data)
      rescue => e
        VulnChaser.logger&.debug("VulnChaser: Failed to extract session context: #{e.message}")
        {}
      end
    end

    def extract_headers_context
      return {} unless @current_request&.respond_to?(:headers) && @current_request.headers
      
      begin
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
      rescue => e
        VulnChaser.logger&.debug("VulnChaser: Failed to extract headers context: #{e.message}")
        {}
      end
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
      # Check if trace exists
      return unless @traces[trace_id]
      
      source_code = extract_source_code(tp)
      return unless source_code
      
      # SOR Framework: Enhanced context collection
      execution_context = extract_execution_context(tp)
      resource_context = extract_resource_context(tp)
      
      # Analyze parameter usage in the method
      param_usage = analyze_parameter_usage(tp, source_code, trace_id)
      
      # Ensure execution_trace array exists
      @traces[trace_id][:execution_trace] ||= []
      
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
      # Try to get method source using method_source gem
      begin
        method = tp.self.method(tp.method_id)
        if method.respond_to?(:source)
          source = method.source
          sanitized_source = @data_sanitizer.sanitize_source_code(source)
          return sanitized_source
        end
      rescue MethodSource::SourceNotFoundError, NameError, ArgumentError
        # Continue to fallback
        VulnChaser.logger&.debug("VulnChaser: Method source not found for #{tp.method_id}, using fallback")
      rescue => e
        # Log other unexpected errors but continue
        VulnChaser.logger&.debug("VulnChaser: Method source extraction failed: #{e.message}")
      end
      
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
      return path unless defined?(Rails) && Rails.respond_to?(:root) && Rails.root
      
      begin
        # Make paths relative to Rails root for consistency
        rails_root = Rails.root.to_s
        if path.start_with?(rails_root)
          path.sub(rails_root, "")
        else
          path
        end
      rescue => e
        # Fallback to original path if Rails.root is not available
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
      trace_data = @traces[trace_id]
      return default_parameter_usage unless trace_data
      
      request_info = trace_data[:request_info]
      return default_parameter_usage unless request_info
      
      request_params = request_info[:params] || {}
      
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
        
        # Pattern-Free Parameter Analysis
        # Collect raw interpolation and method usage data without security classification
        usage_info[:contains_interpolation] = source_code.include?('#{')
        usage_info[:contains_params_reference] = source_code.include?('params')
        usage_info[:direct_interpolation] = source_code.include?('#{') && source_code.include?('params')
        
        # Raw method detection without pattern-based security assessment
        usage_info[:source_code] = source_code
        usage_info[:method_calls] = source_code.scan(/\w+\(/).map { |m| m.chomp('(') }
        
        # Let LLM determine sanitization and security implications
        usage_info[:llm_analysis_required] = true
      end
      
      usage_info
    end
    
    def assess_risk_level(tp, source_code, param_usage)
      # Pattern-Free Risk Assessment: 
      # Collect raw risk indicators without predefined security classifications
      # Let LLM perform creative risk analysis based on execution context
      
      risk_indicators = {
        parameter_usage: param_usage,
        source_code_present: !source_code.empty?,
        direct_interpolation: param_usage[:direct_interpolation] || false,
        sanitization_detected: param_usage[:sanitization_detected] || false,
        method_name: tp.method_id.to_s,
        execution_context: true
      }
      
      # Return raw data instead of predetermined risk level
      # LLM will determine actual risk based on full context
      return {
        risk_classification: 'llm_analysis_required',
        raw_indicators: risk_indicators,
        pattern_free_assessment: true
      }
    end
    
    def default_parameter_usage
      {
        uses_request_params: false,
        param_keys_used: [],
        sanitization_detected: false,
        direct_interpolation: false
      }
    end
  end
end