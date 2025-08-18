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
      # Loop detection for duplicate method calls
      @method_call_cache = {}
      # Cache for bundled gem paths
      @bundled_gem_paths = nil
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
        request_context: extract_request_context,
        execution_trace: []
      }

      # Reset method call cache for new trace
      @method_call_cache[trace_id] = {}

      @trace_point = TracePoint.new(:call) do |tp|
        record_enhanced_method_call(tp, trace_id) if relevant_method?(tp)
      end
      @trace_point.enable
    end

    def finish_trace(trace_id)
      @trace_point&.disable
      trace_data = @traces.delete(trace_id)
      
      # Clean up method call cache for this trace
      @method_call_cache.delete(trace_id)
      
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
      return true if project_root_code?(tp.path)
      return true if custom_path_code?(tp.path)
      return true if user_configured_gem_code?(tp.path)
      
      false
    end


    def project_root_code?(path)
      manual_roots = VulnChaser::Config.project_roots
      if manual_roots && !manual_roots.empty?
        return manual_roots.any? { |root| path.start_with?(root) }
      end
      
      return false if VulnChaser::Config.disable_auto_detection
      
      project_roots.any? { |root_path| path.start_with?(root_path) }
    end
    
    def project_roots
      @project_roots ||= detect_project_roots
    end
    
    def detect_project_roots
      roots = []
      
      if rails_project?
        rails_root = Rails.root.to_s
        rails_dirs = %w[app config lib].map { |dir| File.join(rails_root, dir) }
        existing_dirs = rails_dirs.select { |dir| Dir.exist?(dir) }
        roots.concat(existing_dirs)
        VulnChaser.logger&.info("VulnChaser: Detected Rails project, tracing: #{existing_dirs.join(', ')}")
      end
      
      if gem_project?
        gem_root = detect_gem_root
        gem_dirs = %w[lib src].map { |dir| File.join(gem_root, dir) }
        existing_dirs = gem_dirs.select { |dir| Dir.exist?(dir) }
        roots.concat(existing_dirs)
        VulnChaser.logger&.info("VulnChaser: Detected Gem project, tracing: #{existing_dirs.join(', ')}")
      end
      
      if sinatra_project?
        sinatra_root = detect_sinatra_root
        sinatra_dirs = %w[app lib routes].map { |dir| File.join(sinatra_root, dir) }
        existing_dirs = sinatra_dirs.select { |dir| Dir.exist?(dir) }
        roots.concat(existing_dirs)
        VulnChaser.logger&.info("VulnChaser: Detected Sinatra project, tracing: #{existing_dirs.join(', ')}")
      end
      
      if roots.empty?
        generic_root = detect_generic_ruby_root
        generic_dirs = %w[lib src app].map { |dir| File.join(generic_root, dir) }
        existing_dirs = generic_dirs.select { |dir| Dir.exist?(dir) }
        roots.concat(existing_dirs)
        VulnChaser.logger&.info("VulnChaser: Detected generic Ruby project, tracing: #{existing_dirs.join(', ')}")
      end
      
      roots.uniq
    end
    
    def rails_project?
      defined?(Rails) && Rails.respond_to?(:root) && Rails.root
    end
    
    def gem_project?
      current_dir = Dir.pwd
      Dir.glob(File.join(current_dir, '*.gemspec')).any?
    end
    
    def sinatra_project?
      gemfile_path = File.join(Dir.pwd, 'Gemfile')
      return false unless File.exist?(gemfile_path)
      
      File.read(gemfile_path).include?('sinatra')
    rescue
      false
    end
    
    def detect_gem_root
      current_dir = Dir.pwd
      gemspec_files = Dir.glob(File.join(current_dir, '*.gemspec'))
      
      if gemspec_files.any?
        File.dirname(gemspec_files.first)
      else
        current_dir
      end
    end
    
    def detect_sinatra_root
      current_dir = Dir.pwd
      
      path = current_dir
      while path != '/'
        return path if File.exist?(File.join(path, 'Gemfile'))
        path = File.dirname(path)
      end
      
      current_dir
    end
    
    def detect_generic_ruby_root
      current_dir = Dir.pwd
      indicators = %w[Gemfile Rakefile .git]
      
      path = current_dir
      while path != '/'
        if indicators.any? { |indicator| File.exist?(File.join(path, indicator)) }
          return path
        end
        path = File.dirname(path)
      end
      
      current_dir
    end
    
    # User-configured gem tracing
    def user_configured_gem_code?(path)
      return false unless VulnChaser::Config.traced_gems
      return false if VulnChaser::Config.traced_gems.empty?
      
      traced_gem_paths.any? { |gem_path| path.start_with?(gem_path) }
    end
    
    def traced_gem_paths
      @traced_gem_paths ||= discover_user_configured_gem_paths
    end
    
    def discover_user_configured_gem_paths
      return [] unless defined?(Bundler)
      return [] unless VulnChaser::Config.traced_gems
      
      user_gems = VulnChaser::Config.traced_gems
      gem_paths = []
      
      begin
        Bundler.load.specs.each do |spec|
          if user_gems.include?(spec.name)
            gem_path = spec.full_gem_path
            gem_paths << gem_path if gem_path && Dir.exist?(gem_path)
          end
        end
        
        VulnChaser.logger&.info("VulnChaser: User configured #{gem_paths.size} gems for tracing: #{user_gems.join(', ')}")
        gem_paths
      rescue => e
        VulnChaser.logger&.warn("VulnChaser: Failed to resolve user configured gems: #{e.message}")
        []
      end
    end
    
    def custom_path_code?(path)
      return false unless VulnChaser::Config.custom_paths
      
      VulnChaser::Config.custom_paths.any? { |custom_path| path.include?(custom_path) }
    end

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
      
      # Check for duplicate method calls (loop detection)
      method_signature = generate_method_signature(tp)
      return if duplicate_method_call?(trace_id, method_signature)
      
      source_code = extract_source_code(tp)
      return unless source_code
      
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
        parameter_usage: param_usage,
        risk_level: assess_risk_level(tp, source_code, param_usage),
        execution_context: execution_context,
        resource_context: resource_context,
        timestamp: Time.now.iso8601(3)
      }
      
      # Mark this method call as seen
      mark_method_call_seen(trace_id, method_signature)
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

    # Loop detection methods
    def generate_method_signature(tp)
      "#{tp.defined_class}##{tp.method_id}@#{normalize_file_path(tp.path)}:#{tp.lineno}"
    end

    def duplicate_method_call?(trace_id, method_signature)
      cache = @method_call_cache[trace_id]
      return false unless cache
      
      cache.key?(method_signature)
    end

    def mark_method_call_seen(trace_id, method_signature)
      cache = @method_call_cache[trace_id]
      return unless cache
      
      cache[method_signature] = true
    end
  end
end
