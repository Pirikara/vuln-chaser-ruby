module VulnChaser
  class ContextEnricher
    """
    実行コンテキストを富化（セキュリティ判定なし）
    実行時環境の詳細な情報を構造化して収集
    """
    
    def enrich_execution_context(trace_data, execution_traces)
      {
        application_context: extract_application_context,
        runtime_environment: analyze_runtime_environment,
        execution_metadata: generate_execution_metadata(trace_data, execution_traces),
        performance_metrics: collect_performance_metrics(execution_traces),
        call_chain_analysis: analyze_call_chain(execution_traces)
      }
    end

    private

    def extract_application_context
      context = {}
      
      # Rails application context
      if defined?(Rails)
        context[:framework] = 'rails'
        context[:rails_version] = Rails.version if Rails.respond_to?(:version)
        context[:environment] = Rails.env if Rails.respond_to?(:env)
        context[:application_name] = Rails.application.class.module_parent.name if Rails.application
        
        # Rails configuration insights
        if Rails.respond_to?(:configuration)
          config = Rails.configuration
          context[:session_store] = config.session_store.to_s if config.respond_to?(:session_store)
          context[:cache_store] = config.cache_store.to_s if config.respond_to?(:cache_store)
          context[:log_level] = config.log_level.to_s if config.respond_to?(:log_level)
        end
      else
        context[:framework] = 'ruby'
      end
      
      # Ruby version and platform
      context[:ruby_version] = RUBY_VERSION
      context[:ruby_platform] = RUBY_PLATFORM
      context[:ruby_engine] = RUBY_ENGINE if defined?(RUBY_ENGINE)
      
      # Gem environment
      if defined?(Bundler)
        context[:bundler_version] = Bundler::VERSION
        context[:gemfile_lock_exists] = File.exist?('Gemfile.lock')
      end
      
      context
    end

    def analyze_runtime_environment
      environment = {}
      
      # Process information
      environment[:process_id] = Process.pid
      environment[:parent_process_id] = Process.ppid
      environment[:user_id] = Process.uid if Process.respond_to?(:uid)
      environment[:group_id] = Process.gid if Process.respond_to?(:gid)
      
      # Memory and performance
      if defined?(GC)
        gc_stats = GC.stat
        environment[:gc_count] = gc_stats[:count] if gc_stats[:count]
        environment[:heap_allocated_pages] = gc_stats[:heap_allocated_pages] if gc_stats[:heap_allocated_pages]
        environment[:heap_live_slots] = gc_stats[:heap_live_slots] if gc_stats[:heap_live_slots]
      end
      
      # Thread information
      environment[:thread_count] = Thread.list.size
      environment[:main_thread] = Thread.current == Thread.main
      
      # Working directory
      environment[:working_directory] = Dir.pwd
      
      # Load path information
      environment[:load_path_size] = $LOAD_PATH.size
      environment[:loaded_features_count] = $LOADED_FEATURES.size
      
      environment
    end

    def generate_execution_metadata(trace_data, execution_traces)
      metadata = {}
      
      # Basic execution info
      metadata[:trace_id] = trace_data[:trace_id]
      metadata[:start_time] = trace_data[:timestamp]
      metadata[:trace_count] = execution_traces.size
      
      # Request context (if available)
      if trace_data[:request_info]
        request_info = trace_data[:request_info]
        metadata[:http_method] = request_info[:method]
        metadata[:request_path] = request_info[:path]
        metadata[:has_parameters] = !request_info[:params].empty?
        metadata[:parameter_count] = request_info[:params].size
      end
      
      # File and method distribution
      file_distribution = analyze_file_distribution(execution_traces)
      metadata[:unique_files] = file_distribution[:unique_files]
      metadata[:file_distribution] = file_distribution[:distribution]
      
      method_distribution = analyze_method_distribution(execution_traces)
      metadata[:unique_methods] = method_distribution[:unique_methods]
      metadata[:method_distribution] = method_distribution[:distribution]
      
      # Risk level distribution
      risk_distribution = analyze_risk_distribution(execution_traces)
      metadata[:risk_distribution] = risk_distribution
      
      # Parameter usage statistics
      param_stats = analyze_parameter_usage_stats(execution_traces)
      metadata[:parameter_usage_stats] = param_stats
      
      metadata
    end

    def collect_performance_metrics(execution_traces)
      metrics = {}
      
      # Execution timing (if available)
      if execution_traces.any? { |t| t[:timestamp] }
        timestamps = execution_traces.filter_map { |t| t[:timestamp] }
        if timestamps.size > 1
          # Calculate execution duration
          start_time = Time.parse(timestamps.first)
          end_time = Time.parse(timestamps.last)
          metrics[:total_execution_time_ms] = ((end_time - start_time) * 1000).round(2)
          metrics[:average_method_time_ms] = (metrics[:total_execution_time_ms] / execution_traces.size).round(2)
        end
      end
      
      # Complexity metrics
      complexity_scores = execution_traces.map do |trace|
        calculate_method_complexity(trace[:source] || '')
      end
      
      metrics[:average_complexity] = (complexity_scores.sum.to_f / complexity_scores.size).round(2)
      metrics[:max_complexity] = complexity_scores.max
      metrics[:complexity_distribution] = {
        low: complexity_scores.count { |s| s <= 3 },
        medium: complexity_scores.count { |s| s > 3 && s <= 7 },
        high: complexity_scores.count { |s| s > 7 }
      }
      
      # Source code metrics
      source_metrics = analyze_source_code_metrics(execution_traces)
      metrics[:source_code_metrics] = source_metrics
      
      metrics
    end

    def analyze_call_chain(execution_traces)
      chain_analysis = {}
      
      # Call depth analysis
      chain_analysis[:total_depth] = execution_traces.size
      chain_analysis[:unique_classes] = extract_unique_classes(execution_traces).size
      chain_analysis[:unique_files] = extract_unique_files(execution_traces).size
      
      # Call patterns
      call_patterns = identify_call_patterns(execution_traces)
      chain_analysis[:patterns] = call_patterns
      
      # Recursion detection
      recursion_info = detect_recursion(execution_traces)
      chain_analysis[:recursion] = recursion_info
      
      # Cross-boundary calls
      boundary_calls = identify_boundary_calls(execution_traces)
      chain_analysis[:boundary_calls] = boundary_calls
      
      # Method clustering
      method_clusters = cluster_methods_by_purpose(execution_traces)
      chain_analysis[:method_clusters] = method_clusters
      
      chain_analysis
    end

    # Helper methods for detailed analysis
    def analyze_file_distribution(execution_traces)
      files = execution_traces.map { |t| t[:file] }.compact
      unique_files = files.uniq
      
      distribution = unique_files.map do |file|
        count = files.count(file)
        {
          file: file,
          call_count: count,
          percentage: (count.to_f / files.size * 100).round(2)
        }
      end.sort_by { |d| -d[:call_count] }
      
      {
        unique_files: unique_files.size,
        distribution: distribution
      }
    end

    def analyze_method_distribution(execution_traces)
      methods = execution_traces.map { |t| t[:method] }.compact
      unique_methods = methods.uniq
      
      distribution = unique_methods.map do |method|
        count = methods.count(method)
        {
          method: method,
          call_count: count,
          percentage: (count.to_f / methods.size * 100).round(2)
        }
      end.sort_by { |d| -d[:call_count] }
      
      {
        unique_methods: unique_methods.size,
        distribution: distribution
      }
    end

    def analyze_risk_distribution(execution_traces)
      risk_levels = execution_traces.map { |t| t[:risk_level] }.compact
      
      distribution = {}
      %w[none low medium high].each do |level|
        count = risk_levels.count(level)
        distribution[level] = {
          count: count,
          percentage: risk_levels.empty? ? 0 : (count.to_f / risk_levels.size * 100).round(2)
        }
      end
      
      distribution
    end

    def analyze_parameter_usage_stats(execution_traces)
      param_usages = execution_traces.filter_map { |t| t[:parameter_usage] }
      
      return {} if param_usages.empty?
      
      stats = {}
      
      # Overall parameter usage
      uses_params_count = param_usages.count { |p| p[:uses_request_params] }
      stats[:methods_using_params] = uses_params_count
      stats[:methods_using_params_percentage] = (uses_params_count.to_f / param_usages.size * 100).round(2)
      
      # Direct interpolation usage
      direct_interp_count = param_usages.count { |p| p[:direct_interpolation] }
      stats[:methods_with_direct_interpolation] = direct_interp_count
      stats[:direct_interpolation_percentage] = (direct_interp_count.to_f / param_usages.size * 100).round(2)
      
      # Sanitization detection
      sanitized_count = param_usages.count { |p| p[:sanitization_detected] }
      stats[:methods_with_sanitization] = sanitized_count
      stats[:sanitization_percentage] = (sanitized_count.to_f / param_usages.size * 100).round(2)
      
      # Parameter key usage
      all_param_keys = param_usages.flat_map { |p| p[:param_keys_used] || [] }
      unique_param_keys = all_param_keys.uniq
      stats[:unique_parameter_keys] = unique_param_keys.size
      stats[:most_used_parameters] = unique_param_keys.map do |key|
        {
          key: key,
          usage_count: all_param_keys.count(key)
        }
      end.sort_by { |p| -p[:usage_count] }.first(5)
      
      stats
    end

    def calculate_method_complexity(source_code)
      return 1 if source_code.empty?
      
      complexity = 1  # Base complexity
      
      # Control structures add complexity
      complexity += source_code.scan(/\bif\b/).length
      complexity += source_code.scan(/\bcase\b/).length
      complexity += source_code.scan(/\bwhile\b/).length
      complexity += source_code.scan(/\bfor\b/).length
      complexity += source_code.scan(/\beach\b/).length
      complexity += source_code.scan(/\btimes\b/).length
      complexity += source_code.scan(/\brescue\b/).length
      complexity += source_code.scan(/\bensure\b/).length
      
      # Logical operators add complexity
      complexity += source_code.scan(/\&\&|\|\||and\b|or\b/).length
      
      complexity
    end

    def analyze_source_code_metrics(execution_traces)
      source_codes = execution_traces.map { |t| t[:source] }.compact
      
      return {} if source_codes.empty?
      
      metrics = {}
      
      # Line count metrics
      line_counts = source_codes.map { |code| code.lines.count }
      metrics[:average_lines_per_method] = (line_counts.sum.to_f / line_counts.size).round(2)
      metrics[:max_lines_per_method] = line_counts.max
      metrics[:min_lines_per_method] = line_counts.min
      
      # Character count metrics
      char_counts = source_codes.map { |code| code.length }
      metrics[:average_chars_per_method] = (char_counts.sum.to_f / char_counts.size).round(2)
      metrics[:max_chars_per_method] = char_counts.max
      
      # Comment analysis
      comment_counts = source_codes.map { |code| code.scan(/#[^\n]*/).length }
      metrics[:methods_with_comments] = comment_counts.count { |c| c > 0 }
      metrics[:average_comments_per_method] = (comment_counts.sum.to_f / comment_counts.size).round(2)
      
      # String literal analysis
      string_counts = source_codes.map { |code| code.scan(/"[^"]*"|'[^']*'/).length }
      metrics[:average_string_literals] = (string_counts.sum.to_f / string_counts.size).round(2)
      
      metrics
    end

    def extract_unique_classes(execution_traces)
      classes = execution_traces.filter_map do |trace|
        method = trace[:method]
        if method && method.include?('#')
          method.split('#')[0]
        elsif method && method.include?('::')
          method.split('::')[0]
        end
      end
      
      classes.uniq
    end

    def extract_unique_files(execution_traces)
      execution_traces.map { |t| t[:file] }.compact.uniq
    end

    def identify_call_patterns(execution_traces)
      patterns = []
      
      # Sequential method calls in same class
      execution_traces.each_cons(2) do |current, next_trace|
        current_class = extract_class_name(current[:method])
        next_class = extract_class_name(next_trace[:method])
        
        if current_class && next_class && current_class == next_class
          patterns << {
            type: 'same_class_sequence',
            class_name: current_class,
            methods: [current[:method], next_trace[:method]]
          }
        end
      end
      
      # Controller -> Model -> Database patterns
      controller_to_db = detect_controller_to_database_pattern(execution_traces)
      patterns.concat(controller_to_db) if controller_to_db.any?
      
      # Service object patterns
      service_patterns = detect_service_patterns(execution_traces)
      patterns.concat(service_patterns) if service_patterns.any?
      
      patterns
    end

    def detect_recursion(execution_traces)
      method_calls = execution_traces.map { |t| t[:method] }
      
      recursion_info = {}
      
      # Direct recursion
      method_calls.each_with_index do |method, index|
        remaining_calls = method_calls[(index + 1)..-1]
        if remaining_calls && remaining_calls.include?(method)
          recursion_info[:direct_recursion] ||= []
          recursion_info[:direct_recursion] << {
            method: method,
            first_occurrence: index,
            recursion_depth: remaining_calls.count(method)
          }
        end
      end
      
      # Indirect recursion (A -> B -> A)
      indirect_recursion = detect_indirect_recursion(method_calls)
      recursion_info[:indirect_recursion] = indirect_recursion if indirect_recursion.any?
      
      recursion_info
    end

    def identify_boundary_calls(execution_traces)
      boundary_calls = []
      
      execution_traces.each_with_index do |trace, index|
        file_path = trace[:file]
        method_name = trace[:method]
        
        # Controller boundaries
        if file_path&.include?('/controllers/') && index < execution_traces.size - 1
          next_trace = execution_traces[index + 1]
          if !next_trace[:file]&.include?('/controllers/')
            boundary_calls << {
              type: 'controller_exit',
              from: method_name,
              to: next_trace[:method],
              boundary: 'controller_to_model'
            }
          end
        end
        
        # Model boundaries
        if file_path&.include?('/models/') && index < execution_traces.size - 1
          next_trace = execution_traces[index + 1]
          if next_trace[:file]&.include?('/lib/') || 
             next_trace[:method]&.include?('ActiveRecord')
            boundary_calls << {
              type: 'model_exit',
              from: method_name,
              to: next_trace[:method],
              boundary: 'model_to_persistence'
            }
          end
        end
        
        # Service boundaries
        if file_path&.include?('/services/') || method_name&.include?('Service')
          boundary_calls << {
            type: 'service_boundary',
            method: method_name,
            file: file_path
          }
        end
      end
      
      boundary_calls
    end

    def cluster_methods_by_purpose(execution_traces)
      clusters = {
        controller_actions: [],
        model_operations: [],
        database_operations: [],
        validation_operations: [],
        authentication_operations: [],
        utility_operations: []
      }
      
      execution_traces.each do |trace|
        method_name = trace[:method]
        file_path = trace[:file]
        source_code = trace[:source] || ''
        
        # Classify by purpose
        if file_path&.include?('/controllers/') || method_name&.include?('Controller')
          clusters[:controller_actions] << method_name
        elsif source_code.match?(/SELECT|INSERT|UPDATE|DELETE|find|where|create|save|destroy/i)
          clusters[:database_operations] << method_name
        elsif method_name&.downcase&.include?('valid') || source_code.include?('validate')
          clusters[:validation_operations] << method_name
        elsif method_name&.downcase&.include?('auth') || method_name&.downcase&.include?('login')
          clusters[:authentication_operations] << method_name
        elsif file_path&.include?('/models/') || method_name&.include?('#')
          clusters[:model_operations] << method_name
        else
          clusters[:utility_operations] << method_name
        end
      end
      
      # Remove empty clusters and add counts
      clusters.filter_map do |purpose, methods|
        next if methods.empty?
        
        [purpose, {
          count: methods.size,
          unique_methods: methods.uniq.size,
          methods: methods.uniq
        }]
      end.to_h
    end

    # Helper methods for pattern detection
    def extract_class_name(method_name)
      return nil unless method_name
      
      if method_name.include?('#')
        method_name.split('#')[0]
      elsif method_name.include?('::')
        parts = method_name.split('::')
        parts.size > 1 ? parts[0] : nil
      else
        nil
      end
    end

    def detect_controller_to_database_pattern(execution_traces)
      patterns = []
      
      execution_traces.each_cons(3).with_index do |triple, index|
        controller_trace, model_trace, db_trace = triple
        
        if controller_trace[:file]&.include?('/controllers/') &&
           model_trace[:file]&.include?('/models/') &&
           (db_trace[:source]&.match?(/SELECT|INSERT|UPDATE|DELETE/i) || db_trace[:method]&.include?('ActiveRecord'))
          
          patterns << {
            type: 'controller_model_database',
            start_index: index,
            controller_method: controller_trace[:method],
            model_method: model_trace[:method],
            database_operation: db_trace[:method]
          }
        end
      end
      
      patterns
    end

    def detect_service_patterns(execution_traces)
      patterns = []
      
      service_traces = execution_traces.select do |trace|
        trace[:file]&.include?('/services/') || 
        trace[:method]&.include?('Service') ||
        trace[:method]&.match?(/\w+Service/)
      end
      
      service_traces.each do |service_trace|
        patterns << {
          type: 'service_object',
          method: service_trace[:method],
          file: service_trace[:file]
        }
      end
      
      patterns
    end

    def detect_indirect_recursion(method_calls)
      indirect_patterns = []
      
      method_calls.each_with_index do |method, index|
        # Look for patterns like A -> B -> A or A -> B -> C -> A
        (2..5).each do |gap|
          next if index + gap >= method_calls.size
          
          if method_calls[index + gap] == method
            call_chain = method_calls[index..(index + gap)]
            if call_chain.uniq.size == call_chain.size - 1  # Only one repetition
              indirect_patterns << {
                pattern: call_chain,
                start_index: index,
                recursion_gap: gap
              }
            end
          end
        end
      end
      
      indirect_patterns
    end
  end
end