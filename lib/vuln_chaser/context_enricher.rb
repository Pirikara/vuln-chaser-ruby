module VulnChaser
  class ContextEnricher
    """
    Pattern-Free Execution Context Collection
    Gathers comprehensive runtime information without security pre-assessment
    Enables LLM to understand execution environment for creative analysis
    """
    
    def enrich_execution_context(trace_data, execution_traces)
      {
        application_context: extract_application_context,
        runtime_environment: collect_runtime_environment,
        execution_metadata: generate_execution_metadata(trace_data, execution_traces),
        raw_performance_data: collect_raw_performance_data(execution_traces)
      }
    end

    private

    def extract_application_context
      context = {}
      
      # Framework detection without security implications
      if defined?(Rails)
        context[:framework] = 'rails'
        context[:rails_version] = Rails.version if Rails.respond_to?(:version)
        context[:environment] = Rails.env if Rails.respond_to?(:env)
        context[:application_name] = Rails.application.class.module_parent.name if Rails.application
      end
      
      # Ruby runtime information
      context[:ruby_version] = RUBY_VERSION
      context[:ruby_platform] = RUBY_PLATFORM
      
      context
    end

    def collect_runtime_environment
      {
        gem_environment: collect_gem_information,
        load_path_info: $LOAD_PATH.length,
        thread_count: Thread.list.length,
        process_id: Process.pid,
        memory_usage: get_memory_usage,
        timestamp: Time.current.to_f
      }
    end

    def generate_execution_metadata(trace_data, execution_traces)
      {
        trace_id: trace_data[:trace_id],
        request_info: trace_data[:request_info],
        total_method_calls: execution_traces.length,
        unique_files: execution_traces.map { |t| t[:file] }.compact.uniq.length,
        unique_methods: execution_traces.map { |t| t[:method] }.compact.uniq.length,
        parameter_usage_count: execution_traces.count { |t| 
          t[:parameter_usage]&.dig(:uses_request_params) 
        },
        execution_duration: calculate_execution_duration(execution_traces),
        pattern_free_collection: true
      }
    end

    def collect_raw_performance_data(execution_traces)
      {
        total_execution_steps: execution_traces.length,
        average_source_length: calculate_average_source_length(execution_traces),
        method_distribution: calculate_method_distribution(execution_traces),
        file_distribution: calculate_file_distribution(execution_traces)
      }
    end

    def collect_gem_information
      {
        total_gems: Gem.loaded_specs.length,
        bundler_available: defined?(Bundler),
        security_gems: detect_security_related_gems
      }
    end

    def detect_security_related_gems
      security_keywords = %w[security auth authentication authorization encrypt decrypt sanitize]
      Gem.loaded_specs.keys.select do |gem_name|
        security_keywords.any? { |keyword| gem_name.downcase.include?(keyword) }
      end
    end

    def get_memory_usage
      begin
        `ps -o rss= -p #{Process.pid}`.to_i if RUBY_PLATFORM.include?('linux')
      rescue
        nil
      end
    end

    def calculate_execution_duration(execution_traces)
      return 0 if execution_traces.empty?
      
      begin
        first_trace = execution_traces.first
        last_trace = execution_traces.last
        
        # Handle various timestamp formats safely
        first_timestamp = extract_timestamp(first_trace)
        last_timestamp = extract_timestamp(last_trace)
        
        return 0 if first_timestamp.nil? || last_timestamp.nil?
        
        duration = last_timestamp - first_timestamp
        duration >= 0 ? duration : 0
      rescue => e
        # Return 0 on any timestamp calculation error
        0
      end
    end

    def calculate_average_source_length(execution_traces)
      return 0 if execution_traces.empty?
      
      total_length = execution_traces.sum { |t| (t[:source] || '').length }
      total_length / execution_traces.length.to_f
    end

    def calculate_method_distribution(execution_traces)
      method_counts = Hash.new(0)
      execution_traces.each do |trace|
        method_counts[trace[:method]] += 1 if trace[:method]
      end
      method_counts
    end

    def calculate_file_distribution(execution_traces)
      file_counts = Hash.new(0)
      execution_traces.each do |trace|
        file_counts[trace[:file]] += 1 if trace[:file]
      end
      file_counts
    end

    def extract_timestamp(trace)
      return nil unless trace

      timestamp = trace[:timestamp]
      return nil unless timestamp

      case timestamp
      when Numeric
        timestamp.to_f
      when String
        begin
          Time.parse(timestamp).to_f
        rescue
          Time.current.to_f
        end
      when Time
        timestamp.to_f
      else
        Time.current.to_f
      end
    rescue
      nil
    end
  end
end