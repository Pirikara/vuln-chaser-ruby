module VulnChaser
  class RawDataCollector
    """
    Pattern-Free Raw Execution Data Collection
    Collects comprehensive execution information without pattern-based filtering
    Enables LLM to perform unrestricted creative security analysis
    """
    
    def collect_execution_data(execution_traces)
      {
        code_structure: collect_code_structure(execution_traces),
        data_flow: collect_data_flow_info(execution_traces),
        execution_context: collect_execution_context(execution_traces),
        method_chain: collect_method_chain(execution_traces),
        raw_metadata: collect_raw_metadata(execution_traces)
      }
    end

    private

    def collect_code_structure(execution_traces)
      execution_traces.map.with_index do |trace, index|
        source_code = trace[:source] || ''
        
        {
          step: index,
          method_signature: trace[:method],
          source_code: source_code,
          file_path: trace[:file],
          line_number: trace[:line],
          
          # Raw execution information without pattern-based classification
          parameter_usage: trace[:parameter_usage] || {},
          local_variables: trace[:execution_context]&.dig(:local_variables) || [],
          instance_variables: trace[:execution_context]&.dig(:instance_variables) || [],
          
          # Basic structural information (no security classification)
          source_length: source_code.length,
          source_lines: source_code.lines.count,
          contains_string_interpolation: source_code.include?('#{'),
          contains_parameters: !!(trace[:parameter_usage]&.dig(:uses_request_params))
        }
      end
    end

    def collect_data_flow_info(execution_traces)
      flows = []
      
      execution_traces.each_with_index do |trace, index|
        param_usage = trace[:parameter_usage] || {}
        
        # Collect all data flow without security assessment
        if param_usage[:uses_request_params]
          flows << {
            step: index,
            method: trace[:method],
            source_code: trace[:source] || '',
            parameter_keys: param_usage[:param_keys_used] || [],
            direct_interpolation: param_usage[:direct_interpolation] || false,
            sanitization_detected: param_usage[:sanitization_detected] || false,
            execution_context: trace[:execution_context] || {}
          }
        end
      end
      
      flows
    end

    def collect_execution_context(execution_traces)
      execution_traces.map.with_index do |trace, index|
        {
          step: index,
          method_name: trace[:method],
          file_location: "#{trace[:file]}:#{trace[:line]}",
          source_code: trace[:source] || '',
          local_variables: trace[:execution_context]&.dig(:local_variables) || [],
          instance_variables: trace[:execution_context]&.dig(:instance_variables) || [],
          parameter_usage: trace[:parameter_usage] || {},
          resource_context: trace[:resource_context] || {}
        }
      end
    end

    def collect_method_chain(execution_traces)
      chain = []
      
      execution_traces.each_with_index do |trace, index|
        previous_trace = index > 0 ? execution_traces[index - 1] : nil
        next_trace = execution_traces[index + 1]
        
        chain << {
          step: index,
          current_method: trace[:method],
          previous_method: previous_trace&.dig(:method),
          next_method: next_trace&.dig(:method),
          current_source: trace[:source] || '',
          parameter_flow: trace[:parameter_usage] || {}
        }
      end
      
      chain
    end

    def collect_raw_metadata(execution_traces)
      {
        total_execution_steps: execution_traces.length,
        unique_methods: execution_traces.map { |t| t[:method] }.compact.uniq,
        unique_files: execution_traces.map { |t| t[:file] }.compact.uniq,
        parameter_usage_steps: execution_traces.count { |t| 
          t[:parameter_usage]&.dig(:uses_request_params) 
        },
        direct_interpolation_steps: execution_traces.count { |t| 
          t[:parameter_usage]&.dig(:direct_interpolation) 
        },
        sanitization_detected_steps: execution_traces.count { |t| 
          t[:parameter_usage]&.dig(:sanitization_detected) 
        },
        collection_timestamp: Time.current.to_f,
        pattern_free_collection: true,
        llm_analysis_ready: true
      }
    end
  end
end