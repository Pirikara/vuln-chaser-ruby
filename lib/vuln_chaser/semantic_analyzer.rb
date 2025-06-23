module VulnChaser
  class SemanticAnalyzer
    """
    Pattern-Free Raw Data Collection for LLM Analysis
    Collects execution data without pattern-based classification
    Enables LLM to perform creative, unrestricted security analysis
    """
    
    def analyze_semantic_structure(execution_traces)
      {
        execution_sequence: collect_execution_sequence(execution_traces),
        data_flow_context: collect_data_flow_context(execution_traces),
        method_relationships: collect_method_relationships(execution_traces),
        raw_execution_metadata: collect_raw_metadata(execution_traces)
      }
    end

    private

    def collect_execution_sequence(execution_traces)
      sequence_data = []
      
      execution_traces.each_with_index do |trace, index|
        # Raw execution data without pattern-based analysis
        execution_step = {
          step: index,
          method_name: trace[:method],
          source_code: trace[:source] || '',
          file_location: "#{trace[:file]}:#{trace[:line]}",
          local_variables: trace[:execution_context]&.dig(:local_variables) || [],
          instance_variables: trace[:execution_context]&.dig(:instance_variables) || [],
          parameter_usage: trace[:parameter_usage] || {}
        }
        
        sequence_data << execution_step
      end
      
      sequence_data
    end

    def collect_data_flow_context(execution_traces)
      data_flows = []
      
      execution_traces.each_with_index do |trace, index|
        param_usage = trace[:parameter_usage] || {}
        
        # Raw data flow information without classification
        if param_usage[:uses_request_params]
          data_flows << {
            step: index,
            method: trace[:method],
            source_code: trace[:source] || '',
            parameter_usage: param_usage,
            data_sources: param_usage[:param_keys_used] || [],
            execution_context: trace[:execution_context] || {}
          }
        end
      end
      
      data_flows
    end

    def collect_method_relationships(execution_traces)
      relationships = []
      
      execution_traces.each_with_index do |trace, index|
        next_trace = execution_traces[index + 1]
        
        if next_trace
          relationships << {
            from_step: index,
            to_step: index + 1,
            from_method: trace[:method],
            to_method: next_trace[:method],
            from_source: trace[:source] || '',
            to_source: next_trace[:source] || '',
            data_passed: trace[:parameter_usage] || {}
          }
        end
      end
      
      relationships
    end

    def collect_raw_metadata(execution_traces)
      {
        total_steps: execution_traces.length,
        methods_called: execution_traces.map { |trace| trace[:method] }.compact,
        files_involved: execution_traces.map { |trace| trace[:file] }.compact.uniq,
        parameter_usage_count: execution_traces.count { |trace| 
          trace[:parameter_usage]&.dig(:uses_request_params) 
        },
        execution_start_time: Time.current.to_f,
        trace_collection_metadata: {
          pattern_free_collection: true,
          llm_ready_format: true,
          no_predefined_classifications: true
        }
      }
    end
  end
end