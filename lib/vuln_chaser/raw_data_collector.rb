module VulnChaser
  class RawDataCollector
    """
    実行時の生データを構造化して収集（セキュリティ判定なし）
    LLMが包括的に分析できる形で情報を整理
    """
    
    def collect_execution_data(execution_traces)
      {
        code_structure: collect_code_structure(execution_traces),
        data_flow: collect_data_flow_info(execution_traces),
        external_interactions: collect_external_interactions(execution_traces),
        method_relationships: collect_method_relationships(execution_traces),
        variable_lineage: collect_variable_lineage(execution_traces)
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
          
          # 構造的情報（判定なし、事実のみ）
          method_calls: extract_method_calls(source_code),
          variable_assignments: extract_variable_assignments(source_code),
          string_operations: extract_string_operations(source_code),
          conditional_logic: extract_conditional_logic(source_code),
          external_references: extract_external_references(source_code),
          
          # パラメータ使用情報
          parameter_usage: trace[:parameter_usage] || {},
          local_variables: trace[:execution_context]&.dig(:local_variables) || [],
          instance_variables: trace[:execution_context]&.dig(:instance_variables) || []
        }
      end
    end

    def collect_external_interactions(execution_traces)
      interactions = []
      
      execution_traces.each_with_index do |trace, index|
        source_code = trace[:source] || ''
        
        # データベース操作の構造分析
        if contains_database_operations?(source_code)
          interactions << {
            step: index,
            type: 'database_interaction',
            method: trace[:method],
            query_structure: analyze_query_structure(source_code),
            parameter_bindings: analyze_parameter_bindings(source_code, trace),
            operation_type: infer_operation_type(source_code)
          }
        end
        
        # ファイルシステム操作
        if contains_file_operations?(source_code)
          interactions << {
            step: index,
            type: 'file_interaction',
            method: trace[:method],
            path_construction: analyze_path_construction(source_code),
            operation_type: infer_file_operation_type(source_code),
            access_patterns: analyze_access_patterns(source_code)
          }
        end
        
        # ネットワーク操作
        if contains_network_operations?(source_code)
          interactions << {
            step: index,
            type: 'network_interaction',
            method: trace[:method],
            url_construction: analyze_url_construction(source_code),
            request_structure: analyze_request_structure(source_code),
            protocol_usage: analyze_protocol_usage(source_code)
          }
        end
        
        # システムコマンド実行
        if contains_system_operations?(source_code)
          interactions << {
            step: index,
            type: 'system_interaction',
            method: trace[:method],
            command_structure: analyze_command_structure(source_code),
            argument_construction: analyze_argument_construction(source_code),
            execution_context: analyze_execution_context(source_code)
          }
        end
      end
      
      interactions
    end

    def collect_data_flow_info(execution_traces)
      data_flows = []
      
      execution_traces.each_with_index do |trace, index|
        param_usage = trace[:parameter_usage] || {}
        source_code = trace[:source] || ''
        
        if param_usage[:uses_request_params]
          data_flows << {
            step: index,
            flow_type: 'user_input_flow',
            method: trace[:method],
            input_sources: param_usage[:param_keys_used] || [],
            flow_operations: extract_data_transformations(source_code),
            output_destinations: identify_output_destinations(source_code)
          }
        end
      end
      
      data_flows
    end

    def collect_method_relationships(execution_traces)
      relationships = []
      
      execution_traces.each_cons(2).with_index do |pair, index|
        current_trace, next_trace = pair
        
        relationships << {
          caller_step: index,
          callee_step: index + 1,
          caller_method: current_trace[:method],
          callee_method: next_trace[:method],
          call_context: analyze_call_context(current_trace, next_trace),
          data_passing: analyze_data_passing(current_trace, next_trace)
        }
      end
      
      relationships
    end

    def collect_variable_lineage(execution_traces)
      lineage = {}
      
      execution_traces.each_with_index do |trace, index|
        local_vars = trace[:execution_context]&.dig(:local_variables) || []
        instance_vars = trace[:execution_context]&.dig(:instance_variables) || []
        
        local_vars.each do |var|
          lineage[var] ||= []
          lineage[var] << {
            step: index,
            method: trace[:method],
            scope: 'local',
            usage_context: extract_variable_usage_context(trace[:source], var)
          }
        end
        
        instance_vars.each do |var|
          lineage[var] ||= []
          lineage[var] << {
            step: index,
            method: trace[:method],
            scope: 'instance',
            usage_context: extract_variable_usage_context(trace[:source], var)
          }
        end
      end
      
      lineage
    end

    def extract_string_operations(source_code)
      {
        interpolations: extract_interpolations(source_code),
        concatenations: extract_concatenations(source_code),
        format_operations: extract_format_operations(source_code),
        transformations: extract_string_transformations(source_code)
      }
    end

    # 構造的特徴の検出（セキュリティ判定なし）
    def contains_database_operations?(source_code)
      # SQL keywords or ActiveRecord methods presence
      sql_indicators = %w[SELECT INSERT UPDATE DELETE FROM WHERE JOIN]
      activerecord_indicators = %w[find find_by where create update destroy save execute]
      
      sql_indicators.any? { |kw| source_code.upcase.include?(kw) } ||
      activerecord_indicators.any? { |method| source_code.include?("#{method}(") || source_code.include?(".#{method}") }
    end
    
    def contains_file_operations?(source_code)
      file_indicators = %w[File.open File.read File.write open read write]
      file_indicators.any? { |op| source_code.include?(op) }
    end
    
    def contains_network_operations?(source_code)
      network_indicators = %w[Net::HTTP HTTParty RestClient Faraday]
      network_indicators.any? { |lib| source_code.include?(lib) }
    end
    
    def contains_system_operations?(source_code)
      system_indicators = ['system(', 'exec(', 'spawn(', '`', 'Open3']
      system_indicators.any? { |op| source_code.include?(op) }
    end

    # Helper methods for detailed analysis
    def extract_method_calls(source_code)
      # Extract method call patterns
      method_calls = []
      
      # Method calls with parentheses
      source_code.scan(/(\w+)\s*\([^)]*\)/) do |match|
        method_calls << { name: match[0], type: 'method_with_args' }
      end
      
      # Method calls with dot notation
      source_code.scan(/(\w+)\.(\w+)/) do |receiver, method|
        method_calls << { receiver: receiver, name: method, type: 'dot_notation' }
      end
      
      method_calls
    end

    def extract_variable_assignments(source_code)
      assignments = []
      
      # Simple assignments
      source_code.scan(/(\w+)\s*=\s*([^=\n]+)/) do |var, value|
        assignments << { variable: var, value: value.strip, type: 'assignment' }
      end
      
      assignments
    end

    def extract_conditional_logic(source_code)
      conditionals = []
      
      # If statements
      if source_code.include?('if ')
        conditionals << { type: 'if_statement', context: 'conditional_execution' }
      end
      
      # Case statements
      if source_code.include?('case ')
        conditionals << { type: 'case_statement', context: 'multi_branch' }
      end
      
      # Ternary operators
      if source_code.include?(' ? ')
        conditionals << { type: 'ternary_operator', context: 'inline_conditional' }
      end
      
      conditionals
    end

    def extract_external_references(source_code)
      references = []
      
      # Constant references
      source_code.scan(/([A-Z][A-Za-z0-9_]*(?:::[A-Za-z0-9_]+)*)/) do |const|
        references << { type: 'constant', name: const[0] }
      end
      
      # Global variables
      source_code.scan(/(\$\w+)/) do |global|
        references << { type: 'global_variable', name: global[0] }
      end
      
      references
    end

    def extract_interpolations(source_code)
      interpolations = []
      
      source_code.scan(/#\{([^}]+)\}/) do |content|
        interpolations << { content: content[0], type: 'string_interpolation' }
      end
      
      interpolations
    end

    def extract_concatenations(source_code)
      concatenations = []
      
      # String concatenation with +
      if source_code.include?(' + ')
        concatenations << { type: 'plus_operator', context: 'string_concat' }
      end
      
      # String concatenation with <<
      if source_code.include?(' << ')
        concatenations << { type: 'append_operator', context: 'string_append' }
      end
      
      concatenations
    end

    def extract_format_operations(source_code)
      formats = []
      
      # String formatting with %
      if source_code.include?(' % ')
        formats << { type: 'percent_formatting', context: 'string_format' }
      end
      
      # String formatting with sprintf
      if source_code.include?('sprintf')
        formats << { type: 'sprintf_formatting', context: 'printf_style' }
      end
      
      formats
    end

    def extract_string_transformations(source_code)
      transformations = []
      
      string_methods = %w[upcase downcase strip gsub sub chomp]
      string_methods.each do |method|
        if source_code.include?(".#{method}")
          transformations << { method: method, type: 'string_transformation' }
        end
      end
      
      transformations
    end

    def analyze_query_structure(source_code)
      structure = {}
      
      # Identify SQL query components
      if source_code.upcase.include?('SELECT')
        structure[:type] = 'select'
      elsif source_code.upcase.include?('INSERT')
        structure[:type] = 'insert'
      elsif source_code.upcase.include?('UPDATE')
        structure[:type] = 'update'
      elsif source_code.upcase.include?('DELETE')
        structure[:type] = 'delete'
      end
      
      # Check for WHERE clauses
      if source_code.upcase.include?('WHERE')
        structure[:has_where_clause] = true
      end
      
      # Check for JOIN operations
      if source_code.upcase.include?('JOIN')
        structure[:has_joins] = true
      end
      
      structure
    end

    def analyze_parameter_bindings(source_code, trace)
      bindings = {}
      param_usage = trace[:parameter_usage] || {}
      
      if param_usage[:uses_request_params]
        bindings[:uses_external_params] = true
        bindings[:param_keys] = param_usage[:param_keys_used] || []
        bindings[:interpolation_style] = param_usage[:direct_interpolation] ? 'direct' : 'safe'
      end
      
      bindings
    end

    def infer_operation_type(source_code)
      if source_code.upcase.include?('SELECT') || source_code.include?('.find')
        'read'
      elsif source_code.upcase.include?('INSERT') || source_code.include?('.create')
        'create'
      elsif source_code.upcase.include?('UPDATE') || source_code.include?('.update')
        'update'
      elsif source_code.upcase.include?('DELETE') || source_code.include?('.destroy')
        'delete'
      else
        'unknown'
      end
    end

    def analyze_path_construction(source_code)
      path_info = {}
      
      # Check for path concatenation
      if source_code.include?('File.join')
        path_info[:construction_method] = 'file_join'
      elsif source_code.include?(' + ')
        path_info[:construction_method] = 'string_concat'
      elsif source_code.include?('#{')
        path_info[:construction_method] = 'interpolation'
      end
      
      path_info
    end

    def infer_file_operation_type(source_code)
      if source_code.include?('.read') || source_code.include?('File.read')
        'read'
      elsif source_code.include?('.write') || source_code.include?('File.write')
        'write'
      elsif source_code.include?('.delete') || source_code.include?('File.delete')
        'delete'
      elsif source_code.include?('.open') || source_code.include?('File.open')
        'open'
      else
        'unknown'
      end
    end

    def analyze_access_patterns(source_code)
      patterns = []
      
      # Check for path traversal patterns
      if source_code.include?('../')
        patterns << 'relative_path'
      end
      
      # Check for absolute paths
      if source_code.include?('/')
        patterns << 'absolute_path'
      end
      
      patterns
    end

    def analyze_url_construction(source_code)
      url_info = {}
      
      # Check for URL building
      if source_code.include?('#{')
        url_info[:construction_method] = 'interpolation'
      elsif source_code.include?(' + ')
        url_info[:construction_method] = 'concatenation'
      end
      
      url_info
    end

    def analyze_request_structure(source_code)
      request_info = {}
      
      # Check for HTTP methods
      http_methods = %w[GET POST PUT DELETE PATCH]
      http_methods.each do |method|
        if source_code.upcase.include?(method)
          request_info[:http_method] = method
          break
        end
      end
      
      request_info
    end

    def analyze_protocol_usage(source_code)
      protocols = []
      
      if source_code.include?('https://')
        protocols << 'https'
      elsif source_code.include?('http://')
        protocols << 'http'
      end
      
      if source_code.include?('ftp://')
        protocols << 'ftp'
      end
      
      protocols
    end

    def analyze_command_structure(source_code)
      command_info = {}
      
      # Check for command execution methods
      if source_code.include?('system(')
        command_info[:execution_method] = 'system'
      elsif source_code.include?('exec(')
        command_info[:execution_method] = 'exec'
      elsif source_code.include?('spawn(')
        command_info[:execution_method] = 'spawn'
      elsif source_code.include?('`')
        command_info[:execution_method] = 'backticks'
      end
      
      command_info
    end

    def analyze_argument_construction(source_code)
      args_info = {}
      
      # Check for argument interpolation
      if source_code.include?('#{')
        args_info[:construction_method] = 'interpolation'
      elsif source_code.include?(' + ')
        args_info[:construction_method] = 'concatenation'
      end
      
      args_info
    end

    def analyze_execution_context(source_code)
      context_info = {}
      
      # Check for shell execution
      if source_code.include?('sh ') || source_code.include?('bash ')
        context_info[:shell_type] = 'bash'
      end
      
      context_info
    end

    def extract_data_transformations(source_code)
      transformations = []
      
      # String transformations
      transform_methods = %w[upcase downcase strip gsub sub]
      transform_methods.each do |method|
        if source_code.include?(".#{method}")
          transformations << { type: 'string_transform', method: method }
        end
      end
      
      # Encoding transformations
      if source_code.include?('.encode')
        transformations << { type: 'encoding_transform', method: 'encode' }
      end
      
      transformations
    end

    def identify_output_destinations(source_code)
      destinations = []
      
      # Database output
      if contains_database_operations?(source_code)
        destinations << 'database'
      end
      
      # File output
      if contains_file_operations?(source_code)
        destinations << 'file_system'
      end
      
      # Network output
      if contains_network_operations?(source_code)
        destinations << 'network'
      end
      
      # System output
      if contains_system_operations?(source_code)
        destinations << 'system'
      end
      
      destinations
    end

    def analyze_call_context(current_trace, next_trace)
      context = {}
      
      current_method = current_trace[:method]
      next_method = next_trace[:method]
      
      context[:caller] = current_method
      context[:callee] = next_method
      context[:file_transition] = current_trace[:file] != next_trace[:file]
      
      context
    end

    def analyze_data_passing(current_trace, next_trace)
      data_passing = {}
      
      current_vars = current_trace[:execution_context]&.dig(:local_variables) || []
      next_vars = next_trace[:execution_context]&.dig(:local_variables) || []
      
      # Check for variable sharing/passing
      shared_vars = current_vars & next_vars
      data_passing[:shared_variables] = shared_vars
      data_passing[:variable_count_change] = next_vars.size - current_vars.size
      
      data_passing
    end

    def extract_variable_usage_context(source_code, variable)
      context = {}
      
      if source_code && source_code.include?(variable)
        context[:appears_in_source] = true
        
        # Check usage patterns
        if source_code.include?("#{variable} =")
          context[:usage_type] = 'assignment'
        elsif source_code.include?("#{variable}.")
          context[:usage_type] = 'method_call'
        elsif source_code.include?("#{variable}[")
          context[:usage_type] = 'array_access'
        else
          context[:usage_type] = 'reference'
        end
      else
        context[:appears_in_source] = false
      end
      
      context
    end
  end
end