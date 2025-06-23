module VulnChaser
  class SemanticAnalyzer
    """
    コードの意味構造を分析（セキュリティ判定なし）
    LLMが文脈を理解できるよう情報を構造化
    """
    
    def analyze_semantic_structure(execution_traces)
      {
        control_flow: analyze_control_flow(execution_traces),
        data_dependencies: analyze_data_dependencies(execution_traces),
        trust_boundaries: identify_trust_boundaries(execution_traces),
        business_logic_flow: analyze_business_logic_flow(execution_traces)
      }
    end

    private

    def analyze_control_flow(execution_traces)
      flow_patterns = []
      
      execution_traces.each_with_index do |trace, index|
        source_code = trace[:source] || ''
        
        # Control flow structures
        flow_info = {
          step: index,
          method: trace[:method],
          flow_type: determine_flow_type(source_code),
          complexity: assess_complexity(source_code),
          decision_points: identify_decision_points(source_code),
          loop_structures: identify_loop_structures(source_code)
        }
        
        flow_patterns << flow_info
      end
      
      flow_patterns
    end

    def analyze_data_dependencies(execution_traces)
      dependencies = []
      
      execution_traces.each_with_index do |trace, index|
        param_usage = trace[:parameter_usage] || {}
        source_code = trace[:source] || ''
        
        if param_usage[:uses_request_params]
          dependencies << {
            step: index,
            dependency_type: 'user_input_dependency',
            method: trace[:method],
            param_keys: param_usage[:param_keys_used] || [],
            usage_context: analyze_usage_context(source_code, param_usage),
            data_flow: trace_data_flow(source_code, param_usage)
          }
        end
        
        # Variable dependencies
        local_vars = trace[:execution_context]&.dig(:local_variables) || []
        if local_vars.any?
          dependencies << {
            step: index,
            dependency_type: 'variable_dependency',
            method: trace[:method],
            variables: local_vars,
            scope_context: analyze_scope_context(trace)
          }
        end
      end
      
      dependencies
    end

    def identify_trust_boundaries(execution_traces)
      boundaries = []
      
      execution_traces.each_with_index do |trace, index|
        source_code = trace[:source] || ''
        
        # Identify potential trust boundary crossings
        if crosses_trust_boundary?(trace)
          boundaries << {
            step: index,
            boundary_type: classify_boundary_type(trace),
            method: trace[:method],
            context: extract_boundary_context(trace),
            data_flow: analyze_boundary_data_flow(trace)
          }
        end
      end
      
      boundaries
    end

    def analyze_business_logic_flow(execution_traces)
      {
        authentication_flow: identify_authentication_flow(execution_traces),
        authorization_flow: identify_authorization_flow(execution_traces),
        data_processing_flow: identify_data_processing_flow(execution_traces),
        transaction_flow: identify_transaction_flow(execution_traces)
      }
    end

    # Control flow analysis helpers
    def determine_flow_type(source_code)
      flow_types = []
      
      # Sequential flow (default)
      flow_types << 'sequential'
      
      # Conditional flow
      if source_code.match?(/\bif\b|\bcase\b|\bunless\b|\?.*:/)
        flow_types << 'conditional'
      end
      
      # Loop flow
      if source_code.match?(/\bfor\b|\bwhile\b|\beach\b|\bloop\b|\btimes\b/)
        flow_types << 'iterative'
      end
      
      # Exception handling flow
      if source_code.match?(/\bbegin\b|\brescue\b|\bensure\b|\braise\b/)
        flow_types << 'exception_handling'
      end
      
      # Method invocation flow
      if source_code.include?('.')
        flow_types << 'method_invocation'
      end
      
      flow_types
    end

    def assess_complexity(source_code)
      complexity_score = 1  # Base complexity
      
      # Add complexity for each control structure
      complexity_score += source_code.scan(/\bif\b/).length
      complexity_score += source_code.scan(/\bcase\b/).length
      complexity_score += source_code.scan(/\bwhile\b/).length
      complexity_score += source_code.scan(/\bfor\b/).length
      complexity_score += source_code.scan(/\beach\b/).length
      complexity_score += source_code.scan(/\band\b|\bor\b|\&\&|\|\|/).length
      
      case complexity_score
      when 1..3
        'low'
      when 4..7
        'medium'
      when 8..15
        'high'
      else
        'very_high'
      end
    end

    def identify_decision_points(source_code)
      decision_points = []
      
      # If statements
      source_code.scan(/\bif\s+([^then\n]+)/) do |condition|
        decision_points << {
          type: 'if_condition',
          condition: condition[0].strip,
          complexity: assess_condition_complexity(condition[0])
        }
      end
      
      # Case statements
      if source_code.include?('case ')
        decision_points << {
          type: 'case_statement',
          complexity: 'medium'
        }
      end
      
      # Ternary operators
      source_code.scan(/([^?]+)\?\s*([^:]+):\s*([^,\n]+)/) do |condition, true_val, false_val|
        decision_points << {
          type: 'ternary',
          condition: condition.strip,
          true_branch: true_val.strip,
          false_branch: false_val.strip,
          complexity: 'low'
        }
      end
      
      decision_points
    end

    def identify_loop_structures(source_code)
      loops = []
      
      # Each loops
      if source_code.include?('.each')
        loops << { type: 'each_loop', iteration_type: 'collection' }
      end
      
      # Times loops
      if source_code.include?('.times')
        loops << { type: 'times_loop', iteration_type: 'numeric' }
      end
      
      # While loops
      if source_code.include?('while ')
        loops << { type: 'while_loop', iteration_type: 'conditional' }
      end
      
      # For loops
      if source_code.include?('for ')
        loops << { type: 'for_loop', iteration_type: 'range' }
      end
      
      loops
    end

    def assess_condition_complexity(condition)
      # Count logical operators
      logical_ops = condition.scan(/\band\b|\bor\b|\&\&|\|\|/).length
      
      case logical_ops
      when 0
        'simple'
      when 1..2
        'moderate'
      else
        'complex'
      end
    end

    # Data dependency analysis helpers
    def analyze_usage_context(source_code, param_usage)
      context = {}
      
      # Parameter usage patterns
      context[:direct_usage] = param_usage[:direct_interpolation] || false
      context[:sanitization_present] = param_usage[:sanitization_detected] || false
      
      # Usage in different contexts
      context[:used_in_query] = source_code.match?(/SELECT|INSERT|UPDATE|DELETE|WHERE/i)
      context[:used_in_command] = source_code.match?(/system|exec|spawn|`/)
      context[:used_in_file_op] = source_code.match?(/File\.|open|read|write/)
      context[:used_in_eval] = source_code.match?(/eval|instance_eval|class_eval/)
      
      # Transformation before usage
      context[:transformed_before_use] = detect_transformations(source_code)
      
      context
    end

    def trace_data_flow(source_code, param_usage)
      flow_steps = []
      
      # Input source
      if param_usage[:uses_request_params]
        flow_steps << {
          stage: 'input',
          source: 'user_parameters',
          data_keys: param_usage[:param_keys_used] || []
        }
      end
      
      # Processing stages
      if source_code.include?('.strip') || source_code.include?('.chomp')
        flow_steps << {
          stage: 'processing',
          operation: 'whitespace_cleanup',
          methods: extract_processing_methods(source_code)
        }
      end
      
      if source_code.include?('.gsub') || source_code.include?('.sub')
        flow_steps << {
          stage: 'processing',
          operation: 'string_substitution',
          methods: extract_substitution_methods(source_code)
        }
      end
      
      # Output destination
      output_dest = determine_output_destination(source_code)
      if output_dest
        flow_steps << {
          stage: 'output',
          destination: output_dest,
          method: extract_output_method(source_code)
        }
      end
      
      flow_steps
    end

    def analyze_scope_context(trace)
      context = {}
      
      # Method scope
      method_name = trace[:method]
      context[:method_scope] = {
        name: method_name,
        visibility: infer_method_visibility(method_name),
        type: classify_method_type(method_name)
      }
      
      # Class scope
      if method_name.include?('#')
        class_name = method_name.split('#')[0]
        context[:class_scope] = {
          name: class_name,
          type: classify_class_type(class_name)
        }
      end
      
      # File scope
      file_path = trace[:file]
      context[:file_scope] = {
        path: file_path,
        type: classify_file_type(file_path)
      }
      
      context
    end

    # Trust boundary analysis helpers
    def crosses_trust_boundary?(trace)
      method_name = trace[:method]
      source_code = trace[:source] || ''
      param_usage = trace[:parameter_usage] || {}
      
      # External input reaches internal processing
      return true if param_usage[:uses_request_params] && involves_sensitive_operation?(source_code)
      
      # Method calls that typically cross boundaries
      boundary_indicators = [
        'controller', 'action', 'authenticate', 'authorize',
        'validate', 'sanitize', 'filter', 'transform'
      ]
      
      boundary_indicators.any? { |indicator| method_name.downcase.include?(indicator) }
    end

    def classify_boundary_type(trace)
      method_name = trace[:method]
      source_code = trace[:source] || ''
      
      if method_name.downcase.include?('controller')
        'web_interface_boundary'
      elsif method_name.downcase.include?('authenticate')
        'authentication_boundary'
      elsif method_name.downcase.include?('authorize')
        'authorization_boundary'
      elsif involves_database_operation?(source_code)
        'data_persistence_boundary'
      elsif involves_external_service?(source_code)
        'external_service_boundary'
      else
        'internal_processing_boundary'
      end
    end

    def extract_boundary_context(trace)
      context = {}
      
      context[:method] = trace[:method]
      context[:file] = trace[:file]
      context[:line] = trace[:line]
      
      # Input characteristics
      param_usage = trace[:parameter_usage] || {}
      context[:accepts_external_input] = param_usage[:uses_request_params] || false
      context[:input_validation] = param_usage[:sanitization_detected] || false
      
      # Output characteristics
      source_code = trace[:source] || ''
      context[:generates_output] = !determine_output_destination(source_code).nil?
      context[:output_encoding] = detect_output_encoding(source_code)
      
      context
    end

    def analyze_boundary_data_flow(trace)
      source_code = trace[:source] || ''
      param_usage = trace[:parameter_usage] || {}
      
      flow_analysis = {}
      
      # Input flow
      if param_usage[:uses_request_params]
        flow_analysis[:input_flow] = {
          source: 'external_parameters',
          validation: param_usage[:sanitization_detected],
          direct_usage: param_usage[:direct_interpolation]
        }
      end
      
      # Processing flow
      flow_analysis[:processing] = {
        transformations: detect_transformations(source_code),
        validations: detect_validations(source_code),
        sanitizations: detect_sanitizations(source_code)
      }
      
      # Output flow
      output_dest = determine_output_destination(source_code)
      if output_dest
        flow_analysis[:output_flow] = {
          destination: output_dest,
          encoding: detect_output_encoding(source_code),
          escaping: detect_output_escaping(source_code)
        }
      end
      
      flow_analysis
    end

    # Business logic flow analysis
    def identify_authentication_flow(execution_traces)
      auth_traces = execution_traces.select do |trace|
        method_name = trace[:method]
        auth_keywords = %w[authenticate login sign_in current_user session]
        auth_keywords.any? { |keyword| method_name.downcase.include?(keyword) }
      end
      
      auth_traces.map.with_index do |trace, index|
        {
          step: index,
          method: trace[:method],
          auth_type: classify_auth_type(trace[:method]),
          session_usage: uses_session?(trace[:source]),
          credential_handling: analyze_credential_handling(trace[:source])
        }
      end
    end

    def identify_authorization_flow(execution_traces)
      authz_traces = execution_traces.select do |trace|
        method_name = trace[:method]
        authz_keywords = %w[authorize can? cannot? ability permission role]
        authz_keywords.any? { |keyword| method_name.downcase.include?(keyword) }
      end
      
      authz_traces.map.with_index do |trace, index|
        {
          step: index,
          method: trace[:method],
          authz_type: classify_authz_type(trace[:method]),
          resource_check: analyze_resource_check(trace[:source]),
          permission_model: infer_permission_model(trace[:source])
        }
      end
    end

    def identify_data_processing_flow(execution_traces)
      data_traces = execution_traces.select do |trace|
        param_usage = trace[:parameter_usage] || {}
        param_usage[:uses_request_params] || involves_data_operation?(trace[:source])
      end
      
      data_traces.map.with_index do |trace, index|
        {
          step: index,
          method: trace[:method],
          data_sources: identify_data_sources(trace),
          processing_operations: extract_processing_operations(trace[:source]),
          data_destinations: identify_data_destinations(trace[:source])
        }
      end
    end

    def identify_transaction_flow(execution_traces)
      transaction_traces = execution_traces.select do |trace|
        source_code = trace[:source] || ''
        transaction_keywords = %w[transaction begin commit rollback save! create! update! destroy!]
        transaction_keywords.any? { |keyword| source_code.include?(keyword) }
      end
      
      transaction_traces.map.with_index do |trace, index|
        {
          step: index,
          method: trace[:method],
          transaction_type: classify_transaction_type(trace[:source]),
          atomicity: analyze_atomicity(trace[:source]),
          error_handling: analyze_error_handling(trace[:source])
        }
      end
    end

    # Helper methods for detailed analysis
    def detect_transformations(source_code)
      transformations = []
      
      string_transforms = %w[upcase downcase capitalize strip chomp squeeze]
      string_transforms.each do |transform|
        if source_code.include?(".#{transform}")
          transformations << { type: 'string_transformation', method: transform }
        end
      end
      
      # Encoding transformations
      if source_code.include?('.encode')
        transformations << { type: 'encoding_transformation', method: 'encode' }
      end
      
      # Custom transformations
      if source_code.include?('.gsub') || source_code.include?('.sub')
        transformations << { type: 'pattern_replacement', method: 'substitution' }
      end
      
      transformations
    end

    def extract_processing_methods(source_code)
      methods = []
      
      processing_patterns = %w[strip chomp squeeze]
      processing_patterns.each do |pattern|
        if source_code.include?(".#{pattern}")
          methods << pattern
        end
      end
      
      methods
    end

    def extract_substitution_methods(source_code)
      methods = []
      
      if source_code.include?('.gsub')
        methods << 'gsub'
      end
      
      if source_code.include?('.sub')
        methods << 'sub'
      end
      
      methods
    end

    def determine_output_destination(source_code)
      if source_code.match?(/SELECT|INSERT|UPDATE|DELETE/i)
        'database'
      elsif source_code.match?(/File\.|open.*write|puts.*file/i)
        'file_system'
      elsif source_code.match?(/Net::HTTP|HTTParty|RestClient/i)
        'network'
      elsif source_code.match?(/system|exec|spawn|`/)
        'system_command'
      elsif source_code.include?('render') || source_code.include?('redirect')
        'web_response'
      else
        nil
      end
    end

    def extract_output_method(source_code)
      if source_code.include?('render')
        'render'
      elsif source_code.include?('redirect')
        'redirect'
      elsif source_code.include?('puts')
        'puts'
      elsif source_code.include?('print')
        'print'
      else
        'unknown'
      end
    end

    def infer_method_visibility(method_name)
      if method_name.start_with?('_') || method_name.include?('private')
        'private'
      elsif method_name.include?('protected')
        'protected'
      else
        'public'
      end
    end

    def classify_method_type(method_name)
      if method_name.include?('Controller')
        'controller_action'
      elsif method_name.include?('Model') || method_name.include?('#')
        'model_method'
      elsif method_name.include?('Helper')
        'view_helper'
      elsif method_name.include?('Service')
        'service_method'
      else
        'utility_method'
      end
    end

    def classify_class_type(class_name)
      if class_name.end_with?('Controller')
        'controller'
      elsif class_name.end_with?('Model')
        'model'
      elsif class_name.end_with?('Helper')
        'helper'
      elsif class_name.end_with?('Service')
        'service'
      else
        'utility'
      end
    end

    def classify_file_type(file_path)
      if file_path.include?('/controllers/')
        'controller'
      elsif file_path.include?('/models/')
        'model'
      elsif file_path.include?('/views/')
        'view'
      elsif file_path.include?('/helpers/')
        'helper'
      elsif file_path.include?('/services/')
        'service'
      elsif file_path.include?('/lib/')
        'library'
      else
        'other'
      end
    end

    def involves_sensitive_operation?(source_code)
      sensitive_patterns = [
        /SELECT|INSERT|UPDATE|DELETE/i,
        /system|exec|spawn|`/,
        /File\.|open|read|write/,
        /eval|instance_eval|class_eval/,
        /Net::HTTP|HTTParty|RestClient/i
      ]
      
      sensitive_patterns.any? { |pattern| source_code.match?(pattern) }
    end

    def involves_database_operation?(source_code)
      source_code.match?(/SELECT|INSERT|UPDATE|DELETE|find|where|create|save|destroy/i)
    end

    def involves_external_service?(source_code)
      source_code.match?(/Net::HTTP|HTTParty|RestClient|Faraday|HTTP/i)
    end

    def detect_output_encoding(source_code)
      if source_code.include?('.html_safe') || source_code.include?('html_escape')
        'html_encoded'
      elsif source_code.include?('.to_json')
        'json_encoded'
      elsif source_code.include?('.encode')
        'custom_encoded'
      else
        'none'
      end
    end

    def detect_validations(source_code)
      validations = []
      
      validation_patterns = %w[validates? valid? validate]
      validation_patterns.each do |pattern|
        if source_code.include?(pattern)
          validations << pattern
        end
      end
      
      validations
    end

    def detect_sanitizations(source_code)
      sanitizations = []
      
      sanitization_patterns = %w[sanitize strip_tags escape_html permit]
      sanitization_patterns.each do |pattern|
        if source_code.include?(pattern)
          sanitizations << pattern
        end
      end
      
      sanitizations
    end

    def detect_output_escaping(source_code)
      if source_code.include?('html_escape') || source_code.include?('escape_html')
        'html_escaped'
      elsif source_code.include?('sql_escape') || source_code.include?('quote')
        'sql_escaped'
      elsif source_code.include?('shell_escape')
        'shell_escaped'
      else
        'none'
      end
    end

    def classify_auth_type(method_name)
      if method_name.downcase.include?('session')
        'session_based'
      elsif method_name.downcase.include?('token')
        'token_based'
      elsif method_name.downcase.include?('oauth')
        'oauth'
      elsif method_name.downcase.include?('basic')
        'basic_auth'
      else
        'custom'
      end
    end

    def uses_session?(source_code)
      source_code&.include?('session') || false
    end

    def analyze_credential_handling(source_code)
      handling = {}
      
      if source_code&.include?('password')
        handling[:handles_passwords] = true
      end
      
      if source_code&.include?('token')
        handling[:handles_tokens] = true
      end
      
      if source_code&.include?('encrypt') || source_code&.include?('hash')
        handling[:uses_encryption] = true
      end
      
      handling
    end

    def classify_authz_type(method_name)
      if method_name.downcase.include?('role')
        'role_based'
      elsif method_name.downcase.include?('permission')
        'permission_based'
      elsif method_name.downcase.include?('can')
        'ability_based'
      else
        'custom'
      end
    end

    def analyze_resource_check(source_code)
      checks = {}
      
      if source_code&.include?('owner') || source_code&.include?('user_id')
        checks[:ownership_check] = true
      end
      
      if source_code&.include?('admin') || source_code&.include?('role')
        checks[:role_check] = true
      end
      
      checks
    end

    def infer_permission_model(source_code)
      if source_code&.include?('cancan') || source_code&.include?('ability')
        'cancan'
      elsif source_code&.include?('pundit')
        'pundit'
      elsif source_code&.include?('role')
        'role_based'
      else
        'custom'
      end
    end

    def involves_data_operation?(source_code)
      data_patterns = [
        /SELECT|INSERT|UPDATE|DELETE/i,
        /find|where|create|save|destroy/i,
        /File\.|read|write/,
        /params\[/
      ]
      
      data_patterns.any? { |pattern| source_code&.match?(pattern) }
    end

    def identify_data_sources(trace)
      sources = []
      
      param_usage = trace[:parameter_usage] || {}
      if param_usage[:uses_request_params]
        sources << 'user_input'
      end
      
      source_code = trace[:source] || ''
      if involves_database_operation?(source_code)
        sources << 'database'
      end
      
      if source_code.include?('File.') || source_code.include?('read')
        sources << 'file_system'
      end
      
      sources
    end

    def extract_processing_operations(source_code)
      operations = []
      
      # String operations
      string_ops = %w[upcase downcase strip gsub sub]
      string_ops.each do |op|
        if source_code&.include?(".#{op}")
          operations << { type: 'string_operation', method: op }
        end
      end
      
      # Validation operations
      if source_code&.include?('valid')
        operations << { type: 'validation', method: 'validation_check' }
      end
      
      # Transformation operations
      if source_code&.include?('.to_')
        operations << { type: 'type_conversion', method: 'type_cast' }
      end
      
      operations
    end

    def identify_data_destinations(source_code)
      destinations = []
      
      if involves_database_operation?(source_code)
        destinations << 'database'
      end
      
      if source_code&.include?('File.') || source_code&.include?('write')
        destinations << 'file_system'
      end
      
      if source_code&.include?('render') || source_code&.include?('response')
        destinations << 'web_response'
      end
      
      destinations
    end

    def classify_transaction_type(source_code)
      if source_code&.include?('transaction')
        'explicit_transaction'
      elsif source_code&.include?('save!') || source_code&.include?('create!')
        'implicit_transaction'
      else
        'none'
      end
    end

    def analyze_atomicity(source_code)
      atomicity = {}
      
      if source_code&.include?('transaction')
        atomicity[:explicit_transaction] = true
      end
      
      if source_code&.include?('rollback')
        atomicity[:rollback_support] = true
      end
      
      atomicity
    end

    def analyze_error_handling(source_code)
      error_handling = {}
      
      if source_code&.include?('rescue')
        error_handling[:exception_handling] = true
      end
      
      if source_code&.include?('ensure')
        error_handling[:cleanup_handling] = true
      end
      
      error_handling
    end
  end
end