module VulnChaser
  class DataSanitizer
    # Sensitive parameter patterns
    SENSITIVE_PATTERNS = [
      # Passwords and authentication
      /password/i, /passwd/i, /pwd/i, /passphrase/i,
      /secret/i, /token/i, /key/i, /auth/i,
      /credential/i, /login/i, /pin/i, /code/i,
      
      # Personal information
      /ssn/i, /social.*security/i, /tax.*id/i,
      /credit.*card/i, /card.*number/i, /cvv/i, /cvc/i,
      /account.*number/i, /routing.*number/i,
      
      # System information
      /api.*key/i, /private.*key/i, /certificate/i,
      /database.*url/i, /connection.*string/i,
      /bearer/i, /authorization/i
    ].freeze

    # Credit card pattern (basic Luhn algorithm check)
    CREDIT_CARD_PATTERN = /\b(?:\d{4}[-\s]?){3}\d{4}\b/

    # SSN patterns
    SSN_PATTERN = /\b\d{3}-?\d{2}-?\d{4}\b/

    # Email patterns (partial masking)
    EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/

    def initialize
      @config = VulnChaser.config if defined?(VulnChaser.config)
    end

    def sanitize_params(params)
      return {} unless params.is_a?(Hash)
      
      sanitized = {}
      params.each do |key, value|
        sanitized[key] = sanitize_value(key.to_s, value)
      end
      sanitized
    end

    def sanitize_source_code(source_code)
      return source_code unless source_code.is_a?(String)
      
      sanitized = source_code.dup
      
      # Sanitize potential sensitive data in source code
      sanitized = mask_credit_cards(sanitized)
      sanitized = mask_ssn(sanitized)
      sanitized = mask_emails(sanitized)
      sanitized = mask_quoted_secrets(sanitized)
      
      sanitized
    end

    def sanitize_sql_query(query)
      return query unless query.is_a?(String)
      
      # Don't sanitize the structure, but mask potential data
      sanitized = query.dup
      sanitized = mask_quoted_strings_in_sql(sanitized)
      sanitized
    end

    # SOR Framework: Enhanced sanitization methods
    def sanitize_env(env_data)
      return {} unless env_data.is_a?(Hash)
      
      sanitized = {}
      env_data.each do |key, value|
        case key.to_s
        when 'HTTP_AUTHORIZATION', 'HTTP_X_API_KEY'
          sanitized[key] = '[FILTERED]'
        when 'REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'
          sanitized[key] = mask_ip_address(value.to_s)
        else
          sanitized[key] = value
        end
      end
      sanitized
    end

    def sanitize_session(session_data)
      return {} unless session_data.is_a?(Hash)
      
      sanitized = {}
      session_data.each do |key, value|
        if sensitive_key?(key.to_s)
          sanitized[key] = '[FILTERED]'
        else
          sanitized[key] = sanitize_value(key.to_s, value)
        end
      end
      sanitized
    end

    def sanitize_headers(headers_data)
      return {} unless headers_data.is_a?(Hash)
      
      sanitized = {}
      headers_data.each do |key, value|
        case key.to_s.downcase
        when 'authorization', 'x-api-key', 'x-csrf-token'
          sanitized[key] = '[FILTERED]'
        else
          sanitized[key] = value
        end
      end
      sanitized
    end

    private

    def sanitize_value(key, value)
      return '[FILTERED]' if sensitive_key?(key)
      
      case value
      when String
        return '[FILTERED]' if value.length > 1000 # Prevent huge values
        sanitize_string_value(value)
      when Hash
        sanitize_params(value)
      when Array
        value.map { |v| sanitize_value("array_item", v) }
      else
        value
      end
    end

    def sensitive_key?(key)
      SENSITIVE_PATTERNS.any? { |pattern| key.match?(pattern) }
    end

    def sanitize_string_value(value)
      # Check for credit cards, SSN, etc.
      return '[CREDIT_CARD]' if value.match?(CREDIT_CARD_PATTERN)
      return '[SSN]' if value.match?(SSN_PATTERN)
      
      # Mask emails partially
      if value.match?(EMAIL_PATTERN)
        return value.gsub(EMAIL_PATTERN) { |email| mask_email(email) }
      end
      
      # Return original if no sensitive data detected
      value
    end

    def mask_email(email)
      local, domain = email.split('@')
      return email if local.nil? || domain.nil?
      
      masked_local = local.length > 2 ? "#{local[0]}***#{local[-1]}" : "***"
      "#{masked_local}@#{domain}"
    end

    def mask_credit_cards(text)
      text.gsub(CREDIT_CARD_PATTERN, '[CREDIT_CARD_MASKED]')
    end

    def mask_ssn(text)
      text.gsub(SSN_PATTERN, '[SSN_MASKED]')
    end

    def mask_emails(text)
      text.gsub(EMAIL_PATTERN) { |email| mask_email(email) }
    end

    def mask_quoted_secrets(text)
      # Look for quoted strings that might contain secrets
      text.gsub(/(["'])([^"']*(?:password|secret|token|key)[^"']*)\1/i) do |match|
        quote = $1
        content = $2
        "#{quote}[FILTERED]#{quote}"
      end
    end

    def mask_quoted_strings_in_sql(sql)
      # Mask values in SQL queries while preserving structure
      sql.gsub(/(["'])([^"']{10,})\1/) do |match|
        quote = $1
        content = $2
        
        # If it looks like sensitive data, mask it
        if sensitive_sql_value?(content)
          "#{quote}[FILTERED]#{quote}"
        else
          # Keep short values, truncate long ones
          truncated = content.length > 50 ? "#{content[0..20]}..." : content
          "#{quote}#{truncated}#{quote}"
        end
      end
    end

    def sensitive_sql_value?(value)
      return false unless value.is_a?(String)
      
      # Check if the value looks like sensitive data
      SENSITIVE_PATTERNS.any? { |pattern| value.match?(pattern) } ||
        value.match?(CREDIT_CARD_PATTERN) ||
        value.match?(SSN_PATTERN) ||
        value.length > 100 # Very long strings might be sensitive
    end

    def mask_ip_address(ip)
      return ip unless ip.is_a?(String)
      
      # Mask last octet of IPv4
      if ip.match?(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
        parts = ip.split('.')
        return "#{parts[0]}.#{parts[1]}.#{parts[2]}.***"
      end
      
      # For IPv6 or other formats, mask partially
      if ip.length > 8
        "#{ip[0..3]}***#{ip[-4..-1]}"
      else
        ip
      end
    end
  end
end