require 'net/http'
require 'json'
require 'singleton'
require 'securerandom'

module VulnChaser
  class AsyncTraceSender
    include Singleton

    def initialize
      @core_endpoint = ENV['VULN_CHASER_CORE_URL'] || 'http://localhost:8000'
      @retry_count = 0
      @max_retries = 3
      @retry_delay = 1 # seconds
    end

    def send_batch(traces)
      return if traces.empty?

      Thread.new do
        begin
          batch_data = build_batch_payload(traces)
          response = post_to_core(batch_data)
          handle_response(response, batch_data[:batch_id])
        rescue => e
          handle_error(e, traces)
        end
      end
    end

    def health_check
      uri = URI("#{@core_endpoint}/health")
      begin
        response = Net::HTTP.get_response(uri)
        response.code == '200'
      rescue => e
        VulnChaser.logger&.warn("VulnChaser: Core health check failed: #{e.message}")
        false
      end
    end

    private

    def build_batch_payload(traces)
      {
        batch_id: SecureRandom.uuid,
        timestamp: Time.now.iso8601,
        traces: traces.map { |trace| format_trace_for_api(trace) }
      }
    end

    def format_trace_for_api(trace_data)
      {
        trace_id: trace_data[:request_id] || SecureRandom.uuid,
        request_info: {
          method: trace_data[:method] || 'UNKNOWN',
          path: trace_data[:endpoint] || 'unknown',
          params: sanitize_params(trace_data[:params] || {})
        },
        execution_trace: trace_data[:traces] || []
      }
    end

    def sanitize_params(params)
      # Basic sanitization - replace with proper DataSanitizer
      return {} unless params.is_a?(Hash)
      
      sanitized = {}
      params.each do |key, value|
        if sensitive_param?(key.to_s.downcase)
          sanitized[key] = '[FILTERED]'
        else
          sanitized[key] = value.is_a?(String) && value.length > 100 ? "#{value[0..100]}..." : value
        end
      end
      sanitized
    end

    def sensitive_param?(key)
      %w[password token secret key credential auth].any? { |word| key.include?(word) }
    end

    def post_to_core(batch_data)
      uri = URI("#{@core_endpoint}/api/traces/batch")
      
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.read_timeout = 120  # 2 minutes for LLM analysis
      http.open_timeout = 30   # 30 seconds for connection
      http.write_timeout = 30  # 30 seconds for sending data

      request = Net::HTTP::Post.new(uri.path)
      request['Content-Type'] = 'application/json'
      request['User-Agent'] = "VulnChaser-Ruby/#{VulnChaser::VERSION}"
      request.body = batch_data.to_json

      http.request(request)
    end

    def handle_response(response, batch_id)
      case response.code
      when '200', '201'
        result = JSON.parse(response.body) rescue {}
        VulnChaser.logger&.info("VulnChaser: Batch #{batch_id} analyzed successfully")
        log_analysis_results(result)
        @retry_count = 0
      when '400'
        VulnChaser.logger&.error("VulnChaser: Bad request for batch #{batch_id}: #{response.body}")
      when '429'
        VulnChaser.logger&.warn("VulnChaser: Rate limited for batch #{batch_id}")
        schedule_retry
      when '500', '502', '503', '504'
        VulnChaser.logger&.warn("VulnChaser: Server error for batch #{batch_id}: #{response.code}")
        schedule_retry
      else
        VulnChaser.logger&.warn("VulnChaser: Unexpected response #{response.code} for batch #{batch_id}")
      end
    end

    def handle_error(error, traces)
      case error
      when Net::ReadTimeout, Net::WriteTimeout, Net::OpenTimeout
        VulnChaser.logger&.warn("VulnChaser: Request timeout (#{error.class}): #{error.message}")
        VulnChaser.logger&.warn("VulnChaser: This may indicate Core API is busy with LLM analysis")
      when Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        VulnChaser.logger&.error("VulnChaser: Cannot connect to Core API: #{error.message}")
      else
        VulnChaser.logger&.error("VulnChaser: Failed to send batch: #{error.message}")
      end
      
      if @retry_count < @max_retries && !error.is_a?(Net::ReadTimeout)
        schedule_retry(traces)
      else
        if error.is_a?(Net::ReadTimeout)
          VulnChaser.logger&.warn("VulnChaser: Skipping retry for timeout - analysis may still be in progress")
        else
          VulnChaser.logger&.error("VulnChaser: Max retries exceeded, dropping #{traces.size} traces")
        end
        @retry_count = 0
      end
    end

    def schedule_retry(traces = nil)
      @retry_count += 1
      delay = @retry_delay * @retry_count
      
      Thread.new do
        sleep(delay)
        send_batch(traces) if traces
      end
    end

    def log_analysis_results(result)
      return unless result['results']
      
      vulnerabilities = result['results'].sum { |r| r['vulnerabilities']&.size || 0 }
      if vulnerabilities > 0
        VulnChaser.logger&.warn("VulnChaser: Found #{vulnerabilities} potential vulnerabilities!")
      end
    end
  end
end
