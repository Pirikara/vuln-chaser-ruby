module VulnChaser
  class TraceContext
    attr_reader :request_id, :endpoint, :start_time, :traces
    
    def initialize(request)
      @request_id = SecureRandom.uuid
      @endpoint = "#{request.method} #{request.path}"
      @start_time = Time.current
    end
    
    def to_hash(traces = nil)
      {
        request_id: @request_id,
        endpoint: @endpoint,
        duration: Time.current - @start_time,
        traces: traces
      }
    end
  end
end