require 'thread'
require 'time'

module VulnChaser
  class TraceBuffer
    FLUSH_SIZE_THRESHOLD = 1
    FLUSH_TIME_THRESHOLD = 30 # seconds
    MAX_BUFFER_SIZE = 100 # prevent memory overflow

    def initialize
      @buffer = []
      @mutex = Mutex.new
      @last_flush = Time.now
    end

    def add_trace(trace_data)
      @mutex.synchronize do
        # Prevent memory overflow
        if @buffer.size >= MAX_BUFFER_SIZE
          VulnChaser.logger&.warn("VulnChaser: Buffer overflow, dropping oldest traces")
          @buffer.shift(MAX_BUFFER_SIZE / 2) # Remove half of buffer
        end

        @buffer << trace_data
        flush_if_needed
      end
    end

    def force_flush
      @mutex.synchronize do
        return [] if @buffer.empty?
        
        traces_to_send = @buffer.dup
        @buffer.clear
        @last_flush = Time.now
        traces_to_send
      end
    end

    def stats
      @mutex.synchronize do
        {
          buffer_size: @buffer.size,
          last_flush: @last_flush,
          time_since_flush: Time.now - @last_flush
        }
      end
    end

    private

    def flush_if_needed
      should_flush = @buffer.size >= FLUSH_SIZE_THRESHOLD ||
                     (Time.now - @last_flush) > FLUSH_TIME_THRESHOLD
      VulnChaser.logger&.info("VulnChaser: TraceBuffer - should_flush: #{should_flush}, buffer_size: #{@buffer.size}")

      if should_flush && !@buffer.empty?
        traces_to_send = @buffer.dup
        @buffer.clear
        @last_flush = Time.now
        
        # Send traces asynchronously
        VulnChaser::AsyncTraceSender.instance.send_batch(traces_to_send)
      end
    end
  end

  # Singleton instance for the buffer
  def self.trace_buffer
    @trace_buffer ||= TraceBuffer.new
  end
end
