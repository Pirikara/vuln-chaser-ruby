require 'singleton'

module VulnChaser
  class TraceStore
    include Singleton

    def initialize
      @storage = {}
      @storage_path = Rails.root.join('tmp', 'vuln_chaser')
      FileUtils.mkdir_p(@storage_path)
    end

    def store(trace_data)
      endpoint = trace_data[:endpoint].force_encoding('UTF-8')
      return if duplicate?(endpoint, trace_data)
      
      file_path = @storage_path.join("#{endpoint.parameterize}.json")
      File.write(file_path, JSON.pretty_generate(trace_data))
    end

    private

    def duplicate?(endpoint, trace_data)
      existing = @storage[endpoint]
      return false unless existing
      
      existing[:traces] == trace_data[:traces]
    end
  end
end