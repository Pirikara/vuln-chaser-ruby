require "json"
require "method_source"

module VulnChaser
  class FlowTracer
    def initialize(base_path:)
      @base_path = base_path
      @trace_data = []
    end

    def start
      puts "Starting flow tracer..."
      @trace_point = TracePoint.new(:call, :return) do |tp|
        if relevant?(tp)
          record_trace(tp)
        end
      end
      @trace_point.enable
    end

    def stop
      puts "Stopping flow tracer..."
      @trace_point.disable
      @trace_data
    end

    def traces
      @trace_data
    end

    private

    def relevant?(tp)
      # 基本的な関連フィルタリング
      tp.path.start_with?(@base_path)
    end

    def record_trace(tp)
      return unless tp.event == :call

      method = tp.defined_class.instance_method(tp.method_id)
      source_code = method.source

      trace_entry = {
        event: tp.event,
        defined_class: tp.defined_class.to_s,
        method_id: tp.method_id.to_s,
        path: tp.path,
        lineno: tp.lineno,
        source_code: source_code,
        result: tp.event == :return ? truncate_large_data(tp.return_value) : nil,
        arguments: tp.event == :call ? process_arguments(tp.parameters, tp.binding) : nil
      }
      @trace_data << trace_entry
    rescue MethodSource::SourceNotFoundError
      return
    end
    
    def process_arguments(parameters, binding)
      args_hash = {}
      parameters.each do |type, name|
        next unless name
        value = binding.local_variable_get(name) rescue nil
        args_hash[name] = truncate_large_data(value)
      end
      if defined?(Rails) && binding.local_variable_defined?(:params)
        args_hash["params"] = truncate_large_data(binding.local_variable_get(:params))
      end
      args_hash
    rescue StandardError
      "Unable to process arguments"
    end
    
    def truncate_large_data(data, max_length = 500)
      data_str = data.to_s
      data_str.length > max_length ? "#{data_str[0..max_length]}... (truncated)" : data_str
    end    

    def extract_full_method_source(path, lineno)
      return "Source not found" unless File.exist?(path)

      lines = File.readlines(path)
      start_line = lineno
      end_line = lineno

      # メソッドの開始行を特定（def までさかのぼる）
      start_line -= 1 while start_line > 0 && !lines[start_line - 1].strip.start_with?("def ")
      # メソッドの終了行を特定（end の行を探す）
      nested_count = 0
      end_line.upto(lines.size - 1) do |i|
        nested_count += 1 if lines[i].strip.start_with?("def ") || lines[i].strip == "do"
        nested_count -= 1 if lines[i].strip == "end"
        if nested_count.zero?
          end_line = i
          break
        end
      end

      lines[start_line - 1..end_line].join
    rescue StandardError
      "Source extraction failed"
    end

    def truncate_result(result)
      max_length = 500 # 最大文字数を制限
      case result
      when String
        result.size <= max_length ? result : "#{result[0..249]}... (truncated)"
      when Hash, Array
        truncated_json(result, max_length)
      else
        result.inspect.size <= max_length ? result.inspect : "#{result.inspect[0..249]}... (truncated)"
      end
    rescue StandardError
      "Unable to process result"
    end

    def truncated_json(data, max_length)
      json_str = JSON.pretty_generate(data)
      json_str.size <= max_length ? json_str : "#{json_str[0..249]}... (truncated)"
    rescue JSON::GeneratorError
      "Non-JSON data"
    end

    # トレースデータを逐次保存するためのメソッド（必要なら有効化）
    def append_trace_to_file(trace_entry)
      File.open("trace_log.json", "a") do |file|
        file.puts(trace_entry.to_json)
      end
    rescue IOError
      puts "Failed to write trace to file"
    end
  end
end
