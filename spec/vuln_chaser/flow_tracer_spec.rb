require 'spec_helper'

RSpec.describe VulnChaser::FlowTracer do
  let(:base_path) { Rails.root.to_s }
  let(:flow_tracer) { described_class.new(base_path: base_path) }

  describe '#initialize' do
    it 'sets up instance variables correctly' do
      expect(flow_tracer.instance_variable_get(:@base_path)).to eq(base_path)
      expect(flow_tracer.instance_variable_get(:@trace_data)).to eq([])
      expect(flow_tracer.instance_variable_get(:@current_context)).to be_nil
    end
  end

  describe '#start' do
    let(:context) { double('TraceContext', request_id: 'test-123') }
    let(:logger) { double('Logger') }

    before do
      allow(Rails).to receive(:logger).and_return(logger)
      allow(logger).to receive(:info)
    end

    it 'starts tracing with context' do
      flow_tracer.start(context)
      expect(flow_tracer.instance_variable_get(:@current_context)).to eq(context)
      expect(flow_tracer.instance_variable_get(:@trace_point)).to be_enabled
      expect(logger).to have_received(:info).with("VulnChaser: Starting flow tracer for request: test-123")
    end
  end

  describe '#stop' do
    let(:logger) { double('Logger') }

    before do
      allow(Rails).to receive(:logger).and_return(logger)
      allow(logger).to receive(:info)
      flow_tracer.start
    end

    it 'stops tracing and returns collected data' do
      result = flow_tracer.stop
      expect(result).to be_an(Array)
      expect(flow_tracer.instance_variable_get(:@trace_data)).to be_empty
      expect(flow_tracer.instance_variable_get(:@trace_point)).not_to be_enabled
      expect(logger).to have_received(:info).with("VulnChaser: Stopping flow tracer...")
    end
  end

  describe '#relevant?' do
    let(:trace_point) { double('TracePoint') }

    before do
      VulnChaser::Config.custom_paths = ['app/controllers', 'app/models']
    end

    context 'when path matches custom_paths' do
      it 'returns true' do
        allow(trace_point).to receive(:path).and_return('app/controllers/users_controller.rb')
        expect(flow_tracer.send(:relevant?, trace_point)).to be true
      end
    end

    context 'when path starts with base_path' do
      it 'returns true' do
        allow(trace_point).to receive(:path).and_return("#{base_path}/lib/custom.rb")
        expect(flow_tracer.send(:relevant?, trace_point)).to be true
      end
    end

    context 'when path does not match any criteria' do
      it 'returns false' do
        allow(trace_point).to receive(:path).and_return('/some/other/path.rb')
        expect(flow_tracer.send(:relevant?, trace_point)).to be false
      end
    end
  end

  describe '#record_trace' do
    let(:trace_point) do
      double('TracePoint',
        event: :call,
        defined_class: String,
        method_id: :upcase,
        path: "#{base_path}/app/models/user.rb",
        lineno: 10
      )
    end
    let(:context) { double('TraceContext', request_id: 'test-123') }
    let(:method_double) { double('Method', source: 'def upcase; end', source_location: ['file.rb', 1]) }

    before do
      allow(Time).to receive(:current).and_return(Time.now)
      allow(trace_point.defined_class).to receive(:instance_method).and_return(method_double)
      flow_tracer.instance_variable_set(:@current_context, context)
    end

    it 'records trace data correctly' do
      flow_tracer.send(:record_trace, trace_point)
      recorded_trace = flow_tracer.instance_variable_get(:@trace_data).first

      expect(recorded_trace).to include(
        request_id: 'test-123',
        event: :call,
        defined_class: 'String',
        method_id: 'upcase',
        path: "#{base_path}/app/models/user.rb",
        lineno: 10,
        source_code: 'def upcase; end',
        source_location: ['file.rb', 1]
      )
    end

    context 'when source cannot be found' do
      before do
        allow(trace_point.defined_class).to receive(:instance_method)
          .and_raise(MethodSource::SourceNotFoundError.new('Source not found'))
      end

      it 'handles the error gracefully' do
        expect { flow_tracer.send(:record_trace, trace_point) }
          .to output(/Failed to get source for String#upcase: Source not found/).to_stdout
      end
    end
  end
end
