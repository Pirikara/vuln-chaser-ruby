require 'spec_helper'

RSpec.describe VulnChaser::ExecutionTracer do
  let(:tracer) { described_class.new }
  let(:trace_id) { 'test-trace-123' }
  let(:env) { { 'REQUEST_METHOD' => 'GET', 'PATH_INFO' => '/users' } }

  describe '#initialize' do
    it 'sets up instance variables correctly' do
      expect(tracer.instance_variable_get(:@traces)).to eq({})
      expect(tracer.instance_variable_get(:@data_sanitizer)).to be_a(VulnChaser::DataSanitizer)
    end
  end

  describe '#start_trace' do
    before do
      allow(Time).to receive(:current).and_return(Time.new(2024, 1, 1))
    end

    it 'initializes trace data with request info' do
      tracer.start_trace(trace_id, env)
      
      traces = tracer.instance_variable_get(:@traces)
      expect(traces[trace_id]).to include(
        trace_id: trace_id,
        timestamp: Time.current.iso8601,
        request_info: hash_including(
          method: 'GET',
          path: '/users'
        ),
        execution_trace: []
      )
    end

    it 'enables trace point monitoring' do
      tracer.start_trace(trace_id, env)
      trace_point = tracer.instance_variable_get(:@trace_point)
      expect(trace_point).to be_enabled
    end
  end

  describe '#finish_trace' do
    before do
      tracer.start_trace(trace_id, env)
    end

    it 'disables trace point and removes trace data' do
      result = tracer.finish_trace(trace_id)
      
      expect(tracer.instance_variable_get(:@trace_point)).not_to be_enabled
      expect(tracer.instance_variable_get(:@traces)[trace_id]).to be_nil
    end
  end

  describe 'security method detection' do
    let(:sql_trace_point) do
      double('TracePoint',
        method_id: :find_by_sql,
        defined_class: ActiveRecord::Base,
        path: '/app/models/user.rb',
        lineno: 10
      )
    end

    let(:auth_trace_point) do
      double('TracePoint',
        method_id: :authenticate,
        defined_class: User,
        path: '/app/models/user.rb',
        lineno: 15
      )
    end

    describe '#dangerous_framework_method?' do
      it 'detects SQL-related methods' do
        expect(tracer.send(:dangerous_framework_method?, sql_trace_point)).to be true
      end

      it 'detects authentication methods' do
        expect(tracer.send(:dangerous_framework_method?, auth_trace_point)).to be true
      end
    end

    describe '#important_gem_method?' do
      let(:devise_trace_point) do
        double('TracePoint', path: '/gems/devise/lib/devise.rb')
      end

      it 'detects security gem methods' do
        expect(tracer.send(:important_gem_method?, devise_trace_point)).to be true
      end
    end
  end

  describe 'security context building' do
    let(:sql_source) { "User.find_by_sql(\"SELECT * FROM users WHERE name = '\#{params[:name]}'\")" }
    let(:trace_point) do
      double('TracePoint',
        method_id: :find_by_sql,
        defined_class: ActiveRecord::Base,
        path: '/app/models/user.rb',
        lineno: 10
      )
    end

    it 'builds security context for SQL injection risks' do
      context = tracer.send(:build_security_context, trace_point, sql_source)
      expect(context).to include('SQL execution detected')
      expect(context).to include('Potential SQL injection')
    end
  end
end