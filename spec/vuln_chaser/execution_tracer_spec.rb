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

  describe 'project detection methods' do
    let(:rails_app_path) { '/path/to/rails/app/controllers/users_controller.rb' }
    let(:gem_path) { '/path/to/gems/devise-4.8.0/lib/devise.rb' }
    let(:custom_path) { '/path/to/custom/lib/security.rb' }

    before do
      # Mock Rails for testing
      allow(tracer).to receive(:rails_project?).and_return(true)
      allow(Rails).to receive_message_chain(:root, :to_s).and_return('/path/to/rails')
      allow(Dir).to receive(:exist?).and_return(true)
      
      # Setup config for testing
      VulnChaser::Config.traced_gems = ['devise']
      VulnChaser::Config.custom_paths = ['custom/lib']
    end

    describe '#project_root_code?' do
      it 'detects Rails app code' do
        expect(tracer.send(:project_root_code?, rails_app_path)).to be true
      end
    end

    describe '#user_configured_gem_code?' do
      it 'detects configured gem code' do
        allow(tracer).to receive(:traced_gem_paths).and_return(['/path/to/gems/devise-4.8.0'])
        expect(tracer.send(:user_configured_gem_code?, gem_path)).to be true
      end
    end

    describe '#custom_path_code?' do
      it 'detects custom path code' do
        expect(tracer.send(:custom_path_code?, custom_path)).to be true
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