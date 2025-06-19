require 'spec_helper'

RSpec.describe VulnChaser::Middleware do
  let(:app) { ->(env) { [200, env, 'app'] } }
  let(:middleware) { described_class.new(app) }
  let(:env) { { 'PATH_INFO' => '/users', 'REQUEST_METHOD' => 'GET' } }
  let(:request) { ActionDispatch::Request.new(env) }
  let(:flow_tracer) { instance_double(VulnChaser::FlowTracer) }
  let(:trace_store) { instance_double(VulnChaser::TraceStore) }
  let(:context) { instance_double(VulnChaser::TraceContext) }
  let(:traces) { [{ method: 'index', class: 'UsersController' }] }
  let(:trace_hash) { { endpoint: 'GET /users', traces: traces } }

  before do
    allow(VulnChaser::FlowTracer).to receive(:new).and_return(flow_tracer)
    allow(VulnChaser::TraceContext).to receive(:new).and_return(context)
    allow(VulnChaser::TraceStore).to receive(:instance).and_return(trace_store)
    allow(flow_tracer).to receive(:start)
    allow(flow_tracer).to receive(:stop).and_return(traces)
    allow(context).to receive(:to_hash).and_return(trace_hash)
    allow(trace_store).to receive(:store)
    
    # Setup new TraceBuffer
    trace_buffer = double('TraceBuffer')
    allow(VulnChaser).to receive(:trace_buffer).and_return(trace_buffer)
    allow(trace_buffer).to receive(:add_trace)
  end

  describe '#call' do
    context 'when response is successful (200)' do
      it 'traces and stores the request flow' do
        status, headers, response = middleware.call(env)

        expect(flow_tracer).to have_received(:start).with(context)
        expect(flow_tracer).to have_received(:stop)
        trace_buffer = VulnChaser.trace_buffer
        expect(trace_buffer).to have_received(:add_trace).with(trace_hash)
        expect(status).to eq(200)
      end
    end

    context 'when response is not successful' do
      let(:app) { ->(env) { [500, env, 'error'] } }

      it 'traces but does not store the request flow' do
        status, headers, response = middleware.call(env)

        expect(flow_tracer).to have_received(:start).with(context)
        expect(flow_tracer).to have_received(:stop)
        trace_buffer = VulnChaser.trace_buffer
        expect(trace_buffer).not_to have_received(:add_trace)
        expect(status).to eq(500)
      end
    end
  end
end
