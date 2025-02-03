require 'spec_helper'

RSpec.describe VulnChaser::TraceContext do
  let(:request) { double('Request', method: 'GET', path: '/users') }
  let(:trace_context) { described_class.new(request) }

  describe '#initialize' do
    it 'sets up instance variables with request data' do
      allow(SecureRandom).to receive(:uuid).and_return('test-uuid')
      allow(Time).to receive(:current).and_return(Time.now)

      context = described_class.new(request)

      expect(context.request_id).to eq('test-uuid')
      expect(context.endpoint).to eq('GET /users')
      expect(context.start_time).to be_instance_of(Time)
    end
  end

  describe '#to_hash' do
    let(:start_time) { Time.current }
    let(:end_time) { start_time + 2.seconds }
    let(:traces) { [{ method: 'index', class: 'UsersController' }] }

    before do
      allow(Time).to receive(:current).and_return(start_time, end_time)
    end

    it 'returns hash with trace context data' do
      result = trace_context.to_hash(traces)

      expect(result).to include(
        request_id: trace_context.request_id,
        endpoint: 'GET /users',
        duration: 2.0,
        traces: traces
      )
    end

    it 'handles nil traces' do
      result = trace_context.to_hash

      expect(result).to include(
        request_id: trace_context.request_id,
        endpoint: 'GET /users',
        duration: 2.0,
        traces: nil
      )
    end
  end
end
