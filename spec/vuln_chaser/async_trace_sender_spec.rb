require 'spec_helper'

RSpec.describe VulnChaser::AsyncTraceSender do
  let(:sender) { described_class.instance }
  let(:traces) do
    [
      { trace_id: 'test-123', endpoint: '/users', traces: [] },
      { trace_id: 'test-456', endpoint: '/posts', traces: [] }
    ]
  end

  describe '#initialize' do
    it 'sets up core endpoint URL' do
      expect(sender.instance_variable_get(:@core_endpoint)).to eq('http://localhost:8000')
    end

    it 'uses environment variable if set' do
      ENV['VULN_CHASER_CORE_URL'] = 'http://custom-core:9000'
      new_sender = described_class.allocate
      new_sender.send(:initialize)
      expect(new_sender.instance_variable_get(:@core_endpoint)).to eq('http://custom-core:9000')
      ENV.delete('VULN_CHASER_CORE_URL')
    end
  end

  describe '#send_batch' do
    let(:http_double) { double('Net::HTTP') }
    let(:response_double) { double('Net::HTTPResponse', code: '200', body: '{"status": "ok"}') }

    before do
      allow(Net::HTTP).to receive(:new).and_return(http_double)
      allow(http_double).to receive(:use_ssl=)
      allow(http_double).to receive(:read_timeout=)
      allow(http_double).to receive(:open_timeout=)
      allow(http_double).to receive(:request).and_return(response_double)
    end

    it 'sends traces asynchronously' do
      expect(Thread).to receive(:new).and_yield
      sender.send_batch(traces)
      expect(http_double).to have_received(:request)
    end

    it 'builds proper batch payload' do
      allow(Thread).to receive(:new).and_yield
      expect(sender).to receive(:build_batch_payload).with(traces).and_call_original
      sender.send_batch(traces)
    end

    context 'when traces array is empty' do
      it 'does not send request' do
        sender.send_batch([])
        expect(http_double).not_to have_received(:request)
      end
    end
  end

  describe '#health_check' do
    let(:http_response) { double('Net::HTTPResponse', code: '200') }

    before do
      allow(Net::HTTP).to receive(:get_response).and_return(http_response)
    end

    it 'returns true when core is healthy' do
      expect(sender.health_check).to be true
    end

    context 'when core is unhealthy' do
      before do
        allow(http_response).to receive(:code).and_return('500')
      end

      it 'returns false' do
        expect(sender.health_check).to be false
      end
    end

    context 'when connection fails' do
      before do
        allow(Net::HTTP).to receive(:get_response).and_raise(StandardError.new('Connection failed'))
      end

      it 'returns false and logs warning' do
        expect(VulnChaser.logger).to receive(:warn).with(/Core health check failed/)
        expect(sender.health_check).to be false
      end
    end
  end

  describe 'response handling' do
    let(:batch_id) { 'test-batch-123' }

    describe '#handle_response' do
      context 'with successful response' do
        let(:response) { double('Response', code: '200', body: '{"results": []}') }

        it 'logs success and resets retry count' do
          expect(VulnChaser.logger).to receive(:info).with(/analyzed successfully/)
          sender.send(:handle_response, response, batch_id)
          expect(sender.instance_variable_get(:@retry_count)).to eq(0)
        end
      end

      context 'with rate limit response' do
        let(:response) { double('Response', code: '429') }

        it 'schedules retry' do
          expect(sender).to receive(:schedule_retry)
          sender.send(:handle_response, response, batch_id)
        end
      end

      context 'with server error response' do
        let(:response) { double('Response', code: '500') }

        it 'schedules retry' do
          expect(sender).to receive(:schedule_retry)
          sender.send(:handle_response, response, batch_id)
        end
      end
    end

    describe '#handle_error' do
      let(:error) { StandardError.new('Network error') }

      it 'logs error and schedules retry if under limit' do
        expect(VulnChaser.logger).to receive(:error).with(/Failed to send batch/)
        expect(sender).to receive(:schedule_retry)
        sender.send(:handle_error, error, traces)
      end

      context 'when max retries exceeded' do
        before do
          sender.instance_variable_set(:@retry_count, 3)
        end

        it 'logs final error and resets retry count' do
          expect(VulnChaser.logger).to receive(:error).with(/Failed to send batch/)
          expect(VulnChaser.logger).to receive(:error).with(/Max retries exceeded/)
          sender.send(:handle_error, error, traces)
          expect(sender.instance_variable_get(:@retry_count)).to eq(0)
        end
      end
    end
  end

  describe 'data formatting' do
    describe '#format_trace_for_api' do
      let(:trace_data) do
        {
          request_id: 'req-123',
          endpoint: '/users/search',
          method: 'GET',
          params: { name: 'john', password: 'secret' },
          traces: [{ method: 'User#search', source: 'def search; end' }]
        }
      end

      it 'formats trace data for API consumption' do
        result = sender.send(:format_trace_for_api, trace_data)
        
        expect(result).to include(
          trace_id: 'req-123',
          request_info: hash_including(
            method: 'GET',
            path: '/users/search'
          ),
          execution_trace: [{ method: 'User#search', source: 'def search; end' }]
        )
      end

      it 'sanitizes sensitive parameters' do
        result = sender.send(:format_trace_for_api, trace_data)
        expect(result[:request_info][:params][:password]).to eq('[FILTERED]')
        expect(result[:request_info][:params][:name]).to eq('john')
      end
    end
  end
end