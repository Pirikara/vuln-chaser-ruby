require 'spec_helper'

RSpec.describe VulnChaser::TraceBuffer do
  let(:buffer) { described_class.new }
  let(:trace_data) { { trace_id: 'test-123', data: 'test trace' } }

  describe '#initialize' do
    it 'sets up instance variables correctly' do
      expect(buffer.instance_variable_get(:@buffer)).to eq([])
      expect(buffer.instance_variable_get(:@mutex)).to be_a(Mutex)
      expect(buffer.instance_variable_get(:@last_flush)).to be_a(Time)
    end
  end

  describe '#add_trace' do
    it 'adds trace to buffer' do
      buffer.add_trace(trace_data)
      traces = buffer.instance_variable_get(:@buffer)
      expect(traces).to include(trace_data)
    end

    context 'when buffer exceeds max size' do
      before do
        # Fill buffer to max capacity
        (VulnChaser::TraceBuffer::MAX_BUFFER_SIZE + 5).times do |i|
          buffer.add_trace({ trace_id: "test-#{i}" })
        end
      end

      it 'removes older traces to prevent overflow' do
        traces = buffer.instance_variable_get(:@buffer)
        expect(traces.size).to be <= VulnChaser::TraceBuffer::MAX_BUFFER_SIZE
      end
    end
  end

  describe '#force_flush' do
    before do
      buffer.add_trace(trace_data)
      buffer.add_trace({ trace_id: 'test-456', data: 'another trace' })
    end

    it 'returns all buffered traces and clears buffer' do
      result = buffer.force_flush
      expect(result.size).to eq(2)
      expect(buffer.instance_variable_get(:@buffer)).to be_empty
    end

    it 'updates last flush time' do
      old_time = buffer.instance_variable_get(:@last_flush)
      sleep(0.01) # Ensure time difference
      buffer.force_flush
      new_time = buffer.instance_variable_get(:@last_flush)
      expect(new_time).to be > old_time
    end
  end

  describe '#stats' do
    before do
      buffer.add_trace(trace_data)
    end

    it 'returns buffer statistics' do
      stats = buffer.stats
      expect(stats).to include(
        buffer_size: 1,
        last_flush: be_a(Time),
        time_since_flush: be_a(Numeric)
      )
    end
  end

  describe 'flush conditions' do
    let(:async_sender) { double('AsyncTraceSender') }

    before do
      allow(VulnChaser::AsyncTraceSender).to receive(:instance).and_return(async_sender)
      allow(async_sender).to receive(:send_batch)
    end

    context 'when buffer size reaches threshold' do
      it 'triggers automatic flush' do
        VulnChaser::TraceBuffer::FLUSH_SIZE_THRESHOLD.times do |i|
          buffer.add_trace({ trace_id: "test-#{i}" })
        end

        expect(async_sender).to have_received(:send_batch)
      end
    end

    context 'when time threshold is reached' do
      before do
        # Set last flush to old time
        old_time = Time.current - (VulnChaser::TraceBuffer::FLUSH_TIME_THRESHOLD + 1)
        buffer.instance_variable_set(:@last_flush, old_time)
      end

      it 'triggers automatic flush' do
        buffer.add_trace(trace_data)
        expect(async_sender).to have_received(:send_batch)
      end
    end
  end
end