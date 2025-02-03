require 'spec_helper'

RSpec.describe VulnChaser::TraceStore do
  let(:storage_path) { Rails.root.join('tmp', 'vuln_chaser') }
  let(:store) { described_class.instance }
  
  let(:trace_data) do
    {
      endpoint: 'GET /users',
      traces: [
        { data: 'trace_data', class: 'UsersController' }
      ]
    }
  end

  describe '#initialize' do
    it 'creates storage directory' do
      expect(Dir.exist?(storage_path)).to be true
    end
  end

  describe '#store' do
    before do
      FileUtils.rm_rf(storage_path)
      FileUtils.mkdir_p(storage_path)
    end

    after do
      FileUtils.rm_rf(storage_path)
    end

    it 'stores trace data in a JSON file' do
      store.store(trace_data)
      
      file_path = storage_path.join('get-users.json')
      expect(File.exist?(file_path)).to be true
      
      stored_data = JSON.parse(File.read(file_path))
      expect(stored_data['endpoint']).to eq('GET /users')
    end

    context 'when duplicate trace exists' do
      before do
        store.instance_variable_get(:@storage)[trace_data[:endpoint]] = trace_data
      end

      it 'does not store duplicate trace data' do
        store.store(trace_data)
        expect(Dir[storage_path.join('*.json')]).to be_empty
      end
    end

    context 'with different traces for same endpoint' do
      let(:different_trace_data) do
        {
          endpoint: 'GET /users',
          traces: [
            { data: 'different_trace_data', class: 'UsersController' }
          ]
        }
      end

      it 'stores new trace data and overwrites old one' do
        store.store(trace_data)
        store.store(different_trace_data)
        
        files = Dir[storage_path.join('*.json')]
        expect(files.length).to eq(1)
        
        stored_data = JSON.parse(File.read(files.first))
        expect(stored_data['traces'].first['data']).to eq('different_trace_data')
      end
    end
  end
end
