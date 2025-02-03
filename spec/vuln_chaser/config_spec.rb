require 'spec_helper'

RSpec.describe VulnChaser::Config do
  after do
    described_class.storage_path = nil
    described_class.excluded_paths = nil
    described_class.custom_paths = nil
  end

  describe 'configuration' do
    it 'allows setting and getting storage_path' do
      described_class.storage_path = '/tmp/vuln_chaser'
      expect(described_class.storage_path).to eq('/tmp/vuln_chaser')
    end

    it 'allows setting and getting excluded_paths' do
      paths = ['vendor/', 'node_modules/']
      described_class.excluded_paths = paths
      expect(described_class.excluded_paths).to eq(paths)
    end

    it 'allows setting and getting custom_paths' do
      paths = ['app/controllers', 'app/models']
      described_class.custom_paths = paths
      expect(described_class.custom_paths).to eq(paths)
    end
  end
end
