require 'spec_helper'

RSpec.describe VulnChaser::Config do
  after do
    described_class.storage_path = nil
    described_class.excluded_paths = nil
    described_class.custom_paths = nil
    described_class.traced_gems = nil
    described_class.project_roots = nil
    described_class.disable_auto_detection = nil
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

    it 'allows setting and getting traced_gems' do
      gems = ['devise', 'pundit', 'activerecord']
      described_class.traced_gems = gems
      expect(described_class.traced_gems).to eq(gems)
    end

    it 'allows setting and getting project_roots' do
      roots = ['/app/custom', '/lib/custom']
      described_class.project_roots = roots
      expect(described_class.project_roots).to eq(roots)
    end

    it 'allows setting and getting disable_auto_detection' do
      described_class.disable_auto_detection = true
      expect(described_class.disable_auto_detection).to be true

      described_class.disable_auto_detection = false
      expect(described_class.disable_auto_detection).to be false
    end
  end
end
