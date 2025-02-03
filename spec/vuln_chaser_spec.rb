require 'spec_helper'

RSpec.describe VulnChaser do
  describe '.configure' do
    it 'yields the Config class to the block' do
      expect { |b| described_class.configure(&b) }.to yield_with_args(VulnChaser::Config)
    end

    it 'allows configuration through block' do
      described_class.configure do |config|
        config.storage_path = '/custom/path'
        config.custom_paths = ['app/controllers']
        config.excluded_paths = ['vendor/']
      end

      expect(VulnChaser::Config.storage_path).to eq('/custom/path')
      expect(VulnChaser::Config.custom_paths).to eq(['app/controllers'])
      expect(VulnChaser::Config.excluded_paths).to eq(['vendor/'])
    end
  end

  describe 'VulnChaserTraceError' do
    it 'is defined as a custom error class' do
      expect(VulnChaser::VulnChaserTraceError.ancestors).to include(StandardError)
    end
  end
end
