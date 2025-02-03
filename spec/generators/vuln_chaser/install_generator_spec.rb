require 'spec_helper'
require 'rails/generators'
require 'rails/generators/testing/behavior'

RSpec.describe VulnChaser::Generators::InstallGenerator do
  include Rails::Generators::Testing::Behavior

  tests VulnChaser::Generators::InstallGenerator
  let(:destination_root) { File.expand_path('../../tmp', __dir__) }

  before do
    FileUtils.mkdir_p(destination_root)
    self.class.destination(destination_root)
    self.class.generator_class.source_root(File.expand_path('../../../lib/generators/vuln_chaser/templates', __dir__))
  end

  after do
    FileUtils.rm_rf(destination_root)
  end

  describe 'generator' do
    it 'creates the initializer file' do
      generator.create_initializer
      initializer_path = File.join(destination_root, 'config/initializers/vuln_chaser.rb')
      expect(File.exist?(initializer_path)).to be true
    end

    it 'creates the storage directory' do
      generator.create_storage_directory
      storage_path = File.join(destination_root, 'tmp/vuln_chaser')
      expect(Dir.exist?(storage_path)).to be true
    end
  end
end
