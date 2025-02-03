require "fileutils"
require "rails"
require 'active_support/time'
require "pathname"
require "vuln_chaser"

module Rails
  def self.root
    @root ||= Pathname.new(File.expand_path('../dummy', __FILE__))
  end
  
  def self.logger
    @logger ||= Logger.new(nil)
  end
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.before(:suite) do
    FileUtils.mkdir_p(Rails.root.join('tmp/vuln_chaser'))
  end

  config.after(:suite) do
    FileUtils.rm_rf(Rails.root.join('tmp/vuln_chaser'))
  end

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
