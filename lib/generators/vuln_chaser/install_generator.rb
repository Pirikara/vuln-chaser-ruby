module VulnChaser
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path('templates', __dir__)

      def create_initializer
        template 'initializer.rb', 'config/initializers/vuln_chaser.rb'
      end

      def create_storage_directory
        empty_directory 'tmp/vuln_chaser'
      end
    end
  end
end