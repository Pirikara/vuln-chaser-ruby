if Rails.env.development?
  require 'vuln_chaser'

  VulnChaser.configure do |config|
    # Storage path for trace data
    config.storage_path = Rails.root.join('tmp', 'vuln_chaser')

    # Paths to exclude from tracing
    config.excluded_paths = ['/health_check', '/assets']
    
    # Custom paths to include in tracing
    config.custom_paths = []
  end
end