if Rails.env.development?
  require 'vuln_chaser'

  VulnChaser.configure do |config|
    # Storage path for trace data
    config.storage_path = Rails.root.join('tmp', 'vuln_chaser')

    # Paths to exclude from tracing
    config.excluded_paths = ['/health_check', '/assets']
    
    # Custom paths to include in tracing
    config.custom_paths = []
    
    # Gems to trace (user-specified for rate limit control)
    # Common security-relevant gems:
    config.traced_gems = [
      # 'devise',        # Authentication
      # 'pundit',        # Authorization
      # 'activerecord',  # Database ORM
      # 'nokogiri',    # XML/HTML parsing
      # 'net-http',    # HTTP client
      # 'sidekiq',     # Background jobs
      # 'redis',       # Cache/session store
    ]
    
    # Manual project root specification (optional)
    # Overrides auto-detection if specified
    # config.project_roots = [
    #   Rails.root.join('app').to_s,
    #   Rails.root.join('lib').to_s,
    #   Rails.root.join('engines', 'my_engine', 'lib').to_s
    # ]
    
    # Disable automatic project detection (default: false)
    # config.disable_auto_detection = false
  end
end
