module VulnChaser
  class Config
    class << self
      attr_accessor :storage_path
      attr_accessor :excluded_paths
      attr_accessor :custom_paths
      attr_accessor :traced_gems           # User-specified gems to trace
      attr_accessor :project_roots         # Manual project root specification
      attr_accessor :disable_auto_detection # Disable automatic project detection
    end
  end
end