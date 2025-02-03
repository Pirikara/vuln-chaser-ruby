module VulnChaser
  class Config
    class << self
      attr_accessor :storage_path
      attr_accessor :excluded_paths
      attr_accessor :custom_paths
    end
  end
end