require 'vuln_chaser'

VulnChaser.configure do |config|
  # OpenAI API Key for LLM analysis
  config.llm_api_key = ENV['OPENAI_API_KEY']

  # Storage path for trace data
  config.storage_path = Rails.root.join('tmp', 'vuln_chaser')

  # Paths to exclude from tracing
  config.excluded_paths = ['/health_check', '/assets']
end