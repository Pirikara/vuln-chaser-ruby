# VulnChaser Ruby Agent

VulnChaser is an Interactive Application Security Testing (IAST) tool that provides runtime vulnerability detection for Ruby applications. The Ruby agent instruments your application to capture security-relevant execution traces and send them to the vuln-chaser-core analysis engine for LLM-powered vulnerability detection.

## Features

- **Runtime Security Analysis**: Captures actual execution paths during runtime
- **Zero File I/O**: All operations performed in memory for optimal performance
- **Multi-Application Support**: Works with Rails applications, Ruby gems, CLI tools, and scripts
- **LLM-Powered Detection**: Integrates with vuln-chaser-core for AI-powered vulnerability analysis
- **SOR Framework**: Advanced Subject-Operation-Resource relationship analysis
- **Data Flow Tracking**: Traces data from sources (user input) to sinks (database, system calls)

## Prerequisites

1. **vuln-chaser-core** must be running ([GitHub Repository](https://github.com/Pirikara/vuln-chaser-core))
2. Ruby 3.0+ 
3. Rails 7.0+ (for Rails applications, but Rails is **not required**)

## Installation

### Option 1: From Source

```bash
# Clone the repository
git clone https://github.com/Pirikara/vuln-chaser-ruby.git
cd vuln-chaser-ruby

# Install dependencies
bundle install

# Build and install the gem locally
bundle exec rake build
bundle exec rake install
```

### Option 2: Local Path Installation

Add to your project's Gemfile:

```ruby
group :development, :test do
  gem 'vuln_chaser', path: '/path/to/vuln-chaser-ruby'
end
```

## Rails Application Setup

### 1. Installation

Add to your Rails application's Gemfile:

```ruby
group :development, :test do
  gem 'vuln_chaser', path: '/path/to/vuln-chaser-ruby'
end
```

Run bundle install:
```bash
bundle install
```

### 2. Configuration

Add middleware configuration in `config/application.rb`:

```ruby
require 'vuln_chaser'

class Application < Rails::Application
  # Use the enhanced middleware for comprehensive security analysis
  config.middleware.use VulnChaser::EnhancedMiddleware
  
  # Alternative: Use basic middleware for lighter overhead
  # config.middleware.use VulnChaser::Middleware
end
```

### 3. Optional Configuration

Create `config/initializers/vuln_chaser.rb` for custom settings:

```ruby
VulnChaser.configure do |config|
  # Exclude specific paths from analysis (optional)
  config.excluded_paths = ['/health_check', '/assets', '/api/metrics']
  
  # Include specific gem paths for deep analysis (optional)
  config.custom_paths = [
    'gems/devise',           # Authentication gem
    'gems/cancancan',        # Authorization gem
    'gems/activerecord-sql', # Custom SQL gems
  ]
end
```

### 4. Environment Variables

Set the core API endpoint (optional, defaults to localhost:8000):

```bash
export VULN_CHASER_CORE_URL=http://localhost:8000
```

### 5. Start Analysis

1. **Start vuln-chaser-core**:
   ```bash
   cd vuln-chaser-core
   source venv/bin/activate
   python run_server.py
   ```

2. **Start your Rails application**:
   ```bash
   rails server
   ```

3. **Generate traffic**: Make HTTP requests to your endpoints to trigger analysis

4. **Monitor results**: Check the vuln-chaser-core logs for vulnerability findings

## Non-Rails Ruby Project Setup

VulnChaser can analyze any Ruby application, including gems, CLI tools, and scripts.

### Ruby Gems and Libraries

For analyzing Ruby gems during development or testing:

```ruby
# In your gem's test files or development scripts
require 'vuln_chaser'

# Configure for your gem
VulnChaser.configure do |config|
  config.custom_paths = ['lib/your_gem_name']
end

# Manual tracing approach
tracer = VulnChaser::ExecutionTracer.new
trace_id = "gem-test-#{SecureRandom.hex(4)}"

# Create mock environment
env = {
  'REQUEST_METHOD' => 'GET',
  'PATH_INFO' => '/test',
  'rack.session' => {}
}

# Override method filtering for your gem
def tracer.relevant_method?(tp)
  path = tp.path
  return true if path.include?('your_gem_name')
  return true if path.include?('/lib/')
  false
end

tracer.start_trace(trace_id, env)

begin
  # Your gem code here with potentially malicious input
  YourGem.some_method_with_user_input('<script>alert("xss")</script>')
  YourGem.process_data("'; DROP TABLE users; --")
ensure
  trace_data = tracer.finish_trace(trace_id)
  
  # Send traces for analysis
  if trace_data && trace_data[:traces] && !trace_data[:traces].empty?
    sender = VulnChaser::AsyncTraceSender.instance
    sender.send_batch([trace_data])
  end
end
```

### Test Suite Integration (RSpec/Minitest)

Automatically capture traces during your test suite execution:

```ruby
# spec/spec_helper.rb or test/test_helper.rb
require 'vuln_chaser'

# Configure VulnChaser
VulnChaser.configure do |config|
  config.custom_paths = ['lib/your_project']
end

# RSpec Integration
RSpec.configure do |config|
  config.before(:each) do
    @vuln_chaser_tracer = VulnChaser::ExecutionTracer.new
    @vuln_chaser_trace_id = "rspec-#{SecureRandom.hex(4)}"
    
    # Mock environment for tracer
    env = {
      'REQUEST_METHOD' => 'GET',
      'PATH_INFO' => '/test',
      'rack.session' => {}
    }
    
    # Override relevant_method? to capture your project's calls
    def @vuln_chaser_tracer.relevant_method?(tp)
      path = tp.path
      return true if path.include?('your_project')
      return true if path.include?('/lib/')
      false
    end
    
    @vuln_chaser_tracer.start_trace(@vuln_chaser_trace_id, env)
  end
  
  config.after(:each) do
    if @vuln_chaser_tracer
      trace_data = @vuln_chaser_tracer.finish_trace(@vuln_chaser_trace_id)
      
      if trace_data && trace_data[:traces] && !trace_data[:traces].empty?
        # Send traces to vuln-chaser-core for analysis
        sender = VulnChaser::AsyncTraceSender.instance
        sender.send_batch([trace_data])
      end
    end
  end
end
```

### CLI Applications

For CLI tools and command-line applications:

```ruby
#!/usr/bin/env ruby
require 'vuln_chaser'

# Configure for CLI analysis
VulnChaser.configure do |config|
  config.custom_paths = ['lib', 'bin']
end

# Simple CLI wrapper
def analyze_cli_execution(&block)
  tracer = VulnChaser::ExecutionTracer.new
  trace_id = "cli-#{SecureRandom.hex(4)}"
  
  env = {
    'REQUEST_METHOD' => 'CLI',
    'PATH_INFO' => File.basename($0),
    'rack.session' => {}
  }
  
  def tracer.relevant_method?(tp)
    path = tp.path
    return true if path.include?('/lib/')
    return true if path.include?('/bin/')
    false
  end
  
  tracer.start_trace(trace_id, env)
  
  begin
    yield
  ensure
    trace_data = tracer.finish_trace(trace_id)
    
    if trace_data && trace_data[:traces] && !trace_data[:traces].empty?
      sender = VulnChaser::AsyncTraceSender.instance
      sender.send_batch([trace_data])
    end
  end
end

# Usage example
analyze_cli_execution do
  # Your CLI application logic
  user_input = ARGV[0] || gets.chomp
  process_user_arguments(user_input)
  execute_commands(user_input)
end
```

## Configuration Options

### Basic Configuration

```ruby
VulnChaser.configure do |config|
  # Paths to include in analysis
  config.custom_paths = ['lib/myapp', 'app/services']
  
  # Paths to exclude from analysis  
  config.excluded_paths = ['/assets', '/node_modules']
end
```

### Core API Connection

```ruby
# Environment variable (recommended)
export VULN_CHASER_CORE_URL=http://localhost:8000

# Or programmatically (for testing)
ENV['VULN_CHASER_CORE_URL'] = 'http://localhost:8000'
```

## Understanding the Analysis

VulnChaser captures and analyzes:

1. **Request Information**: HTTP method, path, parameters (sanitized)
2. **Method Call Chains**: Complete execution trace with security role classification
3. **Data Flow**: How user input flows through your application
4. **Security Context**: Authentication, authorization, validation steps
5. **Risk Assessment**: Direct interpolation, missing sanitization
6. **SOR Analysis**: Subject-Operation-Resource relationship evaluation

### Sample Analysis Output

The vuln-chaser-core will provide structured vulnerability reports:

```json
{
  "trace_id": "trace-001",
  "vulnerabilities": [
    {
      "owasp_category": "A03:2021",
      "type": "SQL Injection",
      "severity": "high",
      "confidence": 0.95,
      "affected_method": "UserSearch#build_query",
      "method_call_chain": [
        {
          "step": 1,
          "method": "UsersController#search",
          "file": "app/controllers/users_controller.rb",
          "line": 25,
          "role": "entry_point",
          "security_relevance": "high"
        },
        {
          "step": 2,
          "method": "UserSearch#build_query",
          "file": "app/services/user_search.rb", 
          "line": 15,
          "role": "sink",
          "security_relevance": "high"
        }
      ],
      "proof_of_concept": {
        "attack_vector": "GET /users/search?name='; DROP TABLE users; --",
        "expected_outcome": "Database table deletion via SQL injection",
        "example_payload": "'; DROP TABLE users; --"
      },
      "recommendation": "Use parameterized queries or ActiveRecord methods instead of string interpolation",
      "sor_context": "Untrusted user input flows directly to SQL execution without validation"
    }
  ],
  "sor_analysis": {
    "summary": {
      "risk_level": "critical",
      "total_violations": 2,
      "message": "High-risk data flow detected from untrusted source to dangerous sink"
    }
  }
}
```

## Supported Vulnerability Types

- **A01: Access Control** - Missing authorization, direct object references
- **A03: Injection** - SQL injection, command injection, code injection, XSS
- **A07: Authentication** - Authentication bypass, weak verification
- **A05: Security Misconfiguration** - Debug mode, information disclosure
- **A06: Vulnerable Components** - Outdated gems, known vulnerabilities

## Performance Impact

VulnChaser is designed for minimal performance impact:

- **TracePoint Overhead**: < 5% in typical applications
- **Memory Usage**: < 50MB additional memory
- **Network Impact**: Batched, asynchronous communication
- **Zero File I/O**: All operations in memory

## Troubleshooting

### Common Issues

1. **Core Connection Failed**:
   ```bash
   # Check if vuln-chaser-core is running
   curl http://localhost:8000/health
   
   # Set correct URL
   export VULN_CHASER_CORE_URL=http://your-core-host:8000
   ```

2. **No Traces Generated**:
   - Ensure tracer is properly configured with `relevant_method?` override
   - Check `custom_paths` configuration matches your file structure
   - Verify the code being tested actually calls instrumented methods

3. **High Memory Usage**:
   - Monitor the number of captured traces
   - Implement more restrictive `relevant_method?` filtering
   - Ensure vuln-chaser-core is receiving and processing traces

### Debug Mode

Enable debug logging to troubleshoot issues:

```ruby
# Enable detailed logging
VulnChaser.logger.level = Logger::DEBUG

# Monitor trace collection
puts "Trace count: #{tracer.instance_variable_get(:@traces).length}"
```

## Development

```bash
# Run tests
bundle exec rake spec

# Build gem
bundle exec rake build

# Install locally  
bundle exec rake install

# Test with a sample project
cd /path/to/test/project
bundle exec rspec --format documentation
```

## Related Projects

- **[vuln-chaser-core](https://github.com/Pirikara/vuln-chaser-core)**: Python-based analysis engine with LLM integration
- **Integration Examples**: See the test suite for examples of analyzing different types of Ruby projects

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/Pirikara/vuln-chaser-ruby](https://github.com/Pirikara/vuln-chaser-ruby).

This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/Pirikara/vuln-chaser-ruby/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Security Notice

This tool is designed for development and testing environments only. Do not use in production without careful security review. All sensitive data is automatically sanitized before transmission to the analysis core.

**Important**: VulnChaser requires a running instance of [vuln-chaser-core](https://github.com/Pirikara/vuln-chaser-core) to perform vulnerability analysis. The Ruby agent captures and sends execution traces; the actual AI-powered analysis happens in the core component.
