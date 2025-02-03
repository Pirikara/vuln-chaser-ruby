# VulnChaser
VulnChaser is a security analysis tool for Ruby on Rails applications that traces execution flows and detects potential vulnerabilities using LLM.

## Installation

Add this line to your application's Gemfile:

```bash
$ git clone https://github.com/Pirikara/vuln-chaser.git
```

Add to your Rails application's Gemfile:
```ruby
group: development do
  gem 'vuln_chaser', path: '/path/to/vuln-chaser'
end
```

## Setup
1. Generate the initializer:
```bash
$ bin/rails generate vuln_chaser:install
```
2. Configuration in `config/initializers/vuln_chaser.rb`
```ruby
require 'vuln_chaser'

VulnChaser.configure do |config|
  config.storage_path = Rails.root.join('tmp', 'vuln_chaser')
  config.excluded_paths = ['/health_check', '/assets']
  # Specify words matching the path of the file you want to trace in addition to Rails.root (optional)
  config.custom_paths = [
    'gems/hogehoge'
  ]
end
```
3. Add middleware in `config/application.rb`:
```ruby
require 'vuln_chaser'
class Application < Rails::Application
  ...
  config.middleware.use VulnChaser::Middleware
  ...
end
```
## Usage
### Trace generation
1. Start your Rails application
2. Make HTTP requests to your endpoints
3. Check `tmp/vuln_chaser` directory for generated trace files
4. Each trace file contains:
- Request endpoint
- Method call tree
- Source code locations (path and line number)
- Execution timestamps

Example trace file `tmp/vuln_chaser/users-index.json`:
```json
{
  "request_id": "abc123",
  "endpoint": "GET /users",
  "duration": 0.05,
  "traces": [
    {
      "request_id": "abc123",
      "event": "call",
      "defined_class": "UsersController",
      "method_id": "index",
      "source_code": "def index\n  @users = User.all\nend",
      "souce_location": [
        "app/controllers/users_controller.rb",
        10
      ],
      "timestamp": "20xx-01-01 00:00:00 UTC"
    },
    ...
  ]
}
```

### Advanced Tracing
VulnChaser can trace into specific gem or library code by configuring `custom_paths`. This is useful when you want to analyze the security of specific dependencies:

```ruby
VulnChaser.configure do |config|
  config.custom_paths = [
    'gems/hogehoge',
    'gems/hugahuga'
  ]
end
```
This configuration will:
- Track method calls into specified gem directories
- Record full execution paths through third-party code
- Help identify potential vulnerabilities in dependencies
- Provide deeper insight into library behavior

This feature is particularly valuable when:
- Auditing third-party authentication systems
- Analyzing authorization libraries
- Investigating ORM query builders
- Reviewing HTTP client implementations

### Security Analysis
Use the generated trace files with your preferred LLM to analyze:
- SQL injection vulnerabilities
- XSS vulnerabilities
- Authentication bypasses
- Authorization issues
- Input validation problems

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Pirikara/vuln-chaser. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the VulnChaser project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/Pirkara/vuln-chaser/blob/main/CODE_OF_CONDUCT.md).
