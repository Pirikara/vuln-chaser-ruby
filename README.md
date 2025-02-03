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
```ruby:config/initializers/vuln_chaser.rb
VulnChaser.configure do |config|
  config.custom_paths = [
    'gems/hogehoge'
  ]
end
```
3. Add middleware in `config/application.rb`:
```ruby:config/application.rb
require 'vuln_chaser'
class Application < Rails::Application
  ...
  config.middleware.use VulnChaser::Middleware
  ...
end
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Pirikara/vuln-chaser. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the VulnChaser project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/Pirkara/vuln-chaser/blob/main/CODE_OF_CONDUCT.md).
