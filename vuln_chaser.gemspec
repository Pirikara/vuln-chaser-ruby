
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "vuln_chaser/version"

Gem::Specification.new do |spec|
  spec.name          = "vuln_chaser"
  spec.version       = VulnChaser::VERSION
  spec.authors       = ["Tomoya Yamashita"]
  spec.email         = ["pirikara077@gmail.com"]

  spec.summary       = %q{Vuln Chaser}
  spec.description   = %q{Vuln Chaser}
  spec.homepage      = "https://github.com/Pirikara/vuln-chaser"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["homepage_uri"] = spec.homepage
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    Dir["{lib,bin}/**/*", "*.gemspec", "README*", "LICENSE*", "Rakefile"].select { |f| File.file?(f) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "rails", ">= 7.0"
  spec.add_dependency "method_source", "~> 1.0"

  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rake", "~> 13.0"
end
