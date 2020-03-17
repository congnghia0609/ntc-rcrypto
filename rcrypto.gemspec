# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rcrypto/version'

Gem::Specification.new do |spec|
  spec.name          = "ntc-rcrypto"
  spec.version       = Rcrypto::VERSION
  spec.authors       = ["nghiatc"]
  spec.email         = ["congnghia0609@gmail.com"]

  spec.summary       = %q{ntc-rcrypto ruby cryptography.}
  spec.description   = %q{ntc-rcrypto is module ruby cryptography.}
  spec.homepage      = "https://github.com/congnghia0609/ntc-rcrypto"
  spec.license       = 'Apache-2.0'
  spec.required_ruby_version = Gem::Requirement.new(">= 2.3.0")

  # spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/congnghia0609/ntc-rcrypto"
  spec.metadata["changelog_uri"] = "https://github.com/congnghia0609/ntc-rcrypto"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  # spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
  #   `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  # end
  spec.files = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
end
