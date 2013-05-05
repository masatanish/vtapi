# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'vtapi/version'

Gem::Specification.new do |spec|
  spec.name          = "vtapi"
  spec.version       = Vtapi::VERSION
  spec.authors       = ["masatanish"]
  spec.email         = ["masatanish@gmail.com"]
  spec.description   = %q{Ruby gem library for VirusTotal Public API version2.0.}
  spec.summary       = %q{Ruby gem library for VirusTotal Public API version2.0.}
  spec.homepage      = "https:://github.com/masatanish/vtapi"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec", "~>2.13.0"
  spec.add_development_dependency "webmock", "~>1.11.0"

  spec.add_dependency "rest-client", "~>1.6.7"
end
