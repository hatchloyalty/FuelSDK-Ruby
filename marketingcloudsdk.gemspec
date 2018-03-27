
# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'marketingcloudsdk/version'

Gem::Specification.new do |spec|
  spec.name = 'marketingcloudsdk'
  spec.version       = MarketingCloudSDK::VERSION
  spec.authors       = ['Ashok Magar']
  spec.email         = ['amagar@salesforce.com']
  spec.description   = 'API wrapper for SOAP and REST API with Salesforce Marketing Cloud (ExactTarget)'
  spec.summary       = 'Fuel Client Library for Ruby'
  spec.homepage      = 'https://github.com/ExactTarget/FuelSDK-Ruby'
  spec.license       = ''

  spec.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(samples|test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.3'
  spec.add_development_dependency 'guard', '~> 1.1'
  spec.add_development_dependency 'guard-rspec', '~> 2.0'
  spec.add_development_dependency 'rake', '~>0.9'
  spec.add_development_dependency 'rspec', '~> 2.0'

  spec.add_dependency 'json', '~>1.8', '>= 1.8.1'
  spec.add_dependency 'jwt', '~>1.0', '>= 1.0.0'
  spec.add_dependency 'savon', '2.2.0'
end
