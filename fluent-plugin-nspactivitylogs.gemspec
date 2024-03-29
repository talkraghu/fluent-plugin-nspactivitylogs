# -*- encoding: utf-8 -*-
Gem::Specification.new do |s|
  s.name          = 'fluent-plugin-nspactivitylogs'
  s.version       = '0.1.0'
  s.authors       = ['Raghavendra K', 'Prakashbabu Siddaraddi']
  s.email         = ['talkraghu@gmail.com']
  s.description   = %q{fluent plugin to insert on table}
  s.summary       = %q{fluent plugin to insert on table}
  s.homepage      = 'https://github.com/talkraghu/fluent-plugin-nspactivitylogs'
  s.license       = 'Apache-2.0'

  s.files         = `git ls-files`.split($\)
  s.executables   = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.test_files    = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths = ['lib']

  s.add_dependency 'fluentd', ['>= 0.14.15', '< 2']
  s.add_dependency 'pg'

  s.add_development_dependency 'rake'
  s.add_development_dependency 'test-unit', '~> 3.2.0'
end
