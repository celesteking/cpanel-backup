
$:.push File.expand_path('../lib', __FILE__)
require 'cpanelbackup/version'

Gem::Specification.new do |s|
  s.name        = 'cpanel-backup'
  s.version     = CPanelBackup::Version.string
  s.authors     = CPanelBackup::Version.authors
  s.email       = %w(yuri@fused.internal)
  s.homepage    = 'http://dev.fused.net'
  s.summary     = %q{CPanel Backup helper}
  s.description = %q{CPanel Backup helper that helps you backup & restore CPanel accounts}

  s.files         = %w(README.textile Gemfile Rakefile) + Dir.glob('{bin,lib,spec}/**/*')
  s.test_files    = Dir.glob('{test,spec,features}/**/*')
  s.executables   = Dir.glob('{sbin/*')
  s.require_paths = %w(lib)
  s.bindir        = %w{sbin}

  s.add_development_dependency 'yard'

  s.add_runtime_dependency 'cpanel-helper', '~> 0.1'
  s.add_runtime_dependency 'activesupport', '~> 3.1'
end
