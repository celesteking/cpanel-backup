# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "cpanelbackup/version"

Gem::Specification.new do |s|
  s.name        = "cpanel-backup"
  s.version     = CPanelBackup::Version.string
  s.authors     = CPanelBackup::Version.authors
  s.email       = %w(yuri@fused.com)
  s.homepage    = "http://dev.fused.net"
  s.summary     = %q{CPanel Backup helper}
  s.description = %q{CPanel Backup helper that helps you backup & restore CPanel accounts}

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- {sbin,bin}/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  s.bindir = %w{sbin}

  s.add_development_dependency 'yard'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'shoulda-matchers'

  s.add_runtime_dependency 'cpanel-helper', '~> 0.1'
  s.add_runtime_dependency 'activesupport', '>= 3.0.8'

end
