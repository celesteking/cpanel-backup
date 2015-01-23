source "http://rubygems.org"

# Specify your gem's dependencies in cpanelbackup.gemspec
gemspec

if `hostname` =~ /^yu/
	gem 'cpanel-helper', '~> 0.1', :path => '/code/ruby/cpanelhelper/'
else
	gem 'cpanel-helper', '~> 0.1'
end
