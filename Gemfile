source "https://rubygems.org"

# Specify your gem's dependencies in cpanelbackup.gemspec
gemspec

if ENV['GEMDEV_PATH'] 
	gem 'cpanel-helper', '~> 0.1', path: (ENV['GEMDEV_PATH'] + '/cpanelhelper/')
else
	gem 'cpanel-helper', '~> 0.1'
end
