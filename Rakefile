require 'erb'
require 'rubygems/package_task'

@gemname = 'rbenv-rubygem-cpanel-backup'
@specfile = "#{@gemname}.spec"

begin
  require 'yard'
  YARD::Rake::YardocTask.new do |t|
    t.files   = ['lib/**/*.rb']
  end
rescue LoadError
end

spec = Gem::Specification.load(Dir.glob('*.gemspec').first)
Gem::PackageTask.new(spec) {}

desc 'Build SRPM'
task srpm: [:gem, :template_spec] do |t|
  sh "rpmbuild -bs -D '_sourcedir #{Dir.pwd}/pkg' -D '_srcrpmdir #{Dir.pwd}/pkg' #{@specfile}"
  $?.success? || raise('Failure building SRPM')
end

task :template_spec do
  spectempl = "#{@specfile}.in"

  gem_version = spec.version
  ruby_version = RUBY_VERSION

  erb = ERB.new(File.read(spectempl))
  erb.filename = spectempl
  File.write(@specfile, erb.result(binding), mode: 'w+')
end

