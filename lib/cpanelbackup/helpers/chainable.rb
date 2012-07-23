
require 'active_support/core_ext/kernel/singleton_class' unless respond_to?(:singleton_class)

# Makes includer "chainable".
# @example
#   class A
#     include Chainable
#			preinit :abc, :def
#   end
#   a = A.new.someparm(:adf).otherparm('abc').thirdparm(123)
#   a.someparm => :adf
#   a.abc => nil
module Chainable

	def method_missing(sym, *args, &block)
		# Attribute accessor that returns nil in case the var was `preinit`ed
		if args.size == 0 and self.class.instance_variable_defined?(:@declared_nils) and self.class.instance_variable_get(:@declared_nils).include?(sym)
			 return instance_variable_defined?("@#{sym}") ? instance_variable_get("@#{sym}") : nil
		end

		super if args.size != 1 or (sym.to_s.match(/(^.+\?$|method_missing)/))

		unless singleton_class.method_defined?(sym)
			# define accessor
			singleton_class.send(:attr_reader, sym)
		end

		# set the var
		instance_variable_set("@#{sym}", args.first)

		self
	end

	# For exceptions
	def to_s
		unless instance_variables.empty?
			super + ' <' + instance_variables.collect {|ivar| "#{ivar}=#{instance_variable_get(ivar).inspect}" }.join(' ') + '>'
		else
			super
		end
	end

	module ClassMethods
		# By default, these vars are nil
		def preinit(*vars)
			@declared_nils ||= []
			@declared_nils.push(*vars)
		end
	end

	def self.included(base)
		base.extend(ClassMethods)
	end
end
