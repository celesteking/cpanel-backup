
class CPanelBackup
	module Version
		MAJOR = 0
		MINOR = 2
		RELEASE = 1

		AUTHORS = {
				'Yuri Arabadji' => [2012..2015, 2018,2023]
		}

		def self.string
			"#{MAJOR}.#{MINOR}.#{RELEASE}"
		end

		def self.authors
			AUTHORS.collect {|ap| [ap[1]].flatten.join(', ') + ' ' + ap[0] }
		end
	end
end
