
require 'cpanelbackup/helpers/chainable'

class CPanelBackup
	class Error < StandardError
		include Chainable
	end

	# Generic backup error
	class BackupError < Error
		preinit :processed
	end

	# pkgacct backup error
	class UserBackupError < BackupError
	end

	class RestoreError < Error
	end

	# restorepkg restore error
	class UserRestoreError < RestoreError
	end
end