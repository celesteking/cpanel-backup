
require 'cpanelbackup/version'

require 'active_support/core_ext/module/attribute_accessors'
require 'active_support/core_ext/hash/reverse_merge'
require 'fileutils'

require 'cpanelhelper'

require 'cpanelbackup/error'


class CPanelBackup
	# Logger instance
	attr_reader :logger
	# Backup directory path
	attr_reader :backup_dir

	# User list to operate on
	attr_reader :users

	# @param [Hash] opts
	# @option opts [String] logger
	# @option opts [String] backup_dir
	def initialize(*opts)
		opts = opts.extract_options!

		# Set ivars
		@logger = opts[:logger] || Logger.new($stderr)
		@backup_dir = opts[:backup_dir] || '/backups/cpanelbackup/accounts'
		@users = opts[:users] || []

		@backup_failures_limit = 3 # number of times user backup can fail

		@pkgacct_exe = '/scripts/pkgacct'
		@restoreacct_exe = '/scripts/restorepkg'
		@killacct_exe = '/scripts/killacct'

		check_cpanel_tools_presence

		logger.debug "[CPanelBackup] Initialized with backup_dir: #{backup_dir}, uid: #{Process.uid}, euid: #{Process.euid}."
	end

	# Back up CPanel accounts.
	# Places account backups into @backup_dir
	# @param [Hash] opts
	# @option opts [Array] :exclude
	# @option opts [Array] :include
	def backup(*opts)
		check_dir_access(backup_dir, true)

		cpanel_accounts = get_cpanel_account_list

		if users.empty?
			accounts_to_backup = cpanel_accounts
		else
			accounts_to_backup = cpanel_accounts & users
			logger.info "[CPanelBackup] Supplied users weren't found and won't be backed up: #{(users - accounts_to_backup).join(', ')}." unless (users - accounts_to_backup).empty?
		end

		if accounts_to_backup.empty?
			logger.error "No CPanel accounts to backup."
			raise BackupError, "No CPanel accounts to backup."
		end

		logger.debug "Backing up: " + accounts_to_backup.join(', ') + '.'

		backup_failures = 0

		backups = [] # array of backup file paths

		accounts_to_backup.each do |user|
			begin
				raise(BackupError.new.processed(backups), "Number of backup failures reached.") if backup_failures >= @backup_failures_limit

				backups << backup_account(user)

			rescue UserBackupError => exc
				logger.error "[CPanelBackup] #{exc.message}. Trying next user."
				backup_failures += 1
				next
			end

			backups
		end

	rescue CPanelHelper::Error => exc
		logger.error "Error occured while interacting with CPanelHelper: <#{exc.class}: #{exc.message}>"
		raise BackupError, exc
	end

	# Restore CPanel accounts from backup.
	# @param [Hash] opts
	# @option opts [Boolean,String] :reconstruct_ip {nil}
	#              [TrueClass]: Whether to retrieve IP from the archive and use it in acc restoral,
	#              [String]: Use specified IP when restoring account
	# @option opts [Boolean]    :kill {true} Kill account before restoral
	# @option opts [String]     :backup_file {} Backup file path
	# @option opts [Boolean]    :trick_homedir {false} Tar homedir files from _@backup_dir/home/user/_ into _@backup_dir/user/homedir.tar_, then append to :backup_file
	# @option opts [Boolean]    :trick_homedir_rm {false} Delete homedir files after _tricking_
	# @option opts [String]     :rsync_homedir {false} Rsync homedir files from this path to user's account
	# @option opts [Boolean]    :cpanel_dbflush_workaround {false} Work around CPanel poo in *users.db*
	# @return [Array<String>] list of restored usernames
	def restore(*opts)
		opts = opts.extract_options!

		check_dir_access(backup_dir, false)

		raise(ArgumentError, 'User list is empty') if users.empty?

		restores = []

		users.each do |user|
			begin
				restores << restore_account(user, opts)
			rescue UserRestoreError => exc
				logger.error "[CPanelBackup] #{exc.message}. Trying next user."
			end
		end

		restores
	end

	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	# Back up user account
	# @param [String] user
	# @return [String] backup file path
	def backup_account(user)

		invoke_and_log_cmd("#{@pkgacct_exe} --backup  --skiphomedir --skipacctdb --nocompress #{user} #{backup_dir}", 'pkgacct')
		raise(UserBackupError, "Failure while backing up #{user}") unless $?.success?

		File.join(backup_dir, "#{user}.tar.gz")
	end

	# Restore user account
	# @see [restore]
	def restore_account(user, *opts)
		default_opts = {
				:backup_file => File.join(@backup_dir, "#{user}.tar"),
				:kill => true,
				:reconstruct_ip => true,
				:trick_homedir => false,
		}
		(opts = opts.extract_options!).reverse_merge!(default_opts)

		if opts[:trick_homedir]
			raise NotImplementedError
			trick_homedir_restore(:backup_dir => @backup_dir, :backup_file => opts[:backup_file], :rm => opts[:trick_homedir_rm])
		end

		if opts[:kill]
			unless kill_account(user)
				logger.info "Note: No such account previously existed on this host."
			end
		end

		if opts[:cpanel_dbflush_workaround]
			unless cpanel_dbflush_workaround(user).nil?
				logger.info "Note: cpanel flush workaround didn't work, so restoral will probably fail."
			end
		end

		if opts[:reconstruct_ip] == true
			# Extract so-called CPanel user datafile to $stdout
			user_data = %x{tar --to-stdout -x -f  #{opts[:backup_file]} #{user}/cp/#{user}}
			unless user_data.match(/^IP=(.+)$/)
				raise(UserRestoreError, "Backup tar file has invalid data.")
			end
			opts[:reconstruct_ip] = $1
			logger.debug "[CPB:restore] Using dedicated IP: #{opts[:reconstruct_ip]} for account restore."
		end

		restore_add_args = "--ip=#{opts[:reconstruct_ip]}" if opts[:reconstruct_ip]

		invoke_and_log_cmd("#{@restoreacct_exe} #{restore_add_args} #{opts[:backup_file]}", 'restorepkg') do |output, stat|
			if output.include?('Account Creation Status: failed')
				raise(UserRestoreError, "Failure restoring #{user}")
			end
		end

		if opts[:rsync_homedir]
			begin
				rsync_files("#{opts[:rsync_homedir]}/#{user}/", "/home/#{user}/", :rm_source => opts[:rm_source])
			rescue BackupError => exc
				raise(UserRestoreError, "Failure rsyncing content for #{user}: #{exc.message}")
			end
		end

		if opts[:rm_source]
			File.unlink(opts[:backup_file])
		end

		user
	end

	# @param [String] user
	def kill_account(user)
		invoke_and_log_cmd("#{@killacct_exe} --force --user=#{user}", 'killacct')
		killacct_success = $?.success?

		FileUtils.rm_rf("/home/#{user}/")

		killacct_success
	end

	#
	# @param [String] src
	# @param [String] dst
	# @param [Hash] opts
	# @option opts [Bool] :rm_source Remove source after successful transfer
	# @raise [BackupError] on error
	def rsync_files(src, dst, *opts)
		opts = opts.extract_options!
		raise ArgumentError if src =~ %r{^[/\.]+$} or dst =~ %r{^[/\.]+$}

		logger.debug "{rsync} Sync'ing #{src} -> #{dst}"
		output = %x{rsync -rlAXtgo #{'--remove-source-files' if opts[:rm_source]} #{src} #{dst}}
		log_lines(output, 'rsync') unless output.strip.empty?

		raise BackupError unless $?.success?

		if opts[:rm_source]
			FileUtils.rm_rf(src, :secure => true)
		end

		true
	end

	def check_dir_access(dir, be_writable = false)
		begin
			Dir.new(dir)
			if be_writable
				raise(BackupError, "Dir #{dir} not writable.") unless File.writable?(dir)
			else
				raise(BackupError, "Dir #{dir} not readable.") unless File.readable?(dir)
			end
		rescue Errno::ENOENT
			begin
				# Create the dir recursively
				FileUtils.mkdir_p(dir, :mode => 0700)
			rescue SystemCallError => exc
				logger.error "Error while creating #{dir}: #{exc}"
				raise BackupError, exc
			end
		rescue SystemCallError => exc
			logger.error "Error while accessing #{dir}: #{exc}"
			raise BackupError, exc
		end
	end

	private
	# Get all existing CPanel accounts list
	# @return [Array<String>]
	def get_cpanel_account_list
		CPanelHelper::Local.find_accounts_by_string('.*', 'regexp').keys
	end

	def trick_homedir_restore(opts)
		# First, we tar homedir files
		#:backup_dir => @backup_dir, :backup_file => opts[:backup_file], :rm => opts[:trick_homedir_rm]) if opts[:trick_homedir]
	end

	def check_cpanel_tools_presence
		unless [@pkgacct_exe, @restoreacct_exe, @killacct_exe].all? {|exe| File.executable?(exe)}
			raise(BackupError, "CPanel tools unaccessible")
		end
	end

	# Wait until user.db gets rid of [user] records.
	# @return [NilClass] on success, otherwise a failure
	def cpanel_dbflush_workaround(user)
		cp_db_file = '/var/cpanel/databases/users.db'
		wait_time = 0
		(1..8).inject do |acc, step| # Sleep logarithmically increasing number of seconds
			%x{sync}
			matched = File.open(cp_db_file, 'r') do |fh|
				fh.fsync
				fh.sync = true
				sleep(0.1)
				matched = fh.read.match(/^[\s]+#{user}:/)
				fh.close
				matched
			end

			unless matched
				logger.debug "{cpanel_poo1} Worked after waiting #{wait_time.round} secs."
				break
			end

			sleep(acc)
			wait_time += acc
			acc * Math.log(6)
		end
	end

	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	def invoke_and_log_cmd(cmd, prefix = nil, &block)
		logger.debug "{#{prefix}}  -- START: #{cmd} --"
		output = %x{#{cmd}}
		log_lines(output, prefix)
		logger.debug "{#{prefix}}  -- END:   #{cmd} --"

		yield(output, $?) if block_given?

		$?.exitstatus
	end

	def log_lines(text, prefix = 'cpbck')
		text.strip.each_line do |line|
			next if line =~ /^[\s\t]*$/
			logger.debug "{#{prefix}}  #{line.strip}"
		end
	end
end
