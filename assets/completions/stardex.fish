# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_stardex_global_optspecs
	string join \n algo= format= buffer-size= no-fail init-sql global-hash= summary-out= h/help V/version
end

function __fish_stardex_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_stardex_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_stardex_using_subcommand
	set -l cmd (__fish_stardex_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c stardex -n "__fish_stardex_needs_command" -l algo -d 'Hashing algorithm to use' -r -f -a "sha256\t''
blake3\t''
md5\t''
sha1\t''
xxh64\t''
xxh3\t''
xxh128\t''
none\t''"
complete -c stardex -n "__fish_stardex_needs_command" -l format -d 'Output format' -r -f -a "jsonl\t''
csv\t''
sql\t''"
complete -c stardex -n "__fish_stardex_needs_command" -l buffer-size -d 'Buffer size in bytes for reading file content (e.g. "64K", "1M")' -r
complete -c stardex -n "__fish_stardex_needs_command" -l global-hash -d 'Calculate a global hash for the entire tar stream' -r -f -a "sha256\t''
blake3\t''
md5\t''
sha1\t''
xxh64\t''
xxh3\t''
xxh128\t''
none\t''"
complete -c stardex -n "__fish_stardex_needs_command" -l summary-out -d 'Output path for the global summary (JSON)' -r -F
complete -c stardex -n "__fish_stardex_needs_command" -l no-fail -d 'Prevent broken pipes by draining stdin on error'
complete -c stardex -n "__fish_stardex_needs_command" -l init-sql -d 'Emit SQL schema and wrap inserts in BEGIN/COMMIT when using --format sql'
complete -c stardex -n "__fish_stardex_needs_command" -s h -l help -d 'Print help'
complete -c stardex -n "__fish_stardex_needs_command" -s V -l version -d 'Print version'
complete -c stardex -n "__fish_stardex_needs_command" -f -a "completions" -d 'Generate shell completions'
complete -c stardex -n "__fish_stardex_needs_command" -f -a "man" -d 'Generate man pages'
complete -c stardex -n "__fish_stardex_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c stardex -n "__fish_stardex_using_subcommand completions" -s h -l help -d 'Print help'
complete -c stardex -n "__fish_stardex_using_subcommand man" -s h -l help -d 'Print help'
complete -c stardex -n "__fish_stardex_using_subcommand help; and not __fish_seen_subcommand_from completions man help" -f -a "completions" -d 'Generate shell completions'
complete -c stardex -n "__fish_stardex_using_subcommand help; and not __fish_seen_subcommand_from completions man help" -f -a "man" -d 'Generate man pages'
complete -c stardex -n "__fish_stardex_using_subcommand help; and not __fish_seen_subcommand_from completions man help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
