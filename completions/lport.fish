# fish completion for lport
# Install: copy to ~/.config/fish/completions/lport.fish

complete -c lport -f

# subcommands
complete -c lport -n '__fish_use_subcommand' -a info -d 'Show full details for port(s)'
complete -c lport -n '__fish_use_subcommand' -a kill -d 'Terminate the process(es) listening on port(s)'

# global flags
complete -c lport -l dev -d 'Show every listening port, including system daemons'
complete -c lport -l json -d 'Print dashboard / info output as JSON'
complete -c lport -l sort -d 'Sort dashboard rows by key' -xa 'port pid process cpu mem uptime'
complete -c lport -s h -l help -d 'Print help'
complete -c lport -s V -l version -d 'Print version'

# kill flags (only after `kill`)
complete -c lport -n '__fish_seen_subcommand_from kill' -s 9 -d 'SIGKILL instead of SIGTERM'
complete -c lport -n '__fish_seen_subcommand_from kill' -l force -d 'SIGKILL instead of SIGTERM'
complete -c lport -n '__fish_seen_subcommand_from kill' -s y -l yes -d 'Skip the confirmation prompt'
