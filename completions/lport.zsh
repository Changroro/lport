# zsh completion for lport
# Install: copy to a directory in $fpath, e.g.
#   cp completions/lport.zsh /usr/local/share/zsh/site-functions/_lport

#compdef lport

local -a subcommands global_flags sort_keys kill_flags
subcommands=(
    'info:show full details for port(s)'
    'kill:terminate the process(es) listening on port(s)'
)
global_flags=(
    '--dev[show every listening port, including system daemons]'
    '--json[print dashboard / info output as JSON]'
    '--sort[sort dashboard rows by key]:key:(port pid process cpu mem uptime)'
    '(-h --help)'{-h,--help}'[print help]'
    '(-V --version)'{-V,--version}'[print version]'
)
kill_flags=(
    '-9[SIGKILL instead of SIGTERM]'
    '--force[SIGKILL instead of SIGTERM]'
    '-y[skip the confirmation prompt]'
    '--yes[skip the confirmation prompt]'
)

if (( CURRENT == 2 )); then
    _arguments -C \
        '1: :->first' \
        '*:: :->rest'
    case "$state" in
        first)
            _describe -t commands 'lport command' subcommands
            _describe -t options 'lport option' global_flags
            ;;
        rest)
            case "$words[2]" in
                kill)
                    _arguments -C '*:: :->args' \
                        $kill_flags \
                        '*:port number:_guard -d "port number"'
                    ;;
                info)
                    _message 'port number'
                    ;;
                *)
                    _describe -t options 'lport option' global_flags
                    ;;
            esac
            ;;
    esac
else
    case "$words[CURRENT-1]" in
        --sort)
            _values -w 'sort key' port pid process cpu mem uptime
            ;;
        *)
            _describe -t options 'lport option' global_flags
            ;;
    esac
fi
