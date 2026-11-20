# bash completion for lport
# Install: source this file, or copy it to a directory in $fpath, e.g.
#   cp completions/lport.bash /usr/local/share/bash-completion/completions/lport

_lport() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local subcommands="info kill"
    local global_flags="--dev --json --sort --help --version -h -V"
    local sort_keys="port pid process cpu mem uptime"
    local kill_flags="-9 --force -y --yes"

    # First word: subcommand or global flag
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=($(compgen -W "${subcommands} ${global_flags}" -- "${cur}"))
        return 0
    fi

    # Value of --sort
    if [[ "${prev}" == "--sort" ]]; then
        COMPREPLY=($(compgen -W "${sort_keys}" -- "${cur}"))
        return 0
    fi

    # After `kill`: kill flags (ports are free-form numbers, not completed)
    if [[ "${COMP_WORDS[1]}" == "kill" ]]; then
        case "${cur}" in
            -*)
                COMPREPLY=($(compgen -W "${kill_flags}" -- "${cur}"))
                return 0
                ;;
        esac
        COMPREPLY=()
        return 0
    fi

    # Otherwise complete global flags
    case "${cur}" in
        -*)
            COMPREPLY=($(compgen -W "${global_flags}" -- "${cur}"))
            return 0
            ;;
    esac
    COMPREPLY=()
    return 0
}

complete -F _lport lport
