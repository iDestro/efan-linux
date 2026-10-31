# efan shell integration for bash and zsh.
#
# Install it from setup.sh, or add this line to ~/.bashrc / ~/.zshrc:
#   source ~/.config/efan/shell/efan.sh
#
# The wrapper is needed because a child process cannot change the proxy
# variables of the parent shell. `efan on` prints shell code; this function
# evaluates it in the current shell.

efan() {
    case "${1:-}" in
        on)
            local _efan_out
            _efan_out=$(EFAN_SHELL_WRAPPER=1 command efan on "${@:2}") || return $?
            eval "$_efan_out"
            ;;
        off)
            local _efan_out
            _efan_out=$(EFAN_SHELL_WRAPPER=1 command efan off "${@:2}") || return $?
            eval "$_efan_out"
            ;;
        *)
            command efan "$@"
            ;;
    esac
}

if [ -n "${BASH_VERSION:-}" ]; then
    _efan_complete() {
        local cur="${COMP_WORDS[COMP_CWORD]}"
        if [ "$COMP_CWORD" -eq 1 ]; then
            COMPREPLY=($(compgen -W "login refresh fetch list start stop restart on off node test proxy log status clash whmcs logout version" -- "$cur"))
        fi
    }
    complete -F _efan_complete efan 2>/dev/null || true
fi
