#!/bin/bash

function f() {
    case $COMP_CWORD in
        1)
            COMPREPLY=($($1 2>&1 | grep -Po "\b$2[a-z_]*(?= - )"));
            ;;
        2)
            if [[ -z "$2"  ]]
            then
                COMPREPLY=($(ls bins/))
            else
                COMPREPLY=($(ls $2*))
            fi
            ;;
        3)
            COMPREPLY=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17);
            ;;
    esac
}

complete -F f ./check
