#!/bin/bash

cwd=$(dirname $(readlink -f $0))


function do_format() {
    if [ -e $cwd/clang-format ];then
        chmod +x $cwd/clang-format
        clang_format=$cwd/clang-format
    else
        clang_format=$(find ~/.vscode-server/ -name "clang-format" | head -n 1)
    fi

    if [[ -z $clang_format ]];then
        clang_format=$(which clang-format)
        if [[ -z "$clang_format" ]];then
            echo "can't find clang-format"
            exit -1
        fi
    fi

    echo $@
    $clang_format -style=file   -fallback-style=google --Wno-error=unknown -i $@
}
export -f do_format

#find . -regex '.*\.\(cpp\|hpp\|cc\|c\|h\|cxx\)' -exec $clang_format -style=file -i {} \;
find $cwd/../drivers/  -regex '.*\.\(cpp\|hpp\|cc\|c\|h\|cxx\)' -exec bash -c 'do_format "$@"' bash  {} \;

