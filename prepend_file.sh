#!/bin/sh -xe

# ----------------------------------------------------------------------------
# SSLCAUDIT - a tool for automatingsecurity audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT 
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------------

# After execution of "./prepend.sh F1 F2" file F2 will contain F2 + F1"
# Example:
#  find . -name \*.py | xargs -n1 -IF ./prepend_file.sh F COPYING.HEADER

[ $# -eq 2 ]

mv "$1" "$1.orig"
cat "$2" "$1.orig" > "$1"
rm "$1.orig"

