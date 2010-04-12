#!/bin/sh

#$@ allows insertion of extra options, e.g --pdf
epydoc -v -o apidoc --name Certain $@ certain

#Make man pages
pod2man man/certain.pod >man/certain.8
pod2man man/certain.cfg.pod >man/certain.cfg.5

