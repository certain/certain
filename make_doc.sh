#!/bin/sh

#$@ allows insertion of extra options, e.g --pdf
sphinx-build -b html sphinx/ sphinx/build/

#Make man pages
pod2man man/certain.pod >man/certain.8
pod2man man/certain.cfg.pod >man/certain.cfg.5

