#!/bin/bash
VERSION=`head -n 1 debian/changelog | sed -e 's/^.* (\(.*\)).*/\1/'`
if [ -d "../tags/$VERSION" ]; then
  echo "Tag $VERSION already exists - do you need to update the changelog?"
  exit
fi

svn-buildpackage --svn-tag --svn-noautodch -k660241D2
