#!/usr/bin/python

import dulwich
import os
import certain
import errno


def main():
    dir = certain.config.get('gitdaemon', 'WorkDir')
    try:
        os.makedirs(dir)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise
    try:
        backend = dulwich.GitBackend(dir)
    except dulwich.NotGitRepository:
        dulwich.Repo.init_bare(dir)
        backend = dulwich.server.GitBackend(dir)
    server = dulwich.server.TCPGitServer(backend, '')

    server.serve_forever()

if __name__ == '__main__':
    main()
