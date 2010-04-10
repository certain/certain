#!/usr/bin/python

import SocketServer
import SimpleHTTPServer
import os
import certain
import errno


def main():
    dir = certain.config.get('webserver', 'WebDir')
    try:
        os.makedirs(dir)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise
    os.chdir(dir)
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("",
        certain.config.getint('webserver', 'ServerPort')), Handler)

    httpd.serve_forever()

if __name__ == '__main__':
    main()
