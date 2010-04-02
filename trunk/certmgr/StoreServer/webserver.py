#!/usr/bin/python

import SocketServer
import SimpleHTTPServer
import os
import certmgr
import errno

def main():
    dir = certmgr.config.get('webserver', 'WebDir')
    try:
        os.makedirs(dir)
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise
    os.chdir(dir)
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("",
        certmgr.config.getint('webserver', 'ServerPort')), Handler)

    httpd.serve_forever()

if __name__ == '__main__':
    main()
