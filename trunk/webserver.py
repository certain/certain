#!/usr/bin/python

import SocketServer
import SimpleHTTPServer
import os
import certmgr

if __name__ == '__main__':
    os.chdir(certmgr.config.get('web', 'WebDir'))
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("",
        certmgr.config.getint('web', 'ServerPort')), Handler)

    httpd.serve_forever()
