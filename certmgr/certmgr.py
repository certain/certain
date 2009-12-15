#!/usr/bin/python

"""Certificate Management System"""

import sys
import socket
import select
import ConfigParser
import threading
import cert
import StringIO
from optparse import OptionParser
from os import path
from OpenSSL import crypto

configfile = "certmgr.cfg"

config = ConfigParser.ConfigParser()
try:
    cfgfiles = config.read(configfile)
    if not cfgfiles:
        raise ConfigParser.Error(
            "Unable to read Configuration File: %s" % (configfile, ))
except (Exception), e:
    print e
    sys.exit(1)


class MsgHandlerThread(threading.Thread):

    def __init__(self, msg, src):
        threading.Thread.__init__(self)
        self.msg = msg
        self.src = src

    def run(self):

        csrinf = cert.get_csr_info(self.msg)

        if config.getint('manager', 'AutoSign') == 1:
            #Sign the msg straight away
            capub = "%s/%s" % (
                config.get('global', 'CAPath'),
                config.get('global', 'CACert'))
            cakey = "%s/%s" % (
                config.get('global', 'CAPrivatePath'),
                config.get('global', 'CAKey'))
            certfile = "%s/%s.crt" % (config.get('global', 'CertPath'),
                                      csrinf.CN)

            cert.sign_csr(cakey, capub, self.msg, certfile,
                          config.getint('cert', 'CertLifetime'))

        else:
            #write out csr to cache
            csrfile = "%s/%s.csr" % (config.get('global', 'CSRCache'),
                                     csrinf.CN)

            with open(csrfile, 'w') as f:
                f.write(self.msg)

#        if config.get('manager', 'HostVerify') == "true" or
#        config.get('manager', 'HostVerify') == "warn":
#            certs.get_cert_info(msg)


def check_certs(pub, key):

    if not path.exists(pub) or not path.exists(key):
        return "err"


def Daemon():

    if not path.exists(config.get('global', 'CAPath') + "/" +
                       config.get('global', 'CACert')):
        print "Ca Certificate Missing.  Create this, or call --init."
        sys.exit(2)

    #Listen for incoming messages
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(0)
    s.bind(('', config.getint('global', 'ManagerPort')))

    while True:
        read, write, error = select.select([s], [], [])
        if s not in read:
            continue
        msg, src = s.recvfrom(65535)
        thread = MsgHandlerThread(msg, src)
        thread.start()


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-i", "--init",
                      action="store_true", dest="init",
                      help="Setup certificates on your system.")
    parser.add_option("-d", "--daemon",
                      action="store_true", dest="daemon",
                      help="Start Certificate Manager Daemon.")
    parser.add_option("-s", "--send",
                      action="store_true", dest="send",
                      help="Send a CSR file to the Certificate Manager.")
    parser.add_option("-f", "--file",
                      dest="file",
                      help="Specifies the CSR file to be sent with --send.")

    parser.set_defaults(cminit=False, daemon=False, send=False)

    (options, args) = parser.parse_args()

    if options.init:

        if config.getint('manager', 'IsMaster') == 1:
            #Generate a CA if no certs exist

            pub = "%s/%s" % (
                config.get('global', 'CAPath'),
                config.get('global', 'CACert'))
            key = "%s/%s" % (
                config.get('global', 'CAPrivatePath'),
                config.get('global', 'CAKey'))

            if check_certs(pub, key) == "err":
                try:
                    CN = config.get('ca', 'CN')
                except:
                    CN = socket.getfqdn()

                capub = "%s/%s" % (
                    config.get('global', 'CAPath'),
                    config.get('global', 'CACert'))
                cakey = "%s/%s" % (
                    config.get('global', 'CAPrivatePath'),
                    config.get('global', 'CAKey'))
                (keyobj, certobj) = cert.make_ca(CN,
                             config.get('ca', 'OU'),
                             config.get('ca', 'O'),
                             config.get('ca', 'L'),
                             config.get('ca', 'ST'),
                             config.get('ca', 'C'),
                             config.getint('ca', 'CALifetime'))

                with open(cakey, 'w') as f:
                    f.write(
                        crypto.dump_privatekey(crypto.FILETYPE_PEM, keyobj))

                with open(capub, 'w') as f:
                    f.write(
                        crypto.dump_certificate(crypto.FILETYPE_PEM, certobj))

        else:
            #Make client key and CSR
            try:
                CN = config.get('cert', 'CN')
            except ConfigParser.NoOptionError:
                CN = socket.getfqdn()

            pub = "%s/%s.crt" % (config.get('global', 'CertPath'), CN)
            key = "%s/%s.key" % (config.get('global', 'PrivatePath'), CN)

            if check_certs(pub, key) == "err":

                keyfile = "%s/%s.key" % (config.get('global', 'PrivatePath'),
                                         CN)
                csrfile = "%s/%s.csr" % (config.get('global', 'CSRCache'),
                                         CN)
                key = cert.make_key(config.getint('cert', 'Bits'))
                csr = cert.make_csr(key, CN,
                                    config.get('cert', 'OU'),
                                    config.get('cert', 'O'),
                                    config.get('cert', 'L'),
                                    config.get('cert', 'ST'),
                                    config.get('cert', 'C'))

                with open(keyfile, 'w') as f:
                    f.write(
                        crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

                with open(csrfile, 'w') as f:
                    f.write(crypto.dump_certificate_request(
                        crypto.FILETYPE_PEM, csr))


    if options.daemon:
        if config.getint('manager', 'IsMaster') == 1:
            Daemon()
        else:
            print "IsMaster not set in configuration file!"
            sys.exit(2)


    if options.send:
        #Send csr to host

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if options.file:
            sendfile = options.file
        else:
            try:
                CN = config.get('cert', 'CN')
            except ConfigParser.NoOptionError:
                CN = socket.getfqdn()
            sendfile = "%s/%s.csr" % (config.get('global', 'CSRCache'), CN)

            with open(sendfile) as f:
                s.sendto(f.read(), (config.get('global', 'ManagerAddress'),
                                    config.getint('global', 'ManagerPort')))
