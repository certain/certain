#!/usr/bin/python

"""Certificate Management System"""

import sys
import socket
import time
import select
import ConfigParser
import threading
import cert
from optparse import OptionParser
import os
from OpenSSL import crypto
import logging
import logging.handlers

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

log = logging.getLogger('certmgr')
log.setLevel(getattr(logging, config.get('global', 'LogLevel')))
logformat = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
logconsole = logging.StreamHandler()
logconsole.setFormatter(logformat)
logconsole.setLevel(getattr(logging, config.get('global', 'LogLevel')))
log.addHandler(logconsole)


class MsgHandlerThread(threading.Thread):

    def __init__(self, msg, src):
        threading.Thread.__init__(self)
        self.msg = msg
        self.src = socket.gethostbyaddr(src[0])[0]

    def run(self):

        csrinf = cert.get_csr_info(crypto.load_certificate_request(
            crypto.FILETYPE_PEM, self.msg))

        if csrinf.CN != self.src:
            if config.get('manager', 'HostVerify') == "true":
                raise HostVerifyError
            elif config.get('manager', 'HostVerify') == "warn":
                log.warn("Hostname: %s doesn't match certificate CN: %s",
                         self.src, csrinf.CN)

        if config.getint('manager', 'AutoSign') == 1:
            log.info("Auto-signing enabled")
            #Sign the msg straight away
            capub = ca_cert_file()
            cakey = ca_key_file()
            certfile = cert_file(csrinf.CN)
            log.info("Signing Certificate")
            certobj = cert.sign_csr(cakey, capub,
                          crypto.load_certificate_request(
                              crypto.FILETYPE_PEM, self.msg),
                          config.getint('cert', 'CertLifetime'))

            with open(certfile, 'w') as f:
                log.info("Writing Certificate: %s", certfile)
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certobj))


        else:
            #Just save the CSR for later signing
            with open(csr_cache_file(self.src), 'w') as f:
                log.info("Writing CSR to cache: %s", csr_cache_file(self.src))
                f.write(self.msg)


class HostVerifyError(Exception):
    """Errors in Certificate Hostname Verification"""

    def __init__(self, e=None):
        log.error("Hostname doesn't match certificate CN value")


def ca_cert_file():
    return "%s/%s" % (config.get('global', 'CAPath'),
                      config.get('global', 'CACert'))


def ca_key_file():
    return "%s/%s" % (config.get('global', 'CAPrivatePath'),
                      config.get('global', 'CAKey'))


def cert_file(name):
    return "%s/%s.crt" % (config.get('global', 'CertPath'), name)


def key_file(name):
    return "%s/%s.key" % (config.get('global', 'PrivatePath'), name)


def csr_file(name):
    return "%s/%s.csr" % (config.get('global', 'CertPath'), name)


def csr_cache_file(name):
    return "%s/%s.csr" % (config.get('global', 'CSRCache'), name)


def make_certs():
        if config.getint('manager', 'IsMaster') == 1:
            #Generate a CA if no certs exist

            if not os.path.exists(ca_key_file()):
                log.info("Generating CA Certificates for Master")
                try:
                    CN = config.get('ca', 'CN')
                except:
                    CN = socket.getfqdn()

                (keyobj, certobj) = cert.make_ca(CN,
                             config.get('ca', 'OU'),
                             config.get('ca', 'O'),
                             config.get('ca', 'L'),
                             config.get('ca', 'ST'),
                             config.get('ca', 'C'),
                             config.getint('ca', 'CALifetime'))

                with open(ca_key_file(), 'w') as f:
                    f.write(
                        crypto.dump_privatekey(crypto.FILETYPE_PEM, keyobj))

                with open(ca_cert_file(), 'w') as f:
                    f.write(
                        crypto.dump_certificate(crypto.FILETYPE_PEM, certobj))
            else:
                log.warn("CA Certificates already exist")


        #Make client key and CSR if needed
        try:
            CN = config.get('cert', 'CN')
        except ConfigParser.NoOptionError:
            CN = socket.getfqdn()

        if not os.path.exists(key_file(CN)):
            log.info("Making Key and CSR for %s", CN)

            key = cert.make_key(config.getint('cert', 'Bits'))
            csr = cert.make_csr(key, CN,
                                config.get('cert', 'OU'),
                                config.get('cert', 'O'),
                                config.get('cert', 'L'),
                                config.get('cert', 'ST'),
                                config.get('cert', 'C'))

            with open(key_file(CN), 'w') as f:
                f.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

            with open(csr_file(CN), 'w') as f:
                f.write(crypto.dump_certificate_request(
                    crypto.FILETYPE_PEM, csr))

            send_csr()
        else:
            log.warn("Certificates already exist")


def check_status():

    if config.getint('manager', 'IsMaster') == 1:
        #Check CA certs
        try:
            capubfile = open(ca_cert_file())
        except IOError:
            log.error("Public CA file missing: %s", ca_cert_file())

        try:
            cakeyfile = open(ca_key_file())
        except IOError:
            log.error("Private CA file missing: %s", ca_key_file())

        cacertinf = crypto.load_certificate(
            crypto.FILETYPE_PEM, capubfile.read())

    #Get cert time without timezone chars
    notafter = cacertinf.get_notAfter()[0:14]
    #If notafter is less than a week away...
    if (time.mktime(time.strptime(notafter, '%Y%m%d%H%M%S'))
        - time.time()) < 604800:
        log.warn("CA Certificate %s expires in less than 7 days!", capubfile)

    log.info("Check Complete")


    #Check certs status
    try:
        CN = config.get('cert', 'CN')
    except:
        CN = socket.getfqdn()

    try:
        pubfile = open(cert_file(CN))
    except IOError:
        log.error("Public certificate file missing: %s", cert_file(CN))
        sys.exit(2)

    try:
        keyfile = open(key_file(CN))
        keyfile.close()
    except IOError:
        log.error("Private key file missing: %s", key_file(CN))
        sys.exit(2)

    certinf = crypto.load_certificate(
        crypto.FILETYPE_PEM, pubfile.read())

    #Get cert time without timezone chars
    notafter = certinf.get_notAfter()[0:14]
    #If notafter is less than a week away...
    if (time.mktime(time.strptime(notafter, '%Y%m%d%H%M%S'))
        - time.time()) < 604800:
        log.warn("Certificate %s expires in less than 7 days!", pubfile)


def csr_list():

    csrpath = config.get('global', 'CSRCache')
    csrfiles = os.listdir(csrpath)

    for file in csrfiles:
        log.info("Processing file %s:", file)
        with open(csrpath + "/" + file) as f:
            csr = crypto.load_certificate_request(
                crypto.FILETYPE_PEM, f.read())

        if (config.get('manager', 'HostVerify') == "warn") and (
            csr.get_subject().CN != file[:-4]):
            log.warn("Hostname doesn't match CN name")

        dosign = raw_input(
            "Sign CSR %s (CN=%s) [N/y/d]? " % (
                file, csr.get_subject().CN)).strip()

        if dosign.lower() == "y":
            log.info("Signing Certificate")

            certobj = cert.sign_csr(ca_key_file(), ca_cert_file(), csr,
                                    config.getint('cert', 'CertLifetime'))

            with open(cert_file(csr.get_subject().CN), 'w') as f:
                log.info("Writing Certificate: %s",
                         cert_file(csr.get_subject().CN))
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                certobj))
            log.info("Deleting CSR file: %s", file)
            os.remove(csrpath + "/" + file)

        elif dosign.lower() == "d":
            log.info("Deleting CSR file: %s", file)
            os.remove(csrpath + "/" + file)
        else:
            log.info("Skipping CSR file: %s", file)


def send_csr():
    #Send csr to host
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sendfile = ''
    if options.file:
        sendfile = options.file
    else:
        try:
            CN = config.get('cert', 'CN')
        except ConfigParser.NoOptionError:
            CN = socket.getfqdn()

    log.info("Sending CSR %s for signing", csr_file(CN))
    with open(csr_file(CN)) as f:
        s.sendto(f.read(), (config.get('global', 'ManagerAddress'),
                            config.getint('global', 'ManagerPort')))


def Daemon():

    if not os.path.exists(ca_cert_file()):
        log.error("Ca Certificate Missing.  Create this, or call --makecerts.")
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


def check_paths():

    for path in ['CertPath', 'PrivatePath', 'CAPath',
                 'CAPrivatePath', 'CSRCache']:

        if not os.path.exists(config.get('global', path)):
            try:
                os.mkdir(config.get('global', path), 0600)
            except OSError:
                log.error("Unable to create path: %s",
                          config.get('global', path))


if __name__ == "__main__":

    check_paths()

    parser = OptionParser()
    parser.add_option("-m", "--makecerts",
                      action="store_true", dest="makecerts",
                      help="Setup certificates on your system.")
    parser.add_option("-d", "--daemon",
                      action="store_true", dest="daemon",
                      help="Start Certificate Manager Daemon.")
    parser.add_option("-c", "--check",
                      action="store_true", dest="check",
                      help="Check status of own CA and Client Certificates.")
    parser.add_option("-x", "--sign",
                      action="store_true", dest="sign",
                      help="View and sign queued CSRs.")
    parser.add_option("-s", "--send",
                      action="store_true", dest="send",
                      help="Send a CSR file to the Certificate Manager.")
    parser.add_option("-f", "--file",
                      dest="file",
                      help="Specifies the CSR file to be sent with --send.")

    parser.set_defaults(makecerts=False, daemon=False, send=False)
    (options, args) = parser.parse_args()

    if options.makecerts:
        make_certs()

    if options.daemon:
        if config.getint('manager', 'IsMaster') == 1:
            Daemon()
        else:
            print "IsMaster not set in configuration file!"
            sys.exit(2)

    if options.send:
        send_csr()

    if options.sign:
        csr_list()

    if options.check:
        check_status()
