#!/usr/bin/python

"""Certificate Management System"""

import sys
import socket
import time
import select
import ConfigParser
import threading
import os
from OpenSSL import crypto
import httplib
from urlparse import urlparse
import logging
from contextlib import closing, nested
import errno
import tempfile
import pysvn
import abc
import smtplib
from email.mime.text import MIMEText

__all__ = ['StoreHandler',
           'check_status',
           'sign_csr',
           'send_csr',
           'make_certs',
           'launch_daemon',
           'parse_config',
           'check_paths',
           'config',
           'key_from_file',
           'cert_from_file',
           'ca_cert_file',
           'ca_key_file',
           'cert_file',
           'key_file',
           'csr_file',
           'csr_cache_file',
           'check_cacerts',
           'make_ca',
           'make_key',
           'make_csr',
           'sign_csr',
           'check_expiry']


class HostVerifyError(Exception):
    """Errors in Certificate Hostname Verification"""

    def __init__(self, args="Hostname doesn't match certificate CN value"):
        Exception.__init__(self, args)


class CACertError(Exception):
    """Error opening CA Certificates"""

    def __init__(self, args="Errors opening CA Certificates"):
        Exception.__init__(self, args)


class LazyConfig(object):
    """Class which calls parse_config the first time it is referenced.

    Allows user to override the default configfile value before it is used

    """

    def __getattr__(self, s):
        parse_config()
        return getattr(config, s)


class StoreBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def setup(self):
        """Setup this specific store object."""
        return

    @abc.abstractmethod
    def fetch(self):
        """Retrieve certificates from the store."""
        return

    @abc.abstractmethod
    def write(self, certobj):
        """Write certificate to the central store."""
        return

    @abc.abstractmethod
    def checkpoint(self):
        """Checkpoint any pending actions on the store."""
        return

    def __enter__(self):
        self.setup()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.checkpoint()


class StoreHandler(object):
    """Class to handle different store types"""

    @classmethod
    def dispatch(cls, name):
        return getattr(cls, name, cls.storeerror)()

    @staticmethod
    def storeerror():
        """Error method - default for getattr to deal with unknown StoreType"""

        log.warn("Unknown StoreType")

    class none(StoreBase):

        def setup(self):
            pass

        def checkpoint(self):
            pass

        def fetch(self):
            pass

        def write(self, certobj):
            pass

    class webdav(StoreBase):

        def setup(self):
            pass

        def checkpoint(self):
            pass

        def fetch(self):
            pass

        def write(self, certobj):
            """Puts certificate on a webdav server"""

            url = urlparse(config.get('global', 'StoreUrl'))
            certfile = "%s/%s.crt" % (url.path, certobj.get_subject().CN)

            log.debug("Writing cert: %s to server: %s", certfile, url)

            if url.scheme == "https":
                web = httplib.HTTPSConnection(url.netloc)
            else:
                web = httplib.HTTPConnection(url.netloc)

            web.request('PUT', certfile,
                        (crypto.dump_certificate(
                            crypto.FILETYPE_PEM, certobj)))
            resp = web.getresponse()
            if not 200 <= resp.status < 300:
                log.error("Error writing to webdav server: %s", resp.status)
                return

    class svn(StoreBase):

        def __init__(self):
            self.client = pysvn.Client()
            self.client.callback_ssl_server_trust_prompt = lambda trust_data: (
                True, 8, False) #8 = Cert not yet trusted - i.e auto-trust
            self.lock = threading.Lock()

        def setup(self):
            log.debug("Setting up svn repository (co)")
            self.storedir = config.get('global', 'StoreDir')
            with self.lock:
                self.client.checkout(config.get('global', 'StoreUrl'),
                                    self.storedir)

        def checkpoint(self):
            log.debug("Doing checkin of store")
            with self.lock:
                self.client.checkin(self.storedir, "Adding certificates")

        def fetch(self):
            with self.lock:
                self.client.update(self.storedir)

        def write(self, certobj):
            certfile = "%s/%s.crt" % (self.storedir, certobj.get_subject().CN)
            log.debug("Storing cert: %s", certfile)

            with nested(self.lock, tempfile.NamedTemporaryFile(
                    dir=os.path.dirname(certfile),
                    delete=False)) as (locked, f_crt):
                self.client.update(self.storedir)
                f_crt.write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, certobj))

            os.rename(f_crt.name, certfile)

            try:
                with self.lock:
                    self.client.add(certfile)
            except ARealException:
                #If add fails, its because its already under VC
                pass


class ExpiryNotifyHandler(object):
    """Class to handle different expiry notification methods"""

    @classmethod
    def dispatch(cls, name, certobj):
        return getattr(cls, name, cls.notifyerror)(certobj)

    @staticmethod
    def notifyerror(certobj):
        """Error method - default to deal with unknown Notify types"""

        log.warn("Unknown Notification Type")

    @staticmethod
    def log(certobj):
        """Log cert expiry messages"""

        log.warn("Certificate is about to expire: %s",
                 certobj.get_subject().CN)

    @staticmethod
    def email(certobj):
        """Email a warning about cert expiry"""

        log.debug("Emailing about cert expiry")
        msg = MIMEText(
"""CA Expiry Warning\n\n
CA %s expires at: %s\n
Please update your CA certificate!""" % (certobj.get_subject().CN,
                time.ctime(float(certobj.get_notAfter()[0:14]))))

        msg['To'] = config.get('email', 'ToAddress')
        msg['From'] = config.get('email', 'FromAddress')
        msg['Subject'] = "CA Expiry Warning"

        s = smtplib.SMTP(config.get('email', 'SMTPServer'))
        s.sendmail(msg['From'],
                   msg['To'],
                   msg.as_string())


class MsgHandlerThread(threading.Thread):

    def __init__(self, store, msg, src, cakey, cacert):
        threading.Thread.__init__(self)
        self.store = store
        self.msg = msg
        self.src = socket.gethostbyaddr(src[0])[0]
        self.cakey = cakey
        self.cacert = cacert

    def run(self):

        csr = crypto.load_certificate_request(
            crypto.FILETYPE_PEM, self.msg)
        CN = csr.get_subject().CN

        if CN != self.src:
            if config.getboolean('global', 'HostVerify'):
                log.error("Hostname: %s doesn't match certificate CN: %s",
                         self.src, CN)
                raise HostVerifyError
            else:
                log.warn("Hostname: %s doesn't match certificate CN: %s",
                         self.src, CN)

        if config.getboolean('global', 'AutoSign'):
            log.info("Auto-signing enabled, signing certificate")
            try:
                certobj = sign_csr(self.cakey, self.cacert, csr,
                                        config.getint('cert', 'CertLifetime'))
            except Exception, e:
                log.warn("Signing failed. Will save for later signing.")
                log.warn(str(e))

            else:
                with tempfile.NamedTemporaryFile(
                    dir=os.path.dirname(cert_file(CN)),
                    delete=False) as f_crt:
                    log.info("Writing certificate: %s", cert_file(CN))
                    f_crt.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                        certobj))

                os.rename(f_crt.name, cert_file(CN))

                log.info("Storing Signed Cert")
                self.store.write(certobj)
                self.store.checkpoint()
                return

        #Just save the CSR for later signing
        with tempfile.NamedTemporaryFile(
            dir=os.path.dirname(csr_cache_file(self.src)),
            delete=False) as f_csr:
            log.info("Writing CSR to cache: %s", csr_cache_file(self.src))
            f_csr.write(self.msg)

            os.rename(f_csr.name, csr_cache_file(self.src))


class CertExpiry(object):

    def __init__(self, cakey, cacert, store):
        self.cacert = cacert
        self.cakey = cakey
        self.store = store

    def expiry_timer(self):

        self.store.fetch()
        crtpath = "%s/%s.%s" % (config.get('global', 'StoreDir'),
                             config.get('cert', 'CN'), "crt")

        try:
            crt = cert_from_file(crtpath)
        except Exception:
            log.warn("Certificate missing. Call --makecerts.")
        else:
            crttimerlength = check_expiry(crt) - config.getint(
                'cert', 'ExpiryDeadline')
            log.debug("Cert expiry timer waiting for %d seconds",
                crttimerlength)

            if crttimerlength <= config.getint('global', 'NotifyFrequency'):
                crttimerlength = config.getint('global', 'NotifyFrequency')
                log.debug("Resetting cert timer wait to %d seconds",
                    crttimerlength)
            self.tcrt = threading.Timer(crttimerlength,
                                        self.expiry_action, [crt])
            self.tcrt.daemon = True
            self.tcrt.start()

        if self.cacert is not None:
            catimerlength = check_expiry(self.cacert) - config.getint(
                'ca', 'ExpiryDeadline')
            log.debug("CA expiry timer waiting for %d seconds", catimerlength)
            if catimerlength <= config.getint('global', 'NotifyFrequency'):
                catimerlength = config.getint('global', 'NotifyFrequency')
                log.debug("Resetting CA timer wait to %d seconds",
                    catimerlength)
            self.tca = threading.Timer(catimerlength,
                                       self.expiry_action,
                                       [self.cacert],
                                       {'caoverwrite': True,
                                        'notify': True})
            self.tca.daemon = True
            self.tca.start()

    def expiry_action(self, cert, caoverwrite=False, notify=False):
        """Launched when expired cert timer completes"""

        if notify:
            for notifytype in config.get(
                'global', 'ExpiryNotifiers').replace(' ', '').split(','):
                ExpiryNotifyHandler.dispatch(notifytype, cert)

        #Need to allow overwriting of CA
        #Re-sending of CSR will happen for free
        make_certs(caoverwrite)

        #Update the local cert store
        self.store.fetch()

        self.expiry_timer()


class Polling(object):

    def __init__(self, store, polltime):
        self.store = store
        self.polltime = polltime

    def poll_timer(self):
        if self.polltime:
            log.debug("Starting poll timer for %d seconds", self.polltime)
            self.timer = threading.Timer(self.polltime, self.poll_action)
            self.timer.daemon = True
            self.timer.start()

    def poll_action(self):
        log.debug("Poll: calling store.fetch")
        self.store.fetch()
        self.poll_timer()


def ca_cert_file():
    return "%s/%s" % (config.get('global', 'CAPath'),
                      config.get('global', 'CACert'))


def ca_key_file():
    return "%s/%s" % (config.get('global', 'CAPrivatePath'),
                      config.get('global', 'CAKey'))


def make_key(bits=2048):
    """Create RSA key

    bits: Bits for RSA key (defaults to 2048)

    Returns the Pkey object

    """

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)

    return key


def make_csr(key, CN,
             OU="CertMgr Dept", O="CertMgr Org",
             L="CertMgr City", ST="CertMgr State", C="UK"):
    """Make a certificate request from an RSA key

    key: String containing key
    CN: Common Name (aka CA hostname)
    OU: Organisational Unit (CertMgr Dept)
    O: Organisation (CertMgr Org)
    L: Location (CertMgr City)
    ST: State (CertMgr State)
    C: Country (UK)

    Returns an X509 object

    """

    csr = crypto.X509Req()
    name = csr.get_subject()
    name.C = C
    name.ST = ST
    name.L = L
    name.O = O
    name.OU = OU
    name.CN = CN

    csr.set_pubkey(key)
    csr.sign(key, 'md5')

    return csr


def sign_csr(cakey, cacert, csr, lifetime=60 * 60 * 24 * 365):
    """Sign certificate request.

    cakey: CA key object
    cacert: CA Public Certificate object
    csr: Certificate Request string
    lifetime: Lifetime of signed cert in seconds (60*60*24*365 = 1 year)

    Returns X509 object

    """

    cert = crypto.X509()
    cert.set_pubkey(csr.get_pubkey())
    cert.set_subject(csr.get_subject())
    ##FIXME## Serial numbers should increment!
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(lifetime)
    cert.set_issuer(cacert.get_subject())
    cert.sign(cakey, 'md5')

    return cert


def make_ca(key, CN, OU="CertMgr Dept", O="CertMgr Org", L="CertMgr City",
            ST="CertMgr State", C="UK", lifetime=60 * 60 * 24 * 365 * 10):
    """Generate a certificate authority

    CN: Common Name
    OU: Organisational Unit (CertMgr Dept)
    O: Organisation (CertMgr Org)
    L: Location (CertMgr City)
    ST: State (CertMgr State)
    C: Country (UK)
    lifetime: Certificate lifetime in seconds (60*60*24*365*10 = 10 years)

    """

    csr = make_csr(key, CN, OU, O, L, ST, C)

    cacert = crypto.X509()
    cacert.set_issuer(csr.get_subject())
    cacert.set_subject(csr.get_subject())
    cacert.set_pubkey(csr.get_pubkey())

    cacert.set_serial_number(0)
    cacert.gmtime_adj_notBefore(0)
    cacert.gmtime_adj_notAfter(lifetime)
    cacert.sign(key, 'md5')

    return cacert


def key_from_file(keyfilename):
    """Read a private key from file"""

    with open(keyfilename) as f:
        return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())


def cert_from_file(certfilename):
    """Read a certificate from file"""

    with open(certfilename) as f:
        return crypto.load_certificate(crypto.FILETYPE_PEM, f.read())


def cert_file(name):
    return "%s/%s.crt" % (config.get('global', 'CertPath'), name)


def key_file(name):
    return "%s/%s.key" % (config.get('global', 'PrivatePath'), name)


def csr_file(name):
    return "%s/%s.csr" % (config.get('global', 'CertPath'), name)


def csr_cache_file(name):
    return "%s/%s.csr" % (config.get('global', 'CSRCache'), name)


def creat(filename, flag=os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0777):
    """A thin wrapper around os.open and os.fdopen to return a file-like
    object.

    With the default arguments, ask for a file to be created only if it
    doesn't already exist. If it does, expect an OSError exception  "e"
    with e.errno == errno.EEXIST.

    """
    return os.fdopen(os.open(filename, flag, mode), 'w')


def parse_config(configfile="/etc/certmgr/certmgr.cfg"):
    global config
    config = ConfigParser.ConfigParser({'CN': socket.getfqdn()})
    if not config.read(configfile):
        raise ConfigParser.Error(
            "Unable to read Configuration File: %s" % (configfile, ))
    log.setLevel(getattr(logging, config.get('global', 'LogLevel')))
    logconsole.setLevel(getattr(logging, config.get('global', 'LogLevel')))


def make_certs(caoverwrite=False):
    if config.getboolean('global', 'IsMaster'):
        #Generate a CA if no certs exist

        log.info("Generating CA certificates for master")
        CN = config.get('ca', 'CN')

        #We never want to overwrite a key file,so do nothing if one exists
        try:
            with creat(ca_key_file(), mode=0666) as f_key:
                key = make_key(config.getint('ca', 'Bits'))
                f_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        except OSError, e:
            if e.errno != errno.EEXIST: # File exists
                raise
            key = key_from_file(ca_key_file())

        if caoverwrite:
            #We want to overwrite the CA
            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(ca_cert_file()), delete=False) as f_cacert:
                cacert = make_ca(key, CN,
                                      config.get('ca', 'OU'),
                                      config.get('ca', 'O'),
                                      config.get('ca', 'L'),
                                      config.get('ca', 'ST'),
                                      config.get('ca', 'C'),
                                      config.getint('ca', 'CALifetime'))
                f_cacert.write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))

            os.rename(f_cacert.name, ca_cert_file())
        else:
            #Only create if it doesn't already exist
            try:
                with creat(ca_cert_file(), mode=0666) as f_cacert:
                    cacert = make_ca(key, CN,
                                          config.get('ca', 'OU'),
                                          config.get('ca', 'O'),
                                          config.get('ca', 'L'),
                                          config.get('ca', 'ST'),
                                          config.get('ca', 'C'),
                                          config.getint('ca', 'CALifetime'))
                    f_cacert.write(
                        crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))
            except OSError, e:
                if e.errno != errno.EEXIST: # File exists
                    raise

    #Make client key and CSR if needed
    CN = config.get('cert', 'CN')

    log.info("Making key and CSR for %s", CN)

    #We never want to overwrite a key file, so do nothing if it already exists.
    try:
        with creat(key_file(CN), mode=0666) as f_key:
            key = make_key(config.getint('cert', 'Bits'))
            f_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    except OSError, e:
        if e.errno != errno.EEXIST: # File exists
            raise
        key = key_from_file(key_file(CN))

    with tempfile.NamedTemporaryFile(
        dir=os.path.dirname(csr_file(CN)), delete=False) as f_csr:
        csr = make_csr(key, CN,
                            config.get('cert', 'OU'),
                            config.get('cert', 'O'),
                            config.get('cert', 'L'),
                            config.get('cert', 'ST'),
                            config.get('cert', 'C'))
        f_csr.write(
            crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))

    os.rename(f_csr.name, csr_file(CN))

    if config.getboolean('client', 'AutoSend'):
        send_csr()


def check_expiry(certobj):
    """Return expiry time in seconds

    certobj: OpenSSL X509 Object

    """

    return int(time.mktime(time.strptime(
        certobj.get_notAfter()[0:14],
        '%Y%m%d%H%M%S')) - time.time())


def check_status():
    if config.getboolean('global', 'IsMaster'):
        #Check CA certs
        try:
            with open(ca_cert_file()) as cacertfile:
                cacert = crypto.load_certificate(
                    crypto.FILETYPE_PEM, cacertfile.read())
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            log.error("Public CA file missing: %s", ca_cert_file())
            sys.exit(2)
        else:
            if check_expiry(cacert) < config.get('ca', 'ExpiryDeadline'):
                log.warn("CA certificate %s expires in less than 7 days!",
                        cacertfile)

        try:
            open(ca_key_file()).close()
        except IOError, e:
            if e.errno != errno.ENOENT:
                raise
            log.error("Private CA file missing: %s", ca_key_file())
            sys.exit(2)


    #Check certs status
    CN = config.get('cert', 'CN')

    try:
        with open(cert_file(CN)) as certfile:
            certinf = crypto.load_certificate(
                crypto.FILETYPE_PEM, certfile.read())
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        log.error("Public certificate file missing: %s", e)
        sys.exit(2)
    else:
        #Get cert time without timezone chars
        notafter = certinf.get_notAfter()[0:14]
        #If notafter is less than a week away...
        if (time.mktime(time.strptime(notafter, '%Y%m%d%H%M%S'))
            - time.time()) < 604800:
            log.warn("Certificate %s expires in less than 7 days!", certfile)

    try:
        open(key_file(CN)).close()
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        log.error("Private key file missing: %s", e)
        sys.exit(2)


def sign_csr():
    if not config.getboolean('global', 'IsMaster'):
        log.error("Not running as a Certificate Master")
        sys.exit(2)

    cakey = cacert = None
    try:
        cakey, cacert = check_cacerts()
    except CACertError:
        log.error("Can't sign CSR without CA Certs")
        sys.exit(2)

    csrpath = config.get('global', 'CSRCache')

    store = StoreHandler.dispatch(config.get('global', 'StoreType'))
    store.setup()

    for csr_file in os.listdir(csrpath):
        log.info("Processing file %s:", csr_file)
        with open(os.path.join(csrpath, csr_file)) as f:
            csr = crypto.load_certificate_request(
                crypto.FILETYPE_PEM, f.read())

        if csr.get_subject().CN != os.path.splitext(csr_file)[0]:
            if config.getboolean('global', 'HostVerify'):
                log.error("Hostname doesn't match CN and HostVerify is set")
                raise HostVerifyError
            else:
                log.warn("Hostname doesn't match CN - continuing anyway")

        dosign = raw_input(
            "Sign CSR %s (CN=%s) [N/y/d(elete)]? " % (
                csr_file, csr.get_subject().CN)).strip().lower()

        if dosign == "y":
            log.info("Signing certificate")

            certobj = sign_csr(cakey, cacert, csr,
                                    config.getint('cert', 'CertLifetime'))

            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(cert_file(csr.get_subject().CN)),
                delete=False) as f_crt:
                log.info("Writing certificate: %s",
                         cert_file(csr.get_subject().CN))
                f_crt.write(crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                certobj))

            os.rename(f_crt.name, cert_file(csr.get_subject().CN))

            log.info("Deleting CSR file: %s", file)
            os.remove(os.path.join(csrpath, file))

            log.info("Storing Signed Cert")
            store.write(certobj)

        elif dosign == "d":
            log.info("Deleting CSR file: %s", csr_file)
            os.remove(os.path.join(csrpath, csr_file))
        else:
            log.info("Skipping CSR file: %s", csr_file)

        store.checkpoint()


def send_csr(file=None):
    "Send csr to host"

    sendfile = file or csr_file(config.get('cert', 'CN'))

    log.info("Sending CSR %s for signing", sendfile)
    with nested(
            open(sendfile),
            closing(socket.socket(type=socket.SOCK_DGRAM))) as (f, s):
        s.sendto(f.read(), (config.get('global', 'MasterAddress'),
                            config.getint('global', 'MasterPort')))


def launch_daemon():
    cakey = cacert = None # Won't be used if auto-signing is turned off.
    if config.getboolean('global', 'AutoSign'):
        try:
            cakey, cacert = check_cacerts()
        except CACertError:
            log.error("Can't perform auto-signing without CA Certs")
            sys.exit(2)

    store = StoreHandler.dispatch(config.get('global', 'StoreType'))
    store.setup()

    certexpiry = CertExpiry(cakey, cacert, store)
    certexpiry.expiry_timer()

    try:
        polling = Polling(store, config.getint('global', 'PollTimer'))
        polling.poll_timer()
    except ConfigParser.Error:
        pass

    if config.get('global', 'IsMaster'):
        #Listen for incoming messages
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setblocking(0)
        s.bind((config.get('global', 'MasterAddress'),
                config.getint('global', 'MasterPort')))

        while True:
            read, write, error = select.select([s], [], [])
            if s not in read:
                continue
            msg, src = s.recvfrom(65535)
            thread = MsgHandlerThread(store, msg, src, cakey, cacert)
            thread.start()


def check_cacerts():
    try:
        cakey = key_from_file(ca_key_file())
        cacert = cert_from_file(ca_cert_file())
        return cakey, cacert
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        log.error("CA certificate Missing.  Create this, or call --makecerts.")
        raise CACertError


def check_paths():
    log.debug("Checking (and creating) paths")

    for path, mode in [('RootPath', 0777),
                 ('CertPath', 0777),
                 ('CSRCache', 0777),
                 ('PrivatePath', 0700),
                 ('CAPath', 0700),
                 ('CAPrivatePath', 0700)]:
        try:
            os.makedirs(config.get('global', path), mode)
        except OSError, e:
            if e.errno == errno.EEXIST:
                continue
            log.error("Unable to create path: %s: %s",
                config.get('global', path),
                e)


log = logging.getLogger('certmgr')
log.setLevel(logging.CRITICAL)
logformat = logging.Formatter('%(levelname)s %(message)s')
logconsole = logging.StreamHandler()
logconsole.setFormatter(logformat)
logconsole.setLevel(logging.CRITICAL)
log.addHandler(logconsole)

#Calling config.* methods will call parse_config, reading the default
#config file if the importing app hasn't previously
#done certmgr.parse_config(configfile="...")
config = LazyConfig()
