#!/usr/bin/python

"""Certificate Management System"""

import sys
import socket
import time
import select
import ConfigParser
import threading
import os
from M2Crypto import m2, RSA, X509, EVP, ASN1
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
from functools import wraps
from collections import namedtuple
import uuid
import base64
import dulwich
import stat
import datetime


__all__ = ['StoreHandler',
           'pending_csrs',
           'sign_csr',
           'send_csr',
           'make_ca',
           'make_cert',
           'launch_daemon',
           'parse_config',
           'check_paths',
           'config',
           'key_from_file',
           'cert_from_file',
           'ca_cert_file',
           'ca_key_file',
           'ca_csr_file',
           'cert_file',
           'key_file',
           'csr_file',
           'csr_cache_file',
           'check_cacerts',
           'make_cacert',
           'make_key',
           'make_csr',
           'check_expiry']


def logexception(func):
    """Redirect any unexpected tracebacks.

    It is desired that unhandled exceptions in threads save the exception and
    destroy the thread. Wrap the run method of a subclass of threading.Thread
    to obtain this behaviour.

    """

    @wraps(func)
    def run(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            log.exception("Exception caught in thread %s",
                threading.current_thread().name)
    return run


def synchronised(lock):
    """Synchronisation decorator."""

    def wrap(f):
        @wraps(f)
        def newFunction(*args, **kw):
            with lock:
                return f(*args, **kw)
        return newFunction
    return wrap


class HostVerifyError(Exception):
    """Errors in Certificate Hostname Verification."""

    def __init__(self, args="Hostname doesn't match certificate CN value"):
        Exception.__init__(self, args)


class CACertError(Exception):
    """Error opening CA Certificates."""

    def __init__(self, args="Errors opening CA Certificates"):
        Exception.__init__(self, args)


class VerboseExceptionFormatter(logging.Formatter):

    def formatException(self, ei):
        stack = []
        tb = ei[2]

        while tb:
            stack.append(tb.tb_frame)
            tb = tb.tb_next
        s = logging.Formatter.formatException(self, ei)
        s += "\nLocals by frame, innermost last"
        for frame in stack:
            s += "\nFrame %s in %s at line %s\n" % (frame.f_code.co_name,
                                                  frame.f_code.co_filename,
                                                  frame.f_lineno)
            for key, value in frame.f_locals.items():
                s += "\t%20s = " % key
                #We have to be careful not to cause a new error in our error
                #printer! Calling str() on an unknown object could cause an
                #error we don't want.
                try:
                    s += str(type(value)) + ' '
                    s += str(value)
                except Exception, e:
                    s += str(e)
                    s += "<ERROR WHILE PRINTING VALUE>"
                s += '\n'
        return s


class LazyConfig(object):
    """Class which calls parse_config the first time it is referenced.

    Allows user to override the default configfile value before it is used.

    """

    def __getattr__(self, result):
        parse_config()
        return getattr(config, result)


class StoreBase(object):
    """Abstract base class for StoreHandler 'plugins'."""

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
    """Class to handle different store types."""

    @classmethod
    def dispatch(cls, name):
        """Dispatch a store object to handle this type of Store.

        Returns an object of the appropriate type, or None. Also logs a message
        if the store type could not be found.

        """

        cls.name = name
        return getattr(cls, name, cls.storeerror)()

    @classmethod
    def storeerror(cls):
        """Error method. Default for getattr to deal with unknown StoreType."""

        log.warn("Unknown StoreType: " + cls.name)

    class none(StoreBase):
        """'Empty' none StoreHandler plugin."""

        def setup(self):
            pass

        def checkpoint(self):
            pass

        def fetch(self):
            pass

        def write(self, certobj):
            pass

        def __str__(self):
            return "StoreHandler.none()"

    class webdav(StoreBase):
        """Webdav StoreHandler plugin."""

        def __init__(self):
            super(webdav, self).__init__()
            self.url = urlparse(config.get('store', 'StoreUrl'))

            if self.url.scheme == "https":
                self.web = httplib.HTTPSConnection(self.url.netloc)
            else:
                self.web = httplib.HTTPConnection(self.url.netloc)

        def setup(self):
            pass

        def checkpoint(self):
            pass

        def fetch(self):
            pass

        def write(self, certobj):
            """Puts certificate on a webdav server."""

            certfile = "%s/%s.crt" % (self.url.path, certobj.get_subject().CN)
            log.debug("Writing cert: %s to server: %s", certfile, self.web)
            self.web.request('PUT', certfile, certobj.as_pem())
            resp = self.web.getresponse()
            if not 200 <= resp.status < 300:
                raise Exception(
                    "Error writing to webdav server: %d" % resp.status)

        def __str__(self):
            return "StoreHandler.webdav()"

    class svn(StoreBase):
        """Subversion StoreHandler plugin."""

        def __init__(self):
            super(svn, self).__init__()
            self.client = pysvn.Client()
            self.client.callback_ssl_server_trust_prompt = lambda trust_data: (
                True, 8, False) #8 = Cert not yet trusted - i.e auto-trust
            self.lock = threading.Lock()
            self.storedir = config.get('global', 'StoreDir')

        def setup(self):
            """Perform an svn checkout."""

            log.debug("Setting up svn repository (co)")
            with self.lock:
                self.client.checkout(config.get('store', 'StoreUrl'),
                                     self.storedir)

        def checkpoint(self):
            """Perform an svn checkin."""

            log.debug("Doing checkin of store")
            with self.lock:
                self.client.checkin(self.storedir, "Adding certificates")

        def fetch(self):
            """Perform an svn update."""

            with self.lock:
                self.client.update(self.storedir)

        def write(self, certobj):
            """Write the certificate to the local svn working copy."""

            certfile = "%s/%s.crt" % (self.storedir, certobj.get_subject().CN)
            log.debug("Storing cert: %s", certfile)

            with nested(self.lock, tempfile.NamedTemporaryFile(
                    dir=os.path.dirname(certfile),
                    delete=False)) as (locked, f_crt):
                self.client.update(self.storedir)
                f_crt.write(certobj.as_pem())

            os.rename(f_crt.name, certfile)

            try:
                with self.lock:
                    self.client.add(certfile)
            except pysvn.ClientError:
                log.exception("Failed to add %s to repository", certfile)

        def __str__(self):
            return "StoreHandler.svn()"

    class git(StoreBase):
        """Git StoreHandler plugin."""

        lock = threading.RLock()

        def __init__(self):
            # Dulwich stores the path literally, so if it is relative, the
            # code is no longer thread safe. abspath works around this.
            path = os.path.abspath(config.get('global', 'StoreDir'))
            try:
                self.repo = dulwich.repo.Repo(path)
            except dulwich.errors.NotGitRepository:
                try:
                    os.makedirs(path)
                except OSError, e:
                    if e.errno != errno.EEXIST:
                        raise
                self.repo = dulwich.repo.Repo.init(path)
                self.repo.refs['HEAD'] = 'ref: refs/heads/master'
            # Work around dulwich 0.50 bug.
            def try_again(func):
                @wraps(func)
                def new_add_object(*args, **kwargs):
                    try:
                        return func(*args, **kwargs)
                    except OSError, e:
                        if e.errno != errno.EEXIST:
                            raise
                        return func(*args, **kwargs)
                return new_add_object
            self.repo.object_store.add_object = try_again(
                self.repo.object_store.add_object)

        @synchronised(lock)
        def setup(self):
            client, path = self._get_transport_and_path(
                            config.get('store', 'StoreUrl'))
            f, commit = self.repo.object_store.add_pack()
            remote_refs = client.fetch_pack(path,
                self.repo.object_store.determine_wants_all,
                self.repo.get_graph_walker(),
                f.write, open(os.devnull, 'w').write)
            commit()
            # We need to decide if the HEAD is a descendant of the branch we
            # are about to merge. If it is, merging again will destroy any
            # commits
            try:
                branch = self.repo.object_store[
                    self.repo.refs['refs/heads/master']]
            except KeyError:
                branch = None
            if not self._branch_has_object(branch, remote_refs['HEAD']):
                self.repo.refs['refs/heads/master'] = remote_refs['HEAD']
                tree = self.repo.tree(
                    self.repo.get_object(self.repo.head()).tree)
                self._unpack(tree, self.repo.path)

        @synchronised(lock)
        def checkpoint(self):
            client, path = self._get_transport_and_path(
                            config.get('store', 'StoreUrl'))
            # Will raise ChecksumMismatch if the server refuses to update
            # because this is not a fast forward FIXME
            def get_changed_refs(old_refs):
                return {"refs/heads/master":
                        self.repo.refs['refs/heads/master']}
            assert get_changed_refs(None)['refs/heads/master']
            client.send_pack(path, get_changed_refs,
                self.repo.object_store.generate_pack_contents)

        @synchronised(lock)
        def fetch(self):
            self.setup()

        @synchronised(lock)
        def write(self, certobj):
            tree = self.repo.tree(self.repo.get_object(self.repo.head()).tree)
            blob = dulwich.objects.Blob.from_string(certobj.as_pem())
            tree.add(0100644, certobj.get_subject().CN + ".crt", blob.id)

            commit = dulwich.objects.Commit()
            commit.tree = tree.id
            commit.author = '<' + config.get('ca', 'Email') + '>'
            commit.committer = commit.author
            commit.commit_time = commit.author_time = int(time.time())
            commit.author_timezone = dulwich.objects.parse_timezone("0000")
            commit.commit_timezone = commit.author_timezone
            commit.encoding = "UTF-8"
            commit.message = u'Add certificate for "%s"\n' % (
                certobj.get_subject().CN, )
            commit.parents = [self.repo.refs['refs/heads/master']]

            self.repo.object_store.add_object(blob)
            self.repo.object_store.add_object(tree)
            self.repo.object_store.add_object(commit)
            self.repo.refs['refs/heads/master'] = commit.id
            self._unpack(tree, self.repo.path)

        def _unpack(self, tree, path='.'):
            for name, mode, sha1 in tree.iteritems():
                if stat.S_ISREG(mode):
                    with open(os.path.join(path, name), 'w') as f:
                        f.write(self.repo.object_store.get_raw(sha1)[1])
                        os.fchmod(f.fileno(), mode)
                elif stat.S_ISDIR(mode):
                    try:
                        # Don't bother with chmod. git doesn't store the mode.
                        os.mkdir(os.path.join(path, name))
                    except OSError, e:
                        if e.errno != errno.EEXIST:
                            raise
                    _unpack(self.repo.object_store[sha1],
                            os.path.join(path, name))

        @staticmethod
        def _get_transport_and_path(uri):
            """Parse a URI pointing to a git repository.

            Returns a dulwich.client object.

            """
            # Stolen from /usr/bin/dulwich
            for handler, transport in (
                    ("git://", dulwich.client.TCPGitClient),
                    ("git+ssh://", dulwich.client.SSHGitClient)):
                if uri.startswith(handler):
                    host, path = uri[len(handler):].split("/", 1)
                    return transport(host), "/" + path
            # if its not git or git+ssh, try a local url..
            return dulwich.client.SubprocessGitClient(), uri

        def _branch_has_object(self, commit, sha):
            """Traverse the list of commits on this branch and return True if
            we find sha."""

            if not commit:
                return False
            if commit.id == sha:
                return True
            for parent in commit.parents:
                if self._branch_has_object(
                        self.repo.object_store[parent], sha):
                    return True
            return False

        def __str__(self):
            return "StoreHandler.git()"


class ExpiryNotifyHandler(object):
    """Class to handle different expiry notification methods."""

    @classmethod
    def dispatch(cls, name, certobj):
        """Dispatch a method to handle this type of expiry.

        Pass a certificate object as the only parameter. These methods may
        return anything, but usually None.

        """

        cls.name = name
        return getattr(cls, name, cls.notifyerror)(certobj)

    @classmethod
    def notifyerror(cls, certobj):
        """Error method - default to deal with unknown Notify types."""

        log.warn("Unknown notification type: " + cls.name)

    @staticmethod
    def log(certobj):
        """Log cert expiry messages."""

        log.warn("Certificate is about to expire: %s",
                 certobj.get_subject().CN)

    @staticmethod
    def email(certobj):
        """Email a warning about cert expiry."""

        log.debug("Emailing about cert expiry")
        msg = MIMEText(
"""CA Expiry Warning

CA %s expires at: %s
Please update your CA certificate!""" % (certobj.get_subject().CN,
                                         str(certobj.get_not_after())))

        msg['To'] = config.get('ca', 'Email')
        msg['From'] = config.get('email', 'FromAddress')
        msg['Subject'] = "CA Expiry Warning"

        smtp = smtplib.SMTP(config.get('email', 'SMTPServer'))
        smtp.sendmail(msg['From'], msg['To'], msg.as_string())
        smtp.quit()


def closing_by_name(name):
    """Like contextlib.closing, but close an attribute of the current object
    given its name."""

    def decorate_closing(func):
        @wraps(func)
        def new(*args, **kwargs):
            with closing(getattr(args[0], name)):
                return func(*args, **kwargs)
        return new
    return decorate_closing


class MsgHandlerThread(threading.Thread):
    """Handle incoming messages in separate threads."""

    def __init__(self, store, sock, src, cakey, cacert):
        threading.Thread.__init__(self)
        self.store = store
        self.sock = sock
        self.src = socket.gethostbyaddr(src[0])[0]
        self.cakey = cakey
        self.cacert = cacert

    @logexception
    @closing_by_name('sock')
    def run(self):
        sockfile = self.sock.makefile('rw', 0)
        msg = sockfile.readlines()
        sig = msg[0]
        pem = ''.join(msg[1:])
        if pem[-1:] == '\n':
            pem = pem[:-1]
        csr = X509.load_request_string(pem)
        CN = csr.get_subject().CN

        if CN != self.src:
            error_message = "Hostname: %s doesn't match certificate CN: %s" % (
                            self.src, CN)
            if config.getboolean('master', 'HostVerify'):
                log.error(error_message)
                self.sock.send("FAIL\n" + error_message + "\n")
                return
            else:
                log.warn(error_message)

        verified = False
        try:
            pub = cert_from_file(cert_store_file(CN)).get_pubkey()
        except (IOError, X509.X509Error):
            pass
        else:
            if not verify_data(sig, pem, pub):
                log.error("Signature verification failed reading CSR from %s.",
                          self.src)
                self.sock.send("FAIL\nSignature verification failed.\n")
                return
            verified = True

        if verified or config.getboolean('master', 'AutoSign'):
            log.info("Signing certificate")
            try:
                certobj = sign_csr(self.cakey, self.cacert, csr,
                                        config.getint('cert', 'CertLifetime'))
            except X509.X509Error:
                log.exception("Signing failed. Will save for later signing.")
            else:
                log.info("Storing Signed Cert")
                self.store.write(certobj)
                self.store.checkpoint()
                self.sock.send('OK\n' + certobj.as_pem())
                return

        #Just save the CSR for later signing
        with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(csr_cache_file(self.src)),
                delete=False) as f_csr:
            log.info("Writing CSR to cache: %s", csr_cache_file(self.src))
            f_csr.write(pem)

            os.rename(f_csr.name, csr_cache_file(self.src))
        self.sock.send('OK\n')

    def __str__(self):
        return 'MsgHandlerThread(src=%r)' % self.src


class CertExpiry(object):
    """Timer threads to watch for certificate expiry"""

    def __init__(self, cakey, cacert, store):
        self.cacert = cacert
        self.cakey = cakey
        self.store = store
        self.tcrt = self.tca = None

    def expiry_timer(self, cert=None):
        """Set timers for certificates passed or in the store.

        Carefully examine the certificate given as an argument or in the local
        store, attempting to create one if it doesn't already exist. If one
        is available, set a timer to run expiry_action. If not, set a shorter
        timer to do the same.

        """

        certtimerlength = 0
        #Always try to get a cert straight away, otherwise it will be at
        #least <NotifyFrequency> before one comes into being
        if not cert:
            self.store.fetch()
            try:
                cert = cert_from_file(cert_store_file(
                    config.get('cert', 'CN')))
            except (X509.X509Error, IOError):
                log.exception("Certificate missing")
                try:
                    cert = make_cert()
                except Exception:
                    pass
        if cert:
            certtimerlength = check_expiry(cert) - config.getint(
                'cert', 'ExpiryDeadline')
            log.debug("Cert expiry timer waiting for %s",
                datetime.timedelta(seconds=certtimerlength))

        if certtimerlength <= config.getint('master', 'NotifyFrequency'):
            certtimerlength = config.getint('master', 'NotifyFrequency')
            log.debug("Resetting cert timer wait to %s",
                      datetime.timedelta(seconds=certtimerlength))

        if self.tcrt:
            self.tcrt.cancel()
        self.tcrt = threading.Timer(certtimerlength,
                                    self.expire_cert, [cert])
        self.tcrt.name = "Cert expiry timer"
        self.tcrt.daemon = True
        self.tcrt.start()

        if self.cacert is not None and config.get('global', 'IsMaster'):
            catimerlength = check_expiry(self.cacert) - config.getint(
                'ca', 'ExpiryDeadline')
            log.debug("CA expiry timer waiting for %s",
                datetime.timedelta(seconds=catimerlength))
            if catimerlength <= config.getint('master', 'NotifyFrequency'):
                catimerlength = config.getint('master', 'NotifyFrequency')
                log.debug("Resetting CA timer wait to %s",
                    datetime.timedelta(seconds=catimerlength))
            if self.tca:
                self.tca.cancel()
            self.tca = threading.Timer(catimerlength, self.expire_ca)
            self.tca.name = "CA expiry timer"
            self.tca.daemon = True
            self.tca.start()

    @logexception
    def expire_ca(self):
        """Launched when expired ca timer completes.

        Trigger the Notify Handler to send any configured notifications, then
        call make_ca to generate a new CA.

        """

        try:
            for notifytype in config.get(
                'master', 'ExpiryNotifiers').replace(' ', '').split(','):
                ExpiryNotifyHandler.dispatch(notifytype, self.cacert)
            self.cacert = make_ca()
        finally:
            self.expiry_timer()

    @logexception
    def expire_cert(self, cert):
        """Launched when expired cert timer completes.

        If passed a certificate, attempt to refresh it by calling make_cert.
        If not, attempt to retrieve one from the store. If this doesn't work,
        call make_cert anyway. If a new cert was obtained, do nothing more.

        In all cases, call expiry_timer again to set a new timer with
        (hopefully) a new certificate.

        """

        try:
            if not cert:
                self.store.fetch()
                try:
                    cert = cert_from_file(cert_store_file(
                        config.get('cert', 'CN')))
                except (IOError, X509.X509Error):
                    # Expected, especially when starting for the first time.
                    pass
                else:
                    return

            #Need to allow overwriting of CA
            #Re-sending of CSR will happen for free
            cert = make_cert()
        finally:
            self.expiry_timer(cert)

    def __str__(self):
        return 'CertExpiry(store=%r)' % self.store


class Polling(object):
    """Container for timer to poll for store changes."""

    def __init__(self, store, polltime):
        self.store = store
        self.polltime = polltime

    def poll_timer(self):
        """Set up a timer to check the store."""

        if self.polltime:
            log.debug("Starting poll timer for %s",
                datetime.timedelta(seconds=self.polltime))
            self.timer = threading.Timer(self.polltime, self.poll_action)
            self.timer.daemon = True
            self.timer.start()

    @logexception
    def poll_action(self):
        """Fetch new certificates, then set another timer."""

        try:
            log.debug("Poll: calling store.fetch")
            self.store.fetch()
        finally:
            self.poll_timer()

    def __str__(self):
        return 'Polling(store=%r, polltime=%r)' % (self.store, self.polltime)


class Sequence(object):
    """Interface for producers of integer sequences."""
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def next(self):
        """Provide the "next" integer in the sequence.

        Guaranteed to be unique but not necessarily consecutive, monotonic or
        increasing.

        """

        pass


class TimeSequence(Sequence):
    """Provide a time-based sequence. This implementation should support one
    million unique integers per second."""

    def __init__(self):
        super(TimeSequence, self).__init__()
        self.lock = threading.Lock()
        self.seq = 0
        self.last_time = time.time()

    def next(self):
        with self.lock:
            t = time.time()
            if t != self.last_time:
                self.seq = 0
                self.last_time = t
            else:
                self.seq += 1
            return int(t * 1e6) + self.seq


class UUIDSequence(Sequence):
    """Provide a UUID as a sequence. See the uuid1 documentation for
    details."""

    def __init__(self):
        super(UUIDSequence, self).__init__()

    def next(self):
        return int(uuid.uuid1())


def get_network_seq():
    """Attempt to connect to the network service running on the master and
    return a unique integer.

    May throw many exceptions, including socket.error and ValueError.

    """

    with closing(socket.socket()) as sock:
        sock.connect((config.get('global', 'MasterAddress'),
                      config.getint('global', 'MasterSeqPort')))
        return int(sock.recv(128))


def crt_subject(CN=None, Email=None, OU=None, O=None, L=None, ST=None, C=None):
    """Returns an X509_Name object populated with appropriate values.

    Note! Subject fields are hierarchical.  (hierarchy reads L->R in kwargs)
    If CN is not set, all fields  other fields will be ignored,
    If OU is unset, O, L, ST, C are ignored...

    """

    #Email needs to be specified in two subject fields
    emailAddress = Email

    localvars = vars()

    info = X509.X509_Name(m2.x509_name_new())

    Subject = namedtuple('Subject', 'emailAddress Email CN OU O L ST C')
    subject = Subject(**localvars)

    for name in subject._fields:
        value = getattr(subject, name)
        log.debug("NAME: %s, VAL: %s", name, value)

        info.add_entry_by_txt(field=name, entry=value, type=0x1000,
                              len=-1, loc=-1, set=0)

    return info


def sign_data(data):
    """Sign data using the private key, return a base64 string."""

    signingkey = EVP.load_key(key_file(config.get('cert', 'CN')),
                              callback=lambda passphrase: 'certmgr')

    signingkey.sign_init()
    signingkey.sign_update(data)

    return base64.b64encode(signingkey.sign_final())


def verify_data(sig, data, pub):
    """Verify a signature (base64 object), return the contents.

    Returns True if signature is valid

    """

    signature = base64.b64decode(sig)

    pub.verify_init()
    pub.verify_update(data)

    return pub.verify_final(signature)


def make_key(bits=2048):
    """Create RSA key

    bits: Bits for RSA key (defaults to 2048)

    Returns an RSA object

    """

    return RSA.gen_key(bits, m2.RSA_F4)


def make_csr(key, CN, Email="certmgr@certmgr",
             OU="CertMgr Dept", O="CertMgr Org",
             L="CertMgr City", ST="CertMgr State", C="UK"):
    """Make a certificate request from an RSA key

    key: String containing key
    CN: Common Name (aka CA hostname)
    Email: Email address of certificate owner
    OU: Organisational Unit (CertMgr Dept)
    O: Organisation (CertMgr Org)
    L: Location (CertMgr City)
    ST: State (CertMgr State)
    C: Country (UK)

    Returns an X509 object

    """

    csr = X509.Request()

    csr.set_subject_name(crt_subject(CN, Email, OU, O, L, ST, C))

    pub = EVP.PKey(md='md5')
    pub.assign_rsa(key, capture=False)

    csr.set_pubkey(pub)
    csr.sign(pub, md='md5')

    return csr


def sign_csr(cakey, cacert, csr, lifetime=60 * 60 * 24 * 365):
    """Sign certificate request.

    cakey: CA key object
    cacert: CA Public Certificate object
    csr: Certificate Request string
    lifetime: Lifetime of signed cert in seconds (60*60*24*365 = 1 year)

    Returns X509 object

    """

    if csr.get_subject().CN == cacert.get_subject().CN:
        log.error("Won't sign a cert with the same Common Name as the CA")
        return

    capub = cacert.get_pubkey()
    capub.assign_rsa(cakey, capture=False)

    pub = csr.get_pubkey()
    cert = X509.X509()

    cert.set_pubkey(pub)

    cert.set_version(0)

    now = int(time.time())

    notbefore = ASN1.ASN1_UTCTIME()
    notbefore.set_time(now)

    califetime = check_expiry(cacert)
    if lifetime > califetime:
        log.warn("Remaining CA lifetime shorter than CertLifetime. \
            CertLifetime being clipped to %s", 
            datetime.timedelta(seconds=califetime))
        lifetime = califetime

    notafter = ASN1.ASN1_UTCTIME()
    notafter.set_time(now + lifetime)

    cert.set_not_before(notbefore)
    cert.set_not_after(notafter)

    #Assign subject from csr
    subject = csr.get_subject()
    cert.set_subject_name(subject)
    cert.set_serial_number(get_network_seq())

    #Set issuer on cert
    cert.set_issuer_name(cacert.get_subject())

    #print cert.as_text()
    cert.sign(capub, md='md5')

    return cert


def make_cacert(key, CN, Email="CA@CertMgr",
            OU="CertMgr Dept", O="CertMgr Org", L="CertMgr City",
            ST="CertMgr State", C="UK", lifetime=60 * 60 * 24 * 365 * 10):
    """Generate a self-signed CA certificate.

    CN: Common Name
    Email: Email address of certificate owner
    OU: Organisational Unit (CertMgr Dept)
    O: Organisation (CertMgr Org)
    L: Location (CertMgr City)
    ST: State (CertMgr State)
    C: Country (UK)
    lifetime: Certificate lifetime in seconds (60*60*24*365*10 = 10 years)

    Returns an X509 (CA) cert object.

    """

    pub = EVP.PKey(md='md5')
    pub.assign_rsa(key, capture=False)
    cacert = X509.X509()
    cacert.set_pubkey(pub)
    cacert.set_subject_name(crt_subject(CN, Email, OU, O, L, ST, C))

    now = int(time.time())
    notbefore = ASN1.ASN1_UTCTIME()
    notbefore.set_time(now)

    notafter = ASN1.ASN1_UTCTIME()
    notafter.set_time(now + lifetime)

    cacert.set_not_before(notbefore)
    cacert.set_not_after(notafter)

    cacert.set_serial_number(1)

    #Self-signed, so issuer derived from the cert itself
    cacert.set_issuer_name(cacert.get_subject())

    #Set CA:TRUE extension on cert (is a CA)
    ext = X509.new_extension("basicConstraints", "CA:TRUE")
    ext.set_critical()
    cacert.add_ext(ext)

    #Sign the cert
    cacert.sign(pub, md='md5')

    return cacert


def ca_cert_file():
    """Return full path of CA cert file from config."""

    return os.path.join(config.get('global', 'CAPath'),
                     config.get('ca', 'CACert'))


def ca_key_file():
    """Return full path of CA key file from config."""

    return os.path.join(config.get('global', 'CAPrivatePath'),
                      config.get('ca', 'CAKey'))


def ca_csr_file():
    """Return full path of CA CSR file from config."""

    return os.path.join(config.get('global', 'CAPath'),
                     config.get('ca', 'CACSR'))


def key_from_file(keyfilename):
    """Read a private key from file.

    Note: M2Crypto provides no way to not set a passphrase on keys
    By default, Certmgr uses the passphrase 'certmgr' throughout.

    Returns an RSA object.

    """

    return RSA.load_key(keyfilename, callback=lambda passphrase: 'certmgr')


def cert_from_file(certfilename):
    """Read a certificate from file."""

    return X509.load_cert(certfilename)


def csr_from_file(csrfilename):
    """Read a certificate request from file."""

    return X509.load_request(csrfilename)


def cert_file(name):
    """Return full path of cert file from config."""

    return os.path.join(config.get('global', 'CertPath'), name) + ".crt"


def cert_store_file(name):
    """Return full path of central store cert file from config."""

    return os.path.join(config.get('global', 'StoreDir'), name) + ".crt"


def key_file(name):
    """Return full path of key file from config."""

    return os.path.join(config.get('global', 'PrivatePath'), name) + ".key"


def csr_file(name):
    """Return full path of csr file from config."""

    return os.path.join(config.get('global', 'CertPath'), name) + ".csr"


def csr_cache_file(name):
    """Return full path of csr file from config."""

    return os.path.join(config.get('global', 'CSRCache'), name) + ".csr"


def creat(filename, flag=os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0777):
    """A thin wrapper around os.open and os.fdopen to return a file-like
    object.

    With the default arguments, ask for a file to be created only if it
    doesn't already exist. If it does, expect an OSError exception "e"
    with e.errno == errno.EEXIST.

    """
    return os.fdopen(os.open(filename, flag, mode), 'w')


def parse_config(configfile="/etc/certmgr/certmgr.cfg"):
    """Parse the config file into 'config' and set up logging."""

    global config
    config = ConfigParser.ConfigParser({'CN': socket.getfqdn()})
    if not config.read(configfile):
        raise ConfigParser.Error(
            "Unable to read Configuration File: %s" % (configfile, ))
    log.setLevel(getattr(logging, config.get('global', 'LogLevel')))
    logconsole.setLevel(getattr(logging, config.get('global', 'LogLevel')))


def make_ca():
    """Generate a CA and CSR file for the master."""

    log.info("Generating CA certificates for master")
    CN = config.get('ca', 'CN')

    #We never want to overwrite a key file, so load from file if one exists
    try:
        #Use the default passphrase 'certmgr' on the key
        with creat(ca_key_file(), mode=0666) as f_key:
            key = make_key(config.getint('ca', 'Bits'))
            f_key.write(key.as_pem(callback=lambda passphrase: "certmgr"))
    except OSError, e:
        if e.errno != errno.EEXIST: # File exists
            raise
        key = key_from_file(ca_key_file())

    with tempfile.NamedTemporaryFile(
            dir=os.path.dirname(ca_cert_file()),
            delete=False) as f_cacert:
        cacert = make_cacert(key, CN, config.get('ca', 'Email'),
                            config.get('ca', 'OU'),
                            config.get('ca', 'O'),
                            config.get('ca', 'L'),
                            config.get('ca', 'ST'),
                            config.get('ca', 'C'),
                            config.getint('ca', 'CALifetime'))
        f_cacert.write(cacert.as_pem())

    os.rename(f_cacert.name, ca_cert_file())

    #Also create a CSR in case the CA needs signing manually
    with tempfile.NamedTemporaryFile(
            dir=os.path.dirname(ca_csr_file()),
            delete=False) as f_cacsr:
        cacsr = make_csr(key, CN, config.get('ca', 'Email'),
                         config.get('ca', 'OU'),
                         config.get('ca', 'O'),
                         config.get('ca', 'L'),
                         config.get('ca', 'ST'),
                         config.get('ca', 'C'))
        f_cacsr.write(cacsr.as_pem())

    os.rename(f_cacsr.name, ca_csr_file())

    with StoreHandler.dispatch(
        config.get('store', 'StoreType')) as store:
        store.write(cacert)

    return cacert


def make_cert():
    """Create Certificate key and csr files, then send to master."""

    #Make client key and CSR if needed
    CN = config.get('cert', 'CN')

    log.info("Making key and CSR for %s", CN)

    #We never want to overwrite a key file, so do nothing if it already exists.
    try:
        #Use the default passphrase 'certmgr' on the key
        with creat(key_file(CN), mode=0666) as f_key:
            key = make_key(config.getint('cert', 'Bits'))
            f_key.write(key.as_pem(callback=lambda passphrase: "certmgr"))
    except OSError, e:
        if e.errno != errno.EEXIST: # File exists
            raise
        key = key_from_file(key_file(CN))

    with tempfile.NamedTemporaryFile(
        dir=os.path.dirname(csr_file(CN)), delete=False) as f_csr:
        csr = make_csr(key, CN, config.get('cert', 'Email'),
                       config.get('cert', 'OU'),
                       config.get('cert', 'O'),
                       config.get('cert', 'L'),
                       config.get('cert', 'ST'),
                       config.get('cert', 'C'))
        f_csr.write(csr.as_pem())

    os.rename(f_csr.name, csr_file(CN))

    return send_csr(csr)


def check_expiry(certobj):
    """Return expiry time in seconds.

    certobj: OpenSSL X509 Object

    """

    return int(
        time.mktime(time.strptime(str(
            certobj.get_not_after()), '%b %d %H:%M:%S %Y %Z')) - time.time())


class CSRChoice(object):
    """Representation of a CSR in the pending queue.

    csr is initialised by pending_csrs. If the file is not a CSR, None is
    passed, and the only method which may be called on CSRChoice is remove.

    """

    def __init__(self, csr, csr_filename):
        self.csr = csr
        self.csr_filename = csr_filename

    def store(self, cakey=None, cacert=None, store=None):
        """Sign and store the CSR.

        If HostVerify is set in the config file, may raise HostVerifyError.
        If cakey or cacert are not given, try to get them. This may raise
        CACertError.
        If store is not given, try to get it. If this fails it will ONLY LOG A
        WARNING. Otherwise, the default store (given in the config file) will
        be setup, written to and checkpointed. Any of these steps may raise an
        exception.

        """

        if (self.csr.get_subject().CN !=
                os.path.splitext(os.path.basename(self.csr_filename))[0]):
            if config.getboolean('master', 'HostVerify'):
                log.error("Hostname doesn't match CN and HostVerify is set")
                raise HostVerifyError
            else:
                log.warn("Hostname doesn't match CN - signing anyway")

        if cakey is None or cacert is None:
            cakey, cacert = check_cacerts()
        certobj = sign_csr(cakey, cacert, self.csr,
                                config.getint('cert', 'CertLifetime'))

        with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(cert_file(self.csr.get_subject().CN)),
                delete=False) as f_crt:
            log.info("Writing certificate: %s",
                     cert_file(self.csr.get_subject().CN))
            f_crt.write(certobj.as_pem())

        os.rename(f_crt.name, cert_file(self.csr.get_subject().CN))

        self.remove()

        log.info("Storing signed cert")
        # If we are passed a store, assume it has been setup.
        if store:
            store.write(certobj)
        else:
            with StoreHandler.dispatch(
                    config.get('store', 'StoreType')) as store:
                store.write(certobj)

    def remove(self):
        """Delete the CSR file from the queue."""

        log.info("Deleting CSR file: %s", self.csr_filename)
        os.remove(self.csr_filename)


def pending_csrs():
    """An interface to the set of pending CSRs."""

    csrpath = config.get('global', 'CSRCache')
    for csr_filename in os.listdir(csrpath):
        csrloc = os.path.join(csrpath, csr_filename)
        try:
            csr = csr_from_file(csrloc)
        except X509.X509Error:
            # If we can't read a CSR, there's probably extra crud in the cache.
            # Yield it anyway, the UI might still want to delete it.
            csr = None
        yield CSRChoice(csr, csrloc)


def send_csr(csrobj):
    """Send csr to certmgr master."""

    msg = "%s\n%s\n" % (sign_data(csrobj.as_pem()), csrobj.as_pem())
    log.info("Sending CSR %s.csr for signing", csrobj.get_subject().CN)
    try:
        with closing(socket.socket()) as sock:
            sock.connect((config.get('global', 'MasterAddress'),
                          config.getint('global', 'MasterPort')))
            sockfile = sock.makefile('rw', 0)
            sockfile.write(msg)
            sock.shutdown(socket.SHUT_WR)
            answer = sockfile.readlines()
        rval = answer[0].strip('\n')
        data = ''.join(answer[1:])
    except (socket.error, IndexError):
        log.exception("Error communicating with master.")
        return

    if rval == 'OK' and data:
        log.info("CSR received by server")
        try:
            cert = X509.load_cert_string(data)
            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(cert_file(
                    config.get('cert', 'CN'))),
                delete=False) as f_crt:
                f_crt.write(cert.as_pem())
        except X509.X509Error:
            log.exception("Error receiving cert.")

        log.debug("Writing received cert")
        os.rename(f_crt.name, cert_file(config.get('cert', 'CN')))
        return cert
    elif rval == 'OK':
        log.info("CSR received and cached by server.")
    elif rval == 'FAIL' and data:
        log.error("Error processing CSR: %s", data)
    else: # Implies a solo 'FAIL' or something else bad
        log.error("Error receiving/parsing answer from master.")


def launch_daemon():
    """Start the certmgr listening socket and/or expiry timers."""

    cakey, cacert = check_cacerts()

    store = StoreHandler.dispatch(config.get('store', 'StoreType'))
    store.setup()

    certexpiry = CertExpiry(cakey, cacert, store)
    certexpiry.expiry_timer()

    try:
        polling = Polling(store, config.getint('store', 'PollTimer'))
        polling.poll_timer()
    except ConfigParser.Error:
        log.warn("PollTimer value not set in config", exc_info=sys.exc_info())

    if config.get('global', 'IsMaster'):
        #Listen for incoming messages
        csrsock = socket.socket()
        csrsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        csrsock.setblocking(0)
        csrsock.bind((config.get('global', 'MasterAddress'),
                      config.getint('global', 'MasterPort')))
        csrsock.listen(5)

        # Listen for sequence requests
        seqsock = socket.socket()
        seqsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        seqsock.setblocking(0)
        seqsock.bind((config.get('global', 'MasterAddress'),
                      config.getint('global', 'MasterSeqPort')))
        seqsock.listen(5)
        sequence = UUIDSequence()

        while True:
            read, write, error = select.select([csrsock, seqsock], [], [])
            if csrsock in read:
                sock, src = csrsock.accept()
                try:
                    thread = MsgHandlerThread(store, sock, src, cakey, cacert)
                    thread.name = 'MsgHandlerThread(src=%r)' % (src, )
                    thread.start()
                except Exception:
                    # Close the socket if there are any exceptions. The thread
                    # will be responsible for closing the socket otherwise.
                    sock.close()
            if seqsock in read:
                with closing(seqsock.accept()[0]) as sock:
                    sock.send(str(sequence.next()))


def check_cacerts(recurse=True):
    """Check for existence of CA cert and key file."""

    try:
        cakey = key_from_file(ca_key_file())
        cacert = cert_from_file(ca_cert_file())
        return cakey, cacert
    except IOError, e:
        if e.errno != errno.ENOENT:
            raise
        make_ca()
        if recurse:
            return check_cacerts(False)
        else:
            log.exception("CA certificate missing!")


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
            log.exception("Unable to create path: %s",
                config.get('global', path))


log = logging.getLogger(__name__)
log.setLevel(logging.CRITICAL)
logformat = VerboseExceptionFormatter('%(levelname)s %(message)s')
logconsole = logging.StreamHandler()
logconsole.setFormatter(logformat)
logconsole.setLevel(logging.CRITICAL)
log.addHandler(logconsole)

#Calling config.* methods will call parse_config, reading the default
#config file if the importing app hasn't previously
#done certmgr.parse_config(configfile="...")
config = LazyConfig()
