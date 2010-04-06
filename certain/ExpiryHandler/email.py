import smtplib
from email.mime.text import MIMEText
from .. import log
from .. import config


def expire(certobj):
    """Email a warning about cert expiry."""

    log.debug("Emailing about cert expiry")
    msg = MIMEText(
"""CA Expiry Warning

CA %s expires at: %s
A new CA will be generated automatically.

If you require signing by a third party, please do this
for the newly created CA.""" % (certobj.get_subject().CN,
                                     str(certobj.get_not_after())))

    msg['To'] = config.get('ca', 'Email')
    msg['From'] = config.get('email', 'FromAddress')
    msg['Subject'] = "CA Expiry Warning"

    smtp = smtplib.SMTP(config.get('email', 'SMTPServer'))
    smtp.sendmail(msg['From'], msg['To'], msg.as_string())
    smtp.quit()
