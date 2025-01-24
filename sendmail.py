import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import __main__

def sendmail(username, password, sender, to, subject, body, use_tls=True):
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    try:
        server = smtplib.SMTP(__main__.config['mail_host'], __main__.config['mail_port'])
        if use_tls: server.starttls()
        server.login(username, password)
        text = msg.as_string()
        server.sendmail(sender, to, text)
        server.quit()
    except Exception:
        return False
    return True