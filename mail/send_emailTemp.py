import smtplib
from email.mime.text import MIMEText

def send_email_temp(receiver_email, contents, title):

    mail = smtplib.SMTP('smtp.gmail.com', 587)
    mail.ehlo()
    mail.starttls()
    email_sent = 'busterdust5@gmail.com'
    msg = MIMEText(contents)
    msg['Subject'] = title
    msg['From'] = email_sent
    msg['To'] = receiver_email

    mail.login('busterdust5@gmail.com','mmfg lxud resj iqin')

    header = 'To:'+email_sent+'\n'+'From: '+receiver_email+'\n'+'subject:testmail\n'
    content = header + contents
    mail.sendmail (email_sent, receiver_email, msg.as_string())

    mail.close()
