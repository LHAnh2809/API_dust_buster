import smtplib
from email.mime.text import MIMEText

def send_cskh_email(email_sent, title, contents):

    mail = smtplib.SMTP('smtp.gmail.com', 587)
    mail.ehlo()
    mail.starttls()
    receiver_email = 'busterdust5@gmail.com'
    msg = MIMEText(contents)
    msg['Subject'] = title
    msg['From'] = receiver_email
    msg['To'] = email_sent

    mail.login('busterdust5@gmail.com','jsqn jybb llhb cfxw')

    header = 'To:'+email_sent+'\n'+'From: '+receiver_email+'\n'+'subject:testmail\n'
    content = header + contents
    mail.sendmail (email_sent, receiver_email, msg.as_string())

    mail.close()