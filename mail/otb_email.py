import smtplib
from email.mime.text import MIMEText

def send_otp_email(receiver_email, otp_code, name):

    contents = f"Xin chào {name}!\n\nMã của bạn là {otp_code}\n\nNhóm,\nOrder food"
    mail = smtplib.SMTP('smtp.gmail.com', 587)
    mail.ehlo()
    mail.starttls()
    email_sent = 'busterdust5@gmail.com'
    msg = MIMEText(contents)
    msg['Subject'] = f"Mã của bạn - {otp_code}"
    msg['From'] = email_sent
    msg['To'] = receiver_email

    mail.login('busterdust5@gmail.com','jsqn jybb llhb cfxw')

    header = 'To:'+email_sent+'\n'+'From: '+receiver_email+'\n'+'subject:testmail\n'
    content = header + contents
    mail.sendmail (email_sent, receiver_email, msg.as_string())

    mail.close()