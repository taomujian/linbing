#!/usr/bin/env python3

import random
import string
import smtplib
from email.header import Header
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart

class MailSender:
    def __init__(self, email_address, smtp_host):
        
        self.from_mail = email_address #发送邮件的邮箱账号
        self.smtp_host = smtp_host
        self.subject = "欢迎注册金睛系统"
        self.imgbody = '''
                       <h3>欢迎注册，您的注册码是</h3>
                       '''

    def attachAttributes(self, msg, to_mail):
        """
        设置邮件头部信息

        :param msg: 要发送的邮件内容
        :param to_mail: 邮件收件人
        :param cc_mail: 邮件抄送人
        :return:
        """
        msg["Subject"] = Header(self.subject, "utf-8")
        msg["From"] = self.from_mail
        msg["To"] = to_mail

    def attachBody(self, msg, email_type, capta, imgfile = None):
        """
        设置邮件正文信息

        :param msg: 要发送的邮件内容
        :param type: 邮件正文类型
        :param capta: 要发送的验证码
        :param imgfile: 图片文件
        :return:
        """
        msgtext = MIMEText(self.imgbody + capta, email_type, "utf-8")
        msg.attach(msgtext)
        if imgfile != None:
            try:
                file = open(imgfile, "rb")
                img = MIMEImage(file.read())
                img.add_header("Content-ID", "<image1>")
                msg.attach(img)
            except(Exception) as err:
                print(str(err))
            finally:
                if file in locals():
                    file.close()
 
    def sendMail(self, to_mail):
        """
        发送邮件

        :param to_mail: 邮件收件人
        :return result: 状态码和邮件所发送的验证码
        """
        msg = MIMEMultipart()
        capta = '' 
        words = ''.join((string.ascii_letters,string.digits))
        for i in range(6):
            capta = capta + random.choice(words) 
        self.attachAttributes(msg, to_mail)
        self.attachBody(msg, "html", capta)
        try:
            smtp = smtplib.SMTP(self.smtp_host) 
            smtp.sendmail(self.from_mail, to_mail, msg.as_string())
            result = ('Z1000', capta)
        except Exception as e:
            print(e)
            result = ('Z1003', capta)
        finally:
            smtp.quit()
            return result

if __name__ == "__main__":
    try:
        MailSender = MailSender('jinjing@xip.io', '127.0.0.1')
        MailSender.sendMail('1483521320@qq.com')
    except Exception as err:
        print(err)