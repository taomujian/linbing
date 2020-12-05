#!/usr/bin/env python3

import random
import string
import smtplib
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email import encoders

class MailSender:
    def __init__(self, email_address, secret, cc_mail = None):
        self.smtpserver = "smtp.qq.com"
        self.smtpport = 465
        self.password = secret #16位的QQ邮箱授权码
        self.from_mail = email_address #发送邮件的QQ邮箱账号
        self.cc_mail = cc_mail
        self.subject = "欢迎注册临兵漏洞扫描系统"
        self.from_name = "欢迎注册临兵漏洞扫描系统"
        self.imgbody = '''
                       <h3>欢迎注册，您的注册码是</h3>
                       '''

    def attachAttributes(self, msg, to_mail, cc_mail = None):
        """
        设置邮件头部信息

        :param str msg: 要发送的邮件内容
        :param str to_mail: 邮件收件人
        :param str cc_mail: 邮件抄送人
        :return:
        """
        msg["Subject"] = Header(self.subject, "utf-8")
        msg["From"] = Header(self.from_name + " <" + "临兵漏洞扫描系统" + ">", "utf-8")
        msg["To"] = Header(",".join(to_mail), "utf-8")
        # msg["Cc"] = Header(",".join(cc_mail), "utf-8")

    def attachBody(self, msg, type, capta, imgfile = None):
        """
        设置邮件正文信息

        :param str msg: 要发送的邮件内容
        :param str type: 邮件正文类型
        :param str capta: 要发送的验证码
        :param str imgfile: 图片文件
        :return:
        """
        msgtext = MIMEText(self.imgbody + capta, type, "utf-8")
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

        :param str to_mail: 邮件收件人
        :return: str result: 状态码和邮件所发送的验证码
        """
        msg = MIMEMultipart()
        capta = '' 
        words = ''.join((string.ascii_letters,string.digits))
        for i in range(6):
            capta = capta + random.choice(words) 
        self.attachAttributes(msg, to_mail)
        self.attachBody(msg, "html", capta)
        try:
            smtp = smtplib.SMTP_SSL(self.smtpserver, self.smtpport)
            smtp.login(self.from_mail, self.password)
            if self.cc_mail == None:
                smtp.sendmail(self.from_mail, to_mail, msg.as_string())
            else:
                smtp.sendmail(self.from_mail, to_mail+self.cc_mail, msg.as_string())
            result = ('Z1000', capta)
        #except(smtplib.SMTPRecipientsRefused):
            #return ("Recipient refused", capta)
        #except(smtplib.SMTPAuthenticationError):
            #return ("Auth error", capta)
        #except(smtplib.SMTPSenderRefused):
            #return ("Sender refused", capta)
        except Exception as e:
            print(e)
            result = ('Z1003', capta)
        finally:
            smtp.quit()
            return result
