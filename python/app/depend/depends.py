#!/usr/bin/env python3

import os
import configparser
from rq import Queue
from redis import Redis
from pydantic import BaseModel
from passlib.context import CryptContext
from app.lib.rsa import Rsa_Crypto
from app.lib.aes import Aes_Crypto
from app.utils.mysql import Mysql_db

UPLOAD_FOLDER = 'static/images'  #文件存放路径
if not os.path.exists("static/images"):
    os.mkdir("static/images")

class VueRequest(BaseModel):
    data: str = None

config = configparser.ConfigParser()
config.read('conf.ini', encoding = 'utf-8')
redis_conn = Redis(host = config.get('redis', 'ip'), password = config.get('redis', 'password'), port = config.get('redis', 'port'))
high_queue = Queue("high", connection = redis_conn)
mysqldb = Mysql_db(config.get('mysql', 'ip'), config.get('mysql', 'port'), config.get('mysql', 'username'), config.get('mysql', 'password'))
aes_crypto = Aes_Crypto(config.get('Aes', 'key'), config.get('Aes', 'iv'))
rsa_crypto = Rsa_Crypto()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
redis_conn = Redis(host = config.get('redis', 'ip'), password = config.get('redis', 'password'), port = config.get('redis', 'port'))
high_queue = Queue("high", connection = redis_conn)