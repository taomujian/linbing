#!/usr/bin/env python3

import configparser
from redis import Redis
from multiprocessing import Pool, freeze_support
from rq import Queue, Worker, Connection

config = configparser.ConfigParser()
config.read('conf.ini', encoding = 'utf-8')

redis_conn = Redis(host = '127.0.0.1', password = config.get('redis', 'password'), port = 6379)

def worker(listen):
    with Connection(redis_conn):
        worker = Worker(map(Queue, listen))
        worker.work()

def run ():
    listen = ['high']
    try:
        cpu_num = 4
        p = Pool(cpu_num)
        for i in range(cpu_num):
            p.apply_async(worker, args=(listen,))  # 开启worker
        p.close()
        p.join()
    except Exception as e:
        print(e)

if __name__ == "__main__":
    freeze_support()
    run()