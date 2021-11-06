#!/usr/bin/env python3

import time
import configparser
from rq import Queue
from redis import Redis
from app.scan.scan import Scan
from app.lib.utils.common import parse_target

config = configparser.ConfigParser()
config.read('conf.ini', encoding = 'utf-8')
redis_conn = Redis(host = config.get('redis', 'ip'), password = config.get('redis', 'password'), port = config.get('redis', 'port'))
high_queue = Queue("high", connection = redis_conn)

def queue_target_list(username, target_list, description, mysqldb):

    """
    保存目标

    :param str username: 用户名
    :param list target_list: 目标列表
    :param str description: 描述
    :param object mysqldb: 进行mysql数据交互的实例化对象

    :return:
    """

    for target in target_list:
        target = target.strip()
        scan_ip = parse_target(target)[0]
        if not scan_ip:
            scan_ip = target
        target = target
        mysqldb.save_target(username, target, description, scan_ip)

def queue_scan_list(username, target_list, option_list, mysqldb):

    """
    添加扫描任务

    :param str username: 用户名
    :param list target_list: 目标列表
    :param list option_list: 扫描选项列表
    :param object mysqldb: 进行mysql数据交互的实例化对象
    :param bool check: 是否进行扫描状态检测

    :return:
    """

    # 先把所有要扫描的目标的状态更新为扫描中
    for item in target_list:
        target = item['target']
        scan_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        mysqldb.update_target_scan_status(username, target, '扫描中')
        mysqldb.update_target_scan_schedule(username, target, '正在排队')

    # 开始把要扫描的目标入队列
    scan_id = mysqldb.get_scan_id(username)
    for item in target_list:
        result = mysqldb.get_target_status(username, target)
        if result != '扫描中':
            check = False
        else:
            check = True
        high_queue.enqueue_call(queue_scan, job_id = scan_id, args = (username, target, scan_id, scan_time, option_list, mysqldb, check,), timeout = 7200000)
        scan_id = str(int(scan_id) + 1)

def queue_scan(username, target, scan_id, scan_time, scan_option, mysqldb, check):

    """
    开启扫描任务

    :param str username: 用户名
    :param str target: 待解析的目标
    :param str scan_id: 扫描id
    :param str scan_time: 扫描时间
    :param str scan_option: 扫描选项
    :param object mysqldb: 进行mysql数据交互的实例化对象
    :param bool check: 是否进行扫描状态检测

    :return:
    """
   
    parse_result = parse_target(target)
    scan_ip = parse_result[0]
    target_ip = mysqldb.get_target_ip(username, target)
    if target_ip != scan_ip:
        mysqldb.update_target_ip(username, target, scan_ip)
    main_domain = parse_result[1]
    domain = parse_result[2]
    scan_status = mysqldb.get_scan_status(username, scan_id)
    if not scan_status:
        mysqldb.save_target_scan(username, target, scan_ip, scan_id, scan_time, '扫描中', '正在排队')

    if not scan_ip:
        mysqldb.update_target_live_status(username, target, '失活')
        mysqldb.update_target_scan_status(username, target, '扫描失败')
        mysqldb.update_target_scan_schedule(username, target, '扫描失败')
        mysqldb.update_scan_status(username, scan_id, '扫描失败')
        mysqldb.update_scan_schedule(username, scan_id, '扫描失败')
    else:
        if check:
            while True:
                result = mysqldb.get_target_status(username, target)
                if result != '扫描中':
                    break
                else:
                    time.sleep(5)

        scan_data = {
            'username': username,
            'target': target,
            'scan_id': scan_id,
            'scan_ip': scan_ip,
            'main_domain': main_domain,
            'domain': domain,
            'scan_option': scan_option
        }
        scan = Scan(mysqldb)
        scan.run(scan_data)
