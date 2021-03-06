#!/usr/bin/env python3

import time
from app.scan.scan import Scan

def queue_scan(username, target, scan_id, scan_ip, main_domain, domain, mysqldb):
    """
    开启扫描任务

    :param str target: 待解析的目标
    :param str scan_id: 扫描id
    :param str scan_ip: 扫描ip
    :param str main_domain: 主域名
    :param str domain: 域名
    :param object mysqldb: 进行mysql数据交互的实例化对象

    :return:
    """
    
    mysqldb.update_target_scan_status(username, target, '扫描中')
    mysqldb.update_target_scan_schedule(username, target, '开始扫描')                                 
    mysqldb.update_scan_status(username, target, scan_id, '扫描中')
    mysqldb.update_scan_schedule(username, target, scan_id, '开始扫描')
    scan_data = {
        'username': username,
        'target': target,
        'scan_ip': scan_ip,
        'scan_id': scan_id,
        'main_domain': main_domain,
        'domain': domain
    }
    scan = Scan(mysqldb)
    scan.run(scan_data)
