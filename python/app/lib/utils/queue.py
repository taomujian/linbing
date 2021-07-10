#!/usr/bin/env python3

import time
from app.scan.scan import Scan
from app.lib.utils.common import parse_target

def queue_scan(username, target, description, scan_id, scan_time, scan_option, mysqldb, check):

    """
    开启扫描任务

    :param str target: 待解析的目标
    :param str description: 目标描述
    :param str scan_id: 扫描id
    :param str scan_time: 扫描时间
    :param str scan_option: 扫描选项
    :param object mysqldb: 进行mysql数据交互的实例化对象
    :param bool check: 是否进行扫描状态检测

    :return:
    """

    parse_result = parse_target(target)
    scan_ip = parse_result[0]
    main_domain = parse_result[1]
    domain = parse_result[2]
    scan_status = mysqldb.get_scan_status(username, scan_id)
    if not scan_status:
        mysqldb.save_target_scan(username, target, description, scan_ip, scan_id, scan_time, '扫描中', '正在排队')

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
                if result['scan_status'] != '扫描中':
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
