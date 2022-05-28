#!/usr/bin/env python3

import nmap
import masscan
import asyncio
from app.lib.common import get_title
from app.utils.finger import WhatCms, Fofa_Scanner

class Port_Scan:
    def __init__(self, mysqldb):
        self.mysqldb = mysqldb

    def nmap_scan(self, username, target, target_ip, scan_id, cmd, port):

        """
        用nmap进行扫描

        :param str username: 用户名
        :param str target: 待扫描的目标
        :param str target_ip: 待扫描的目标ip
        :param str scan_id: 扫描任务id
        :param str cmd: 执行参数
        :param str port: 扫描端口

        :return list scan_list: 扫描的结果
        """
        
        scan_list = []
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cmd = cmd if cmd else '-sS -sV -Pn -T4 --open'
        try:
            nm = nmap.PortScanner()
            arguments = '%s -p %s' %(cmd, port)
            nm.scan(hosts = target_ip, arguments = arguments)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            for host in nm.all_hosts():
                for nmap_proto in nm[host].all_protocols():
                    lport = nm[host][nmap_proto].keys()
                    lport = sorted(lport)
                    try:
                        if len(lport) < 50:
                            for nmap_port in lport:
                                protocol = nm[host][nmap_proto][int(nmap_port)]['name']
                                product = nm[host][nmap_proto][int(nmap_port)]['product']
                                version = nm[host][nmap_proto][int(nmap_port)]['version']
                                if 'tcpwrapped' not in protocol:
                                    if 'http' in protocol or protocol == 'sun-answerbook':
                                        if protocol == 'https' or protocol == 'https-alt' or nmap_port == 443:
                                            scan_url_port = 'https://' + host + ':' + str(nmap_port)
                                        else:
                                            scan_url_port = 'http://' + host + ':' + str(nmap_port)
                                        finger_data = self.mysqldb.all_finger(username)
                                        cms = Fofa_Scanner(scan_url_port, finger_data['fofa_cms'])
                                        fofa_finger = asyncio.run(cms.run())
                                        cms_name = ''
                                        for fofa_finger_tmp in fofa_finger:
                                            if fofa_finger_tmp.lower() in cms.cms_finger_list:
                                                cms_name = fofa_finger_tmp
                                        
                                        '''
                                        if not cms_name:
                                            whatcms = WhatCms(scan_url_port, finger_data['cms'])
                                            cms_result = asyncio.run(whatcms.run())
                                            cms_result = list(set(cms_result))
                                            if cms_result:
                                                cms_name = cms_name + '\n' + ''.join(cms_result)
                                        '''

                                        result = asyncio.run(get_title(scan_url_port))
                                        self.mysqldb.save_target_port(username, target, scan_id, host, str(nmap_port), cms_name, protocol, product, version, result[0], result[1])
                                        self.mysqldb.save_port(username, target, scan_url_port, host, str(nmap_port), cms_name, protocol, product, version, result[0], result[1])
                                    else:
                                        scan_url_port = str(host) + ':' + str(nmap_port)
                                        self.mysqldb.save_target_port(username, target, scan_id, host, str(nmap_port), '', protocol, product, version, '', '')
                                        self.mysqldb.save_port(username, target, scan_url_port, host, str(nmap_port), '', protocol, product, version, '', '')
                                    scan_list.append(scan_url_port)
                    except Exception as e:
                        # print(e)
                        pass
        except Exception as e:
            # print(e)
            pass

        return scan_list

    def masscan_scan(self, username, target, target_ip, scan_id, cmd, port, rate):
        
        """
        用masscan进行扫描

        :param str username: 用户名
        :param str target: 待扫描的目标
        :param str target_ip: 待扫描的目标
        :param str scan_id: 扫描id
        :param str cmd: 执行参数
        :param str port: 扫描端口的最大值
        :param str rate: 扫描速率

        :return list scan_list: 扫描的结果
        """

        scan_list = []
        print('Masscan starting.....\n')
        try:
            cmd = cmd if cmd else '-sS -Pn -n --randomize-hosts -v --send-eth --open'
            masscan_scan = masscan.PortScanner()
            masscan_scan.scan(hosts = target_ip, ports='%s'%(port), arguments = '%s --rate %s' % (cmd, rate))
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            for host in masscan_scan.all_hosts:
                for masscan_proto in masscan_scan[host].keys():
                    if len(masscan_scan[host][masscan_proto].keys()) < 50:
                        for masscan_port in masscan_scan[host][masscan_proto].keys():
                            try:
                                nm = nmap.PortScanner()
                                arguments = '-p %s -sS -sV -Pn --open' % (masscan_port)
                                nm.scan(hosts = host, arguments = arguments)
                                for nmap_proto in nm[host].all_protocols():
                                    protocol = nm[host][nmap_proto][int(masscan_port)]['name']
                                    product = nm[host][nmap_proto][int(masscan_port)]['product']
                                    version = nm[host][nmap_proto][int(masscan_port)]['version']
                                    if 'tcpwrapped' not in protocol:
                                        if 'http' in protocol or protocol == 'sun-answerbook':
                                            if protocol == 'https' or protocol == 'https-alt' or masscan_port == 443:
                                                scan_url_port = 'https://' + host + ':' + str(masscan_port)
                                            else:
                                                scan_url_port = 'http://' + host + ':' + str(masscan_port)
                                            
                                            finger_data = self.mysqldb.all_finger(username)
                                            cms = Fofa_Scanner(scan_url_port, finger_data['fofa_cms'])
                                            fofa_finger = asyncio.run(cms.run())
                                            cms_name = ''
                                            for fofa_finger_tmp in fofa_finger:
                                                if fofa_finger_tmp.lower() in cms.cms_finger_list:
                                                    cms_name = fofa_finger_tmp
                                            '''
                                            if not cms_name:
                                                whatcms = WhatCms(scan_url_port, finger_data['cms'])
                                                cms_result = whatcms.run()
                                                cms_result = list(set(cms_result))
                                                if cms_result:
                                                    cms_name = cms_name + '\n' + ''.join(cms_result)
                                            '''

                                            result = asyncio.run(get_title(scan_url_port))
                                            self.mysqldb.save_target_port(username, target, scan_id,  host, str(masscan_port), cms_name, protocol, product, version, result[0], result[1])
                                            self.mysqldb.save_port(username, target, scan_url_port, host, str(masscan_port), cms_name, protocol, product, version, result[0], result[1])
                                        else:
                                            scan_url_port = str(host) + ':' + str(masscan_port)
                                            self.mysqldb.save_target_port(username, target, scan_id, host, str(masscan_port), '', protocol, product, version, '', '')
                                            self.mysqldb.save_port(username, target, scan_url_port, host, str(masscan_port), '', protocol, product, version, '', '')
                                            scan_list.append(scan_url_port)
                            except Exception as e:
                                # print(e)
                                pass
                            finally:
                                pass
        except Exception as e:
            # print(e)
            pass
        finally:
            print('Masscan scanned.....\n')
            return scan_list

if __name__ == '__main__':
    port_scan = Port_Scan()
    port_scan.masscan_scan('127.0.0.1')