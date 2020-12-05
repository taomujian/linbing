#!/usr/bin/env python3

import nmap
import masscan

class Port_Scan():
    def __init__(self, mysqldb, aes_crypto):
        self.mysqldb = mysqldb
        self.aes_crypto = aes_crypto

    def nmap_scan(self, username, target, description, target_ip, min_port, max_port):
        """
        用nmap进行扫描

        :param str username: 用户名
        :param str target: 待扫描的目标
        :param str target_ip: 待扫描的目标ip
        :param str min_port: 扫描端口的最小值
        :param str max_port: 扫描端口的最大值
        :return list scan_list: 扫描的结果
        """
        scan_list = []
        print('Nmap starting.....')
        self.mysqldb.update_scan(username, target, '开始扫描端口')
        nm = nmap.PortScanner()
        arguments = '-p %s-%s -sS -sV -Pn -T4 --open' % (min_port, max_port)
        nm.scan(hosts = target_ip, arguments = arguments)
        try:
            for host in nm.all_hosts():
                for nmap_proto in nm[host].all_protocols():
                    lport = nm[host][nmap_proto].keys()
                    lport = sorted(lport)
                    for nmap_port in lport:
                        protocol = nm[host][nmap_proto][int(nmap_port)]['name']
                        product = nm[host][nmap_proto][int(nmap_port)]['product']
                        version = nm[host][nmap_proto][int(nmap_port)]['version']
                        if not self.mysqldb.get_target_port(username, target, nmap_port):
                            self.mysqldb.save_target_port(username, target, description, self.aes_crypto.encrypt(str(nmap_port)), self.aes_crypto.encrypt(protocol), self.aes_crypto.encrypt(product), self.aes_crypto.encrypt(version))
                        else:
                            self.mysqldb.update_target_port(username, target, description, self.aes_crypto.encrypt(str(nmap_port)), self.aes_crypto.encrypt(protocol), self.aes_crypto.encrypt(product), self.aes_crypto.encrypt(version))
                        scan_list.append(str(host) + ':' + str(nmap_port))
            print('Nmap scanned.....')
            self.mysqldb.update_scan(username, target, '端口扫描结束')
        except Exception as e:
            print(e)
            pass
        finally:
            pass
        return scan_list

    def masscan_scan(self, username, target, description, target_ip, min_port, max_port, rate):
        """
        用masscan进行扫描

        :param str username: 用户名
        :param str target: 待扫描的目标
        :param str target_ip: 待扫描的目标ip
        :param str min_port: 扫描端口的最小值
        :param str max_port: 扫描端口的最大值
        :param str rate: 扫描速率
        :return list scan_list: 扫描的结果
        """
        scan_list = []
        print('Masscan starting.....\n')
        self.mysqldb.update_scan(username, target, '开始扫描端口')
        masscan_scan = masscan.PortScanner()
        masscan_scan.scan(hosts = target_ip, ports = '%s-%s' % (min_port, max_port), arguments = '-sS -Pn -n --randomize-hosts -v --send-eth --open --rate %s' % (rate))
        try:
            for host in masscan_scan.all_hosts:
                for masscan_proto in masscan_scan[host].keys():
                    for masscan_port in masscan_scan[host][masscan_proto].keys():
                        nm = nmap.PortScanner()
                        arguments = '-p %s -sS -sV -Pn -T4 --open' % (masscan_port)
                        nm.scan(hosts = host, arguments = arguments)
                        for nmap_proto in nm[host].all_protocols():
                            protocol = nm[host][nmap_proto][int(masscan_port)]['name']
                            product = nm[host][nmap_proto][int(masscan_port)]['product']
                            version = nm[host][nmap_proto][int(masscan_port)]['version']
                            if not self.mysqldb.get_target_port(username, target, masscan_port):
                                self.mysqldb.save_target_port(username, target, description, self.aes_crypto.encrypt(str(masscan_port)), self.aes_crypto.encrypt(protocol), self.aes_crypto.encrypt(product), self.aes_crypto.encrypt(version))
                            else:
                                self.mysqldb.update_target_port(username, target, description, self.aes_crypto.encrypt(str(masscan_port)), self.aes_crypto.encrypt(protocol), self.aes_crypto.encrypt(product), self.aes_crypto.encrypt(version))
                            scan_list.append(str(host) + ':' + str(masscan_port))
            print('Masscan scanned.....\n')
            self.mysqldb.update_scan(username, target, '端口扫描结束')
        except Exception as e:
            print(e)
            pass
        finally:
            pass
        return scan_list

if __name__ == '__main__':
    port_scan = Port_Scan()
    port_scan.masscan_scan('127.0.0.1')