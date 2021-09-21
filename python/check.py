#!/usr/bin/env python3

import os
import sys
import signal

def check(parameter):
    
    """
    等待指定时间后杀掉指定的进程

    :param str parameter: 要查找的进程名字关键字
    :return:
    
    """
    
    try:
        out = os.popen("ps -ef |grep \'%s\' |grep -v grep | awk '{print $2}'" %(parameter)).read()
        if out:
            for line in out.splitlines():
                try:
                    os.kill(int(line), signal.SIGKILL)
                except Exception as e:
                    print(e)
                    pass
    except Exception as e:
        print(e)
    finally:
        pass

if __name__ == "__main__":
    parameter = sys.argv[1]
    check(parameter)