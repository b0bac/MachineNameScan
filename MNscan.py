# -*- coding:utf-8 -*-
"""
作者：挖洞的土拨鼠
背景：应急的时候被不能跨广播域找到netbios的机器名，急死了，分析了一波Nmap -A的扫描机器名的原理，发现是靠3389
端口通信里面的返回值判断的（有主机名），这样可以在一定程度上解决这个问题，如果单纯只需要检查机器名的时候可以使用。
"""
# 需要用到的依赖库
import sys
import socket


#全局配置，配置套接字超时时间
socket.setdefaulttimeout(3)


#全局变量、函数
def StringToBinary(content):
    """将文本16进制字符串转成二进制流字符串"""
    try:
        content = content.replace(" ", '').replace('\n', '')
    except Exception, reason:
        raise
    try:
        content = content.decode('hex')
    except Exception, reason:
        raise
    return content

#3389发送数据包数据
CorePayload = """
1603010200010001fc0303428aed87844464ed9311e408e
97a4a98e475b5ccf350cc328e029c3358ecdef90000da00
05000400020001001600330039003a00180035000a001b0
02f0034c010c006c015c00bc001003bc030c02cc028c024
c014c00a00a500a300a1009f006b006a006900680038003
700360088008700860085c01900a7006d0089c032c02ec0
2ac026c00fc005009d003d0084c02fc02bc027c023c013c
00900a400a200a0009e00670040003f003e003200310030
009a0099009800970045004400430042c01800a6006c009
b0046c031c02dc029c025c00ec004009c003c0096004100
07c011c007c016c00cc002c012c00800130010000dc017c
00dc00300ff010000f9000b000403000102000a001c001a
00170019001c001b0018001a0016000e000d000b000c000
9000a00230000000d0020001e0601060206030501050205
03040104020403030103020303020102020203000f00010
1001500a000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000"""


#机器名扫描类
class NmScanner:
    """机器名扫描类"""
    def __init__(self,ipaddress,port=None):
        """初始化参数数据"""
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = (ipaddress, int(port)) if port != None else (ipaddress, 3389)
        self.data = CorePayload
    def Scan(self):
        """扫描函数，根据回显提取机器名数据"""
        try:
            self.client.connect(self.address)
        except Exception, reason:
            return "无法扫描出机器名"
        try:
            self.client.send(StringToBinary(self.data))
        except Exception, reason:
            return "无法扫描出机器名"
        data = self.client.recv(4096)
        self.client.close()
        """
            取回来的回显字段是数据包中的一段数据，\\x1e\\x17是回包紧跟在机器名后面的标志字段值；
            前面的标志位是\\x13后面接一个机器名长度的16进制\\x00-\\xff中的一个值，然后就是机器名；
            机器名结尾有个0；
        """
        return repr(data)[0:repr(data).find('\\x1e\\x17')].split('\\x13')[-1][4:-1]

if __name__ == "__main__":
    try:
        ip = sys.argv[1]
    except Exception, reason:
        print "请输入对方IP地址"
        exit(0) 
    try:
        port = int(sys.argv[2])
        scanner = NmScanner(ip,port)
    except Exception, reason:
        scanner = NmScanner(ip)
    print scanner.Scan()


