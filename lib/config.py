#encoding : utf-8

import logging,requests,os,json,sys
from random import choice
from furl import furl
#file path


def check_cache(host):
    file_path = os.path.dirname(os.path.abspath(__file__))
    result_path = os.path.join(file_path, 'result')
    mkdir_path = os.path.join(result_path, host)
    if os.path.exists(mkdir_path):
        logging.info("the target was caching in result")
        sys.exit(0)
    else:
        os.makedirs(mkdir_path)

def out_put(host,filename,data):
    file_path = os.path.dirname(os.path.abspath(__file__))
    result_path = os.path.join(file_path, 'result')
    output_path = os.path.join(result_path,"{}/{}".format(host,filename))

    fw = open('result/{}/{}'.format(host,filename), 'a')
    fw.writelines(data)



#set output log
logging.basicConfig(level = logging.INFO,
                    format = '%(asctime)s - %(levelname)s: %(message)s')


#dump console
def dump_console(host="", parameter="", payload="", protocol="",rules="" ,filename=""):
    data = ''
    data += "[+]url: {0}\n".format(host)
    data += "[+]parameter: {0}\n".format(parameter)
    if payload:
        data += "[+]payload: {0}\n".format(payload)

    if protocol:
        data += "[+]payload: {0}\n".format(protocol)

    if rules:
        for rule in rules:
            data += "[+]available rule: {0}\n".format(rule)

    if filename:
        filename = filename
    else:
        filename = 'test.log'

    logging.info("\n---\n" + data + "\n---\n")

    f = furl(host)

    out_put(f.host, filename, data)






#Random User-Agent
User_Agent = [
"Mozilla/5.0 (Windows; U; Windows NT 6.0; cs; rv:1.9.0.13) Gecko/2009073022 Firefox/3.0.13",
"Mozilla/5.0 (Windows; U; Windows NT 6.0; cs; rv:1.9.0.19) Gecko/2010031422 Firefox/3.0.19",
"Opera 9.4 (Windows NT 5.3; U; en)",
"Opera 9.4 (Windows NT 6.1; U; en)",
"Opera/9.64 (X11; Linux i686; U; pl) Presto/2.1.1",
]

#Set http headers
headers = {
    'User-Agent' : choice(User_Agent),
    'Rederer' : '',
    'Cookie' : ''
}

#requests
def get_requests(target,timeout='',cookie=''):
    if cookie:
        headers['Cookie'] = cookie
    if timeout:
        timeout = timeout
    else:
        timeout = 5
    content = requests.get(target,
                           headers = headers,
                           timeout = timeout
                           )
    return content