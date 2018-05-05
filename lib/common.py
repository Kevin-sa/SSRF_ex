#encoding : utf-8

from lib.config import *
import math
from lib.config import get_requests

def banner():
    ban = "[+] SSRFex/0.1 - SSRF Vulnerability discovery and utilization \n"
    print(ban)

#judge the target is living
def livetest(target):
    try:
        if get_requests(target):
            return True
    except:
        logging.warning("Access target failed")
        return False

#set ssrf_test judge test_limit
def check_time_limit(target):
    response_time = []

    for i in range(30):
        r = get_requests(target)
        response_time.append(float(r.elapsed.microseconds))


    average = sum(response_time) / len(response_time)
    #lowerstdlimit = average + 1* stdev(response_time, average)
    lowerstdlimit = average

    return lowerstdlimit

#static file hash values to judge SSRF_test
def static_files_hash():
    r = get_requests('http://www.baidu.com/favicon.ico').text
    hash_value = hash(r)

    return hash_value

#calculate the variance
def stdev(values, average):
    summa = 0.0
    for value in values:
        summa += pow((value - average), 2)

    result = math.sqrt(summa / (len(values) - 1))
    return result


