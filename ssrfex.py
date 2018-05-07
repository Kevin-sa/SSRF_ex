#encoding : utf-8

from lib.check_bypass import *
from lib.common import *
from lib.scan import run,file_reader
import argparse

def main(args):
    target = args.target
    parameter = args.parameter
    ip = args.ip

    protocol = []

    url_param = furl(target)

    banner()
    logging.info("Starting to test {} SSRF....".format(url_param.host))

    check_cache(url_param.host)
    check_kown(target)

    if not livetest(target):
        logging.info("Cant connect the target")
        sys.exit(0)

    protocol = test_check(target, parameter)

    if not protocol:
        if check_bypass(target, parameter):
            run(target,parameter,ip_c= ip)


    else:
        if 'file' in protocol:
            file_reader(target, parameter)
        run(target, parameter, ip_c=ip)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog = 'ssrfex.py',usage='%(prog)s [option] [args] usage', description='ssrf test')
    parser.add_argument("-u",dest="target",type=str,help="url targrt")
    parser.add_argument("-d",dest="parameter",type=str,help="SSRF vuln in the parameter")
    parser.add_argument("-i",dest='ip',type=str,help="probe the network ip")
    args = parser.parse_args()

    try:
        main(args)
    except Exception as e:
        logging.error(str(e))
        exit(1)
