#encoding : utf-8

from furl import furl

from lib.check_bypass import *
from lib.common import *


def main(target, parameter):


    url_param = furl(target)

    banner()
    logging.info("Starting to test {} SSRF....".format(url_param.host))

    #check_cache(url_param.host)

    if not livetest(target):
        logging.info("Cant connect the target")
        sys.exit(0)

    if not test_check(target, parameter):
        check_bypass(target, parameter)



if __name__ == "__main__":
    target = "http://192.168.1.109/vuln/ssrf/ssrf.php"
    parameter = "url"
    main(target, parameter)