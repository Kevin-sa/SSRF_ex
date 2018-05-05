#encoding : utf-8

from lib.check import *
import xml.etree.ElementTree as ET

#xml parse and load payload and rules
def load_payload():
    payload = []

    tree = ET.ElementTree(file='lib/xmltest.xml')
    root = tree.getroot()

    for element in root.getiterator('test'):
        test = {}

        for child in element.getchildren():
            if child.text and child.text.strip():
                test[child.tag] = child.text
            else:
                if len(child.getchildren()) == 0:
                    test[child.tag] = None
                    continue
                else:
                    test[child.tag] = {}

        payload.append(test)

    return payload

def check_bypass(target, parameter):
    avalilable_rules = []
    lowerstdlimit = check_time_limit(target)
    payloads = load_payload()

    for payload in payloads:

        target_payload = target + "?"+ parameter + "={0}".format(payload['payload'])

        if check_time_content(target_payload,lowerstdlimit):
            avalilable_rules.append(payload['rules'])

    dump_console(host=target,parameter=parameter,rules=avalilable_rules,filename='rules.log')








