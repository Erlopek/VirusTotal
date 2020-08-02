"""
Python 3
VirusTotal Public API v2.0



__author__ = "Erlopek"
__copyright__ = "Copyright 2017, Erlopek"
__license__ = "Apache License"
__version__ = "1.0.2"
__maintainer__ = "Erlopek"
__email__ = "33432468+Erlopek@users.noreply.github.com"
__status__ = "Beta"

"""

import requests, argparse, json, sys, urllib
from colorama import Fore, Back, Style, init


parser = argparse.ArgumentParser(description='VirusTotal API Script')
parser.add_argument('-f', '--file', help='File eg: sample.exe', required=False)
parser.add_argument('-r', '--report', help='Hash of sample eq: 34534646464364', required=False)
parser.add_argument('-ho', '--hostname', help='Hostname eg: www.virustotal.com', required=False)
parser.add_argument('-u', '--url', help='URL eg: http://www.virustotal.com', required=False)
parser.add_argument('-re', '--rescan', help='Force rescan, eg: hash of sample eq: 34534646464364', required=False)
parser.add_argument('-ur', '--urlreport', help='See existing report, eg: http://www.virustotal.com or scan_id', required=False)
parser.add_argument('-i', '--ip', help='IP eq: 90.156.201.27', required=False)
parser.add_argument('-d', '--domain', help='Domain eq: 027.ru', required=False)

init(autoreset=True)
args = vars(parser.parse_args())

if len(sys.argv) <= 2:
    parser.print_help()
    sys.exit(1)

# Your API key
params = {'apikey': 'xxxxxx'}


def report_request(hash_id):
    params['resource'] = hash_id
    headers = {"Accept-Encoding": "gzip, deflate",
               "User-Agent": "gzip, My python report"}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers)
    global report_out
    report_out = response.json()
    return report_out


def rescan_request(hash_id):
    params['resource'] = hash_id
    headers = {"Accept-Encoding": "gzip, deflate",
               "User-Agent": "gzip, My python rescan"}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',
                             params=params, headers=headers)
    global report_out
    report_out = response.json()
    return report_out


def scan_request(fill):
    files = {'file': (fill, open(fill, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    global report_out
    report_out = response.json()
    return report_out


def scan_url(urls):
    params['url'] = urls
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    global report_out
    report_out = response.json()
    return report_out


def url_report(urls):
    params['resource'] = urls
    headers = {"Accept-Encoding": "gzip, deflate",
               "User-Agent": "gzip, My python report"}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                             params=params, headers=headers)
    global report_out
    report_out = response.json()
    return report_out


def scan_ip(ips):
    params['ip'] = ips
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(params))).read()
    global report_out
    report_out = json.loads(response)
    return report_out


def scan_domain(domains):
    params['domain'] = domains
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(params))).read()
    global report_out
    report_out = json.loads(response)
    return report_out


if args["file"]:
    scan_request(args["file"])
    print ("""\nPermalink: {} \nVerbose_msg: {} \nScan_id: {} \nsha256: {} \n"""
           .format(report_out['permalink'], report_out['verbose_msg'],
                   report_out['scan_id'], report_out['sha256']))

    answer = input("Would you like to see reports?, (Y)yes or (N)o :")
    if answer == "Y" or answer == "y":
        report_request(report_out['scan_id'])
        while report_out['response_code'] != 1:
            print("Too soon  ")
            answer = input("Try again ? (Y)yes or (N)o :")
            if answer == "Y" or answer == "y":
                report_request(report_out['scan_id'])
            else:
                break
        else:
            print ("""\nPermalink: {} \nScandate: {} \nScan_id: {} \nsha256: {} \n"""
                   .format(report_out['permalink'], report_out['scan_date'],
                           report_out['scan_id'], report_out['sha256']))
            for i in report_out['scans']:
                print("{}: ".format(i))
                if str(report_out['scans'][i]['detected']) == "False":
                    print(Fore.GREEN + "Clean")
                else:
                    print (Fore.RED + ("Malicious -- {}"
                                       .format(str(report_out['scans'][i]['result']))))


if args["report"]:
    report_request(args["report"])
    while report_out['response_code'] != 1:
        print("Too soon ")
        answer = input("Try again ? (Y)yes or (N)o :")
        if answer == "Y" or answer == "y":
            report_request(args["report"])
        else:
            break
    else:
        print ("""\nPermalink: {} \nScandate: {} \nScan_id: {} \nsha256: {} \n"""
               .format(report_out['permalink'], report_out['scan_date'],
                       report_out['scan_id'], report_out['sha256']))
        for i in report_out['scans']:
            print("{}: ".format(i))
            if (str(report_out['scans'][i]['detected']) == "False"):
                print(Fore.GREEN + "Clean")
            else:
                print (Fore.RED + ("Malicious -- {}"
                           .format(str(report_out['scans'][i]['result']))))


if args["rescan"]:
    rescan_request(args["rescan"])
    print ("""\nPermalink: {}  \nScan_id: {} \nsha256: {} \n"""
           .format(report_out['permalink'],
                   report_out['scan_id'], report_out['sha256']))

    answer = input("Would you like to see reports, (Y)yes or (N)o :")
    if answer == "Y" or answer == "y":
        report_request(report_out['scan_id'])
        while report_out['response_code'] != 1:
            print("Too soon  ")
            answer = input("Try again ? (Y)yes or (N)o :")
            if answer == "Y" or answer == "y":
                report_request(report_out['scan_id'])
            else:
                break
        else:
            print ("""\nPermalink: {} \nScandate: {} \nScan_id: {} \nsha256: {} \n"""
                   .format(report_out['permalink'], report_out['scan_date'],
                           report_out['scan_id'], report_out['sha256']))
            for i in report_out['scans']:
                print("{}: ".format(i))
                if tr(report_out['scans'][i]['detected']) == "False":
                    print(Fore.GREEN + "Clean")
                else:
                    print (Fore.RED + ("Malicious -- {}"
                                       .format(str(report_out['scans'][i]['result']))))


if args["url"]:
    scan_url(args["url"])
    print ("""\nPermalink: {} \nVerbose_msg: {} \nScan_id: {} \nurl: {} \n"""
           .format(report_out['permalink'], report_out['verbose_msg'],
                   report_out['scan_id'], report_out['url']))
    answer = input("Would you like to see reports?, (Y)yes or (N)o :")
    if answer == "Y" or answer == "y":
        url_report(report_out['scan_id'])
        while report_out['response_code'] != 1:
            print("Too soon  ")
            answer = input("Try again ? (Y)yes or (N)o :")
            if answer == "Y" or answer == "y":
                url_report(report_out['scan_id'])
            else:
                break
        else:
            print ("""\nPermalink: {} \nVerbose_msg: {} \nScan_id: {} \nurl: {} \n"""
                   .format(report_out['permalink'], report_out['verbose_msg'],
                           report_out['scan_id'], report_out['url']))
            for i in report_out['scans']:
                print("{}: ".format(i))
                if str(report_out['scans'][i]['detected']) == "False":
                    print(Fore.GREEN + "Clean")
                else:
                    print (Fore.RED + ("Malicious -- {}"
                                       .format(str(report_out['scans'][i]['result']))))


if args["urlreport"]:
    url_report(args["urlreport"])
    while report_out['response_code'] != 1:
        print("Too soon ")
        answer = input("Try again ? (Y)yes or (N)o :")
        if answer == "Y" or answer == "y":
            url_report(args["urlreport"])
        else:
            break
    else:
        print ("""\nPermalink: {} \nVerbose_msg: {} \nScan_id: {} \nurl: {} \n"""
               .format(report_out['permalink'], report_out['verbose_msg'],
                       report_out['scan_id'], report_out['url']))
        for i in report_out['scans']:
            print("{}: ".format(i))
            if str(report_out['scans'][i]['detected']) == "False":
                print(Fore.GREEN + "Clean")
            else:
                print (Fore.RED + ("Malicious -- {}"
                           .format(str(report_out['scans'][i]['result']))))


if args["ip"]:
    scan_ip(args["ip"])
    if report_out['response_code'] == 0:
        print(Fore.RED + "\nNo info about this IP ")
    elif report_out['response_code'] == -1:
        print(Fore.RED + "\nWrong IP Addresss ")
    else:
        print ("""\nInfo: {} """ .format(report_out['verbose_msg'],))
        if len(report_out['resolutions']) < 10:
            for i in range(0, len(report_out['resolutions'])):
                print(Fore.BLUE + "\nWhen: {}  Hostname: {}"  .format(report_out['resolutions'][i]['last_resolved'],
                      report_out['resolutions'][i]['hostname']))
        else:
            for i in range(0, 10):
                print(Fore.BLUE + "\nWhen: {}  Hostname: {}"  .format(report_out['resolutions'][i]['last_resolved'],
                      report_out['resolutions'][i]['hostname']))
        if len(report_out['detected_urls']) < 10:
            for i in range(0, len(report_out['detected_urls'])):
                print(Fore.CYAN + "\nUrl: {}   Alerts: {} Date of Scan {}"  .format(report_out['detected_urls'][i]
                ['url'], report_out['detected_urls'][i]['positives'], report_out['detected_urls'][i]['scan_date']))
        else:
            for i in range(0, 10):
                print(Fore.CYAN + "\nUrl: {}   Alerts: {} Date of Scan {}"  .format(report_out['detected_urls'][i]
                ['url'], report_out['detected_urls'][i]['positives'], report_out['detected_urls'][i]['scan_date']))


if args["domain"]:
    scan_domain(args["domain"])
    if report_out['response_code'] == 0:
        print(Fore.RED + "\nNo info about this Domain ")
    elif report_out['response_code'] == -1:
        print(Fore.RED + "\nWrong Domain ")
    else:
        print ("""\nInfo: {} """ .format(report_out['verbose_msg'],))
        if len(report_out['resolutions']) < 10:
            for i in range(0, len(report_out['resolutions'])):
                print(Fore.BLUE + "\nWhen: {}  IP: {}"  .format(report_out['resolutions'][i]['last_resolved'],
                      report_out['resolutions'][i]['ip_address']))
        else:
            for i in range(0, 10):
                print(Fore.BLUE + "\nWhen: {}  IP: {}"  .format(report_out['resolutions'][i]['last_resolved'],
                      report_out['resolutions'][i]['ip_address']))
        if len(report_out['detected_urls']) < 10:
            for i in range(0, len(report_out['detected_urls'])):
                print(Fore.CYAN + "\nUrl: {}   Alerts: {} Date of Scan {}"  .format(report_out['detected_urls'][i]
                ['url'], report_out['detected_urls'][i]['positives'], report_out['detected_urls'][i]['scan_date']))
        else:
            for i in range(0, 10):
                print(Fore.CYAN + "\nUrl: {}   Alerts: {} Date of Scan {}"  .format(report_out['detected_urls'][i]
                ['url'], report_out['detected_urls'][i]['positives'], report_out['detected_urls'][i]['scan_date']))
