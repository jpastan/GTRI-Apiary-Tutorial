#!/usr/bin/env python3

'''
Author: James Pastan
Title: search-apiary.py
Use: Script used for searching apiary
'''

import argparse
import sys
import datetime
from datetime import date
import requests
import os
import json
import time

#data for converting tags to full names
module_conversion = {
    "mfwe":"Multi-file Windows Examination",
    "clamav":"ClamAV",
    "tav":"TrendAV",
    "yara":"Yara",
    "suricata":"Suricata",
    "sfi":"Static File Info",
    "strings":"Strings",
    "nom":"Network Observation Module",
    "viex":"Sentar ViEX",
    "static":"Static Analysis",
    "baremetal":"Baremetal",
    "vt":"VirusTotal"
}

#bool for write or append file
append = False

def checkdates(dates):

    #try to convert to datetime
    try:
        start = datetime.datetime.strptime(dates[0], '%Y-%m-%d')
        stop = datetime.datetime.strptime(dates[1], '%Y-%m-%d')
    except:
        sys.stderr.write('''Invalid Date: impossible date entered: {}, {}\n'''.format(dates[0], dates[1]))
        exit(1)

    #three invalid date errors -- too old, too new, start date later than stop date
    if start > stop:
        sys.stderr.write('''Invalid Date: start-date before end-date: {}, {}\n'''.format(dates[0], dates[1]))
        exit(1)
    if stop.date() > date.today():
        sys.stderr.write('''Invalid Date: stop-date after today's date: {}\n'''.format(dates[1]))
        exit(1)
    if start.year < 2008:
        sys.stderr.write('''Invalid Date: start-date must begin on or after 2008-01-01: {}\n'''.format(dates[0]))
        exit(1)

    #returns properly formatted date string
    return 'sample.ingest_date:[{0}+TO+{1}]'.format(dates[0], dates[1])

def checkss(scores):

    #set ss
    lower = scores[0]
    upper = scores[1]

    #check for suspicion score errors
    if lower >= upper or lower < 0 or upper > 10:
        sys.stderr.write('''Invalid Suspicion Score parameters: {} {}'''.format(lower, upper))
        exit(1)

    #returns properly formatted ss for search
    return 'sample.suspicion_score:([{}+TO+{}])'.format(lower, upper)


def output(data, path):

    global append

    #check if save specified
    if not path == None:

        #check global append param to see if write or append file
        if not append:

            #reset append if need be
            append = True
            with open(path, 'w') as outfile:

                #check appropriate write type
                if isinstance(data, dict):
                    outfile.write(json.dumps(data) + '\n')
                else:
                    outfile.write(data + '\n')

        else:
            with open(path, 'a') as outfile:

                #check appropriate write type
                if isinstance(data, dict):
                    outfile.write(json.dumps(data) + '\n')
                else:
                    outfile.write(data + '\n')

    #otherwise print to stdout
    else:
        print(data)



def hash_search(args, s, path):

    #checks for potential errors in selecting the reports fields
    if (not args.getreport == False and (args.availablereports or args.getallreports) or (args.availablereports and args.getallreports)):
        sys.stderr.write('''User can only select one of the following:
            -getallreports
            -getreport
            -availablereports\n''')
        exit(1)

    track = 0

    if not args.info == False:
        overview = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/".format(args.sha256[0]))
        output(overview, path)

    if not args.availablereports == False:
        reports = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/".format(args.sha256[0]))
        output(reports, path)


    if not args.getallreports == False:
        page = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/".format(args.sha256[0]))
        for header in page["results"]:
            for subheader in page["results"][header]:
                reports = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/{1}".format(args.sha256[0], subheader['_id']['$oid']))
                output(reports, path)

    global module_conversion

    if not args.getreport == False:
        page = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/".format(args.sha256[0]))
        searched = []
        for each in args.getreport:
            found = False
            if each in searched:
                continue
            else:
                searched.append(each)
            for header in page["results"]:
                if module_conversion[each] == header:
                    found = True
                    for module in page["results"][header]:
                        report = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/{1}".format(args.sha256[0], module["_id"]['$oid']))
                        output(report, path)
            if not found:
                output('''{} not found for {}. Visit Apiary to schedule the hash for more modules.\n'''.format(module_conversion[each], args.sha256[0]), path)

    if not args.ss == False:
        page = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/".format(args.sha256[0]))
        output(str(page['results']['suspicion']['score']), path)

    if not args.threat == False:
        page = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/".format(args.sha256[0]))
        output(str(page['results']['suspicion']['threat']), path)

    if not args.ingestdate == False:
        page = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/".format(args.sha256[0]))
        epoch = float(page['results']['ingest_date']['$date'])
        utc = time.strftime('%Y-%m-%d', time.localtime(epoch/1000))
        output(utc, path)

    if not args.type == False:
        page = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v1/samples/{0}/".format(args.sha256[0]))
        output(page['results']['type'], path)


def get_json_url(s, url):

    try:
        #queries API
        res = s.get(url)

        #check for Error
        if not res.status_code == 200:
            sys.stderr.write('''A problem occured when searching {}. Script aborted.\n'''.format(url))
            exit(1)

        #returns dict
        return res.json()

    except requests.exceptions.RequestException as e:
        sys.stderr.write("An error occured when searching: [%s]. Script aborted.\n" %(e))
        exit(1)

def do_search(url, s, path):

    #get page json
    page = get_json_url(s, "https://apiary.gtri.gatech.edu/api/v2/results/?search={0}&embed=true&per_page=10".format(url))

    count = page['_meta']['count']
    if count == 0:
        sys.stderr.write("No results for entered parameters. Exiting.\n")
        exit(1)

    #next page for given search
    next_page = page["_meta"]["next_page"]

    #tracks progress
    track = 0

    while not next_page == None and not page == None:
        #elastic search has a fundamental limitation on
        #searches over 10,000 entries.
        if track == 10000:
            break
        for hashes in page['results']:
                track = track + 1
                #next page for given search
                next_page = page["_meta"]["next_page"]

                #get sha
                sha = hashes['sample_hash']

                #passes to function for print or file writing
                output(sha, path)

        #gets new page
        page = get_json_url(s, next_page)


def create_search(args, s, path):
    #check for errors and generate search URL
    #empty string to build search parameter
    search = None

    #checks dates, returns valid, usable dates if passes
    if not args.daterange == None:

        date_query = checkdates(args.daterange)
        search = date_query

    #makes correct limit parameter
    if args.limit > 10000:
        sys.stderr.write('''The result limit cannot exceed 10000\n''')
        exit(1)

    #if suspicion scores are invalid
    if not args.ssrange == None:

        ss = checkss(args.ssrange)
        if not search == None:
            search = search + '+AND+' + ss
        else:
            search = ss

    #makes correct filetype parameter
    if not args.filetype == None:
        ft = 'sample.type:{}'.format(args.filetype[0])
        if not search == None:
            search = search + '+AND+' + ft
        else:
            search = ft

    #makes correct module parameter
    if not args.module == None:
        global module_conversion

        #converts module code to proper string
        mod = 'module:{}'.format(module_conversion[args.module[0]].replace(" ", "+"))
        if not search == None:
            search = search + '+AND+' + mod
        else:
            search = mod

    #passes off to function that does search
    do_search(search, s, path)


def main(args):

    #add cert to requests session
    s = requests.Session()
    s.cert = args.cert[0]

    #undergo dummy request to check cert
    try:
        s.get('https://apiary.gtri.gatech.edu/')
    except:
        sys.stderr.write('''Could not locate certificate to contact Apiary: {}\n'''.format(args.cert[0]))
        exit(1)

    #set up save functionality
    if not args.save == None:

        #create folder to store report
        base = './reports'
        if not os.path.exists(base):
            os.mkdir(base)

        path = os.path.join(base, args.save[0] + '-apiary.txt')

    else:
        path = None

    args.func(args, s, path)



if __name__=='__main__':

    #instantiate argument parser
    argparser = argparse.ArgumentParser(prog='search-apiary',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''User inputs flags in order to get basic data from the Apiary database.
    For more information on how to search Apiary GENERALLY, please enter:\n\n

        python search-apiary search -h

    For more informaiton on how to search Apiary BY A SPECIFIC HASH, please enter:\n\n

        python search-apiary hash -h
        ''')

    requiredNamed = argparser.add_argument_group('required fields')

    requiredNamed.add_argument('-cert', required=True, nargs=1, metavar='CERT_FILE_LOCATION',
        help='''flag specifying location of user certification''')

    argparser.add_argument('-save', nargs=1, metavar='FILE_NAME',
        help='''flag that, when specified, saves the output in a file named by the user instead of printing to stdout''')


    #add subparsers for hash and search
    subparsers = argparser.add_subparsers()

    #search choice lists
    module_options = ['mfwe', 'clamav', 'tav', 'yara', 'suricata',
                            'sfi', 'strings', 'nom', 'viex', 'static', 'baremetal',
                            'vt']
    filetype_options = ['office', 'zip', 'url', 'ms-dos', 'pe', 'pdf', 'android']

    #instantiate search parser
    parser_search = subparsers.add_parser('search',
        help='''argument indicating user requesting general search of Apiary''')

    #set search parser arguments
    parser_search.add_argument('-daterange', nargs=2, metavar=('START_DATE', 'END_DATE'),
        help='''flag indicating user setting date ranges for a general Apiary search -- must be in %Y-%m-%d format''')

    parser_search.add_argument('-ssrange', type=int, nargs=2, metavar=('LOWER_BOUND', 'UPPER_BOUND'),
        help='''flag indicating user setting suspicion score ranges for a general Apiary search''')

    parser_search.add_argument('-module', nargs=1, choices=module_options,
        help='''flag indicating user setting module requirement for search results -- options listed above''')

    parser_search.add_argument('-filetype', nargs=1, choices=filetype_options,
        help='''flag indicating user setting file type requirement for search results -- options listed above''')

    parser_search.add_argument('-limit', nargs=1, type=int, default=10000, metavar="#",
        help='''flag indicating number of hashes that should be returned -- default and max of 10000''')

    parser_search.set_defaults(func=create_search)

    #instantiate hash parser
    parser_hash = subparsers.add_parser('hash',
        help='''argument indicating user requesting hash-specific search of Apiary''')

    #set hash parser arguments
    parser_hash.add_argument('sha256', nargs=1, metavar='SHA256_VALUE',
        help='''sha256 value for a hash search''')

    parser_hash.add_argument('-info',  action='store_true',
        help='''returns overview for a hash''')

    parser_hash.add_argument('-getallreports', action='store_true',
        help='''flag that, when specified, will return all analysis results for a given hash''')

    parser_hash.add_argument('-availablereports', action='store_true',
        help='''returns list of available reports and their report ids for a hash''')

    parser_hash.add_argument('-getreport', nargs='+', choices=module_options, default=False,
        help='''returns all reports specified by user, multiple options may be entered''')

    parser_hash.add_argument('-ss', action='store_true',
        help='''returns the suspicion score of a hash''')

    parser_hash.add_argument('-threat', action='store_true',
        help='''returns the threat of a hash''')

    parser_hash.add_argument('-ingestdate', action='store_true',
        help='''returns the ingest date of a hash''')

    parser_hash.add_argument('-type', action='store_true',
        help='''returns the file type of a hash''')

    parser_hash.set_defaults(func=hash_search)

    args = argparser.parse_args()

    main(args)
