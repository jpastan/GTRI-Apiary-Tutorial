#!/usr/bin/env python3

'''
Author: James Pastan
Title: general-setup.py
Use: Script used explaining apiary searches
'''

import requests
import json
import pprint
import sys
import ast

def main():

    #first, we open a session to be able to make requests to the apiary API
    s = requests.Session()

    #for our session, we must give it a certification so it has the permission
    #to make the appropriate calls. In this example, we have placed our cert
    #.pem file in a file named /cert and for dummy purposes have named the file
    #jane_doe.pem. For your general use, set s.cert to the location of your
    #apiary cert file -- adding to the ./certs file is encouraged.

    s.cert = './certs/James_Pastan.pem'

    #now that our session is allowed to make requests, we can do a test to ensure
    #our certificate has been added appropriately

    #here, we do a dummy request to ensure we can reach the apiary website given
    #the information entered for the certification

    try:

        #if this works without returning an error, we can proceed, otherwise
        #the program will stop as there has been an error adding our certificate
        s.get('https://apiary.gtri.gatech.edu/')

    except:
        sys.stderr.write('''Could not locate certificate to contact Apiary: {}\n'''.format(s.cert))
        exit(1)

    #if we make it here, it means we can now make a request. I will now walk you through multiple request examples.

    #Lets begin with a simple search given we know a hash.

    #We define our search as follows:

    hash_link = "https://apiary.gtri.gatech.edu/api/v1/samples/"

    #and in this example we will be using the following sha256 value as our search parameter

    sha256 = "07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd"

    #To search a hash, we simply add the sha256 value to the end of the url we defined above

    hash_url = hash_link + sha256

    #Now that we have the approriate search instance, we use the requests session we made earlier
    #to actually get information from the apiary website. We will use a defined function
    #called get_json to get the json data at our url. Please look at the get_json_url
    #function to see how to make a request.

    hash_data = get_json_url(s, hash_url)

    pprint.pprint(hash_data)

    #this returns a dictionary that looks as follows:

    '''
    {u'results': {u'_id': {u'$oid': u'59190f39a0d99175a2dbeea3'},
              u'caveats': [],
              u'dropped_by': [],
              u'export': True,
              u'file_exists': True,
              u'filename': u'd724d8cc6420f06e8a48752f0da11c66',
              u'groups': [],
              u'hashes': {u'md5': {u'@Hash': u'd724d8cc6420f06e8a48752f0da11c66'},
                          u'sha1': {u'@Hash': u'3b669778698972c402f7c149fc844d0ddb3a00e8'},
                          u'sha256': {u'@Hash': u'07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd'},
                          u'ssdeep': u'98304:Z8qPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2HI:Z8qPe1Cxcxk3ZAEUadzR8yc4HI'},
              u'ingest_date': {u'$date': 1494814521093},
              u'last_ingested': {u'$date': 1494814521093},
              u'private': False,
              u'readable_identifier': u'',
              u'sources': [{u'customer_id': {u'$oid': u'4e57928522d8ecc54fdea59f'},
                            u'time': {u'$date': 1494814521093}}],
              u'suspicion': {u'score': 7.6,
                             u'summary': {u'AV Detection': u'Win.Ransomware.WannaCry-6313787-0',
                                          u'Packing': u'Armadillo',
                                          u'TCP Connection to host which is down': u'Yes'},
                             u'threat': 3},
              u'type': u'pe'}}
    '''

    #specific information can be accessed as a simple dictionary like,

    print("file type is: {}".format(hash_data['results']['type']))

    #What if we wanted all of the information regarding the analysis modules for a given hash?

    #We use the following url for getting analysis information:

    # https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/

    # Now, we will make a new URL where the {0} index is where we place a specific hash.

    analysis_url = 'https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/'.format(sha256)

    #Again, we can simply get the data at our newly parsed url using our requests session:

    analysis_data = get_json_url(s, analysis_url)

    pprint.pprint(analysis_data)

    #this returns a dictionary that looks as follows:

    '''
    {u'results': {u'ClamAV': [{u'_id': {u'$oid': u'59190f3aa9d1cb76a02dcdd3'},
                               u'time': {u'$date': 1494814526207}}],
                  u'Multi-file Windows Examination': [{u'_id': {u'$oid': u'59441c5a2b18c1061347e75e'},
                                                       u'time': {u'$date': 1497636083467}}],
                  u'Network Observation Module': [{u'_id': {u'$oid': u'59190f3aa9d1cb76a02dcdd2'},
                                                   u'time': {u'$date': 1494814684842}}],
                  u'Static File Info': [{u'_id': {u'$oid': u'59190f3aa0d99175a2dbeea4'},
                                         u'time': {u'$date': 1494814521093}}],
                  u'Strings': [{u'_id': {u'$oid': u'59190f3aa9d1cb76a02dcdd1'},
                                u'time': {u'$date': 1494814525621}}],
                  u'Suricata': [{u'_id': {u'$oid': u'59441d035737491a04d43660'},
                                 u'time': {u'$date': 1497636131352}}],
                  u'Yara': [{u'_id': {u'$oid': u'59190f3aa9d1cb76a02dcdd4'},
                             u'time': {u'$date': 1494814554103}}]}}

    '''

    #the $oid field is the location of the report corresponding to a hash

    #if we wanted to get the ClamAV data for a hash, we would generate a new URL:

    # https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/{1}

    #where {0} is the hash and {1} is the $oid value. In other words:

    for type in analysis_data['results']:
        if type == "ClamAV":
            for each in analysis_data['results'][type]:
                clamav_url = analysis_url + each["_id"]["$oid"]

    #Once more, we can simply get the data at our newly parsed url using our requests session:

    clamav_data = get_json_url(s, clamav_url)

    pprint.pprint(clamav_data)

    #This returns the following information:

    '''
{u'results': {u'_id': {u'$oid': u'59190f3aa9d1cb76a02dcdd3'},
              u'av': {u'status': u'infected',
                      u'virus': u'Win.Ransomware.WannaCry-6313787-0',
                      u'virus_count': 1140},
              u'caveats': [],
              u'configuration': {},
              u'dropped_files': [],
              u'module': u'ClamAV',
              u'module_id': {u'$oid': u'4e81c5fa771803c58299ef0d'},
              u'module_version': 0,
              u'previous_result_id': {u'$oid': u'59190f3aa0d99175a2dbeea4'},
              u'sample_hash': {u'@Hash': u'07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd'},
              u'sample_id': {u'$oid': u'59190f39a0d99175a2dbeea3'},
              u'screenshots': [],
              u'start_time': {u'$date': 1494814525302},
              u'syscall': [],
              u'time': {u'$date': 1494814526207},
              u'types': [u'av'],
              u'url': []}}
    '''

    #What if we wanted to print the information for all of the report modules?

    #Well, we could instantiate a list:

    report_urls = list()

    #And then cycle through the results we got originally from analysis_data,
    #generating new urls as we go.

    for type in analysis_data['results']:
        for each in analysis_data['results'][type]:
            new_url = 'https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/{1}'.format(sha256, each['_id']['$oid'])
            report_urls.append(new_url)

    for url in report_urls:
        print(url)

        #if you'd like to see all of the data printed for each report, uncomment the following:
        # pprint.pprint(get_json_url(s, url))

    #This returns:

    '''
https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/59190f3aa9d1cb76a02dcdd4
https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/59441c5a2b18c1061347e75e
https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/59190f3aa9d1cb76a02dcdd2
https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/59441d035737491a04d43660
https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/59190f3aa9d1cb76a02dcdd3
https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/59190f3aa0d99175a2dbeea4
https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/59190f3aa9d1cb76a02dcdd1
    '''

    #where each link contains the json data for the specific report of a given hash

    #Now we will dive into how to search Apiary generally with parameters. The URL
    #mutated is of the form:
    #  https://apiary.gtri.gatech.edu/api/v2/results/?search={0}&embed=true&per_page={1}
    # where {0} is the parameters, each separated by +AND+ and {1} is a number between 1 and 500 (default value of 10)
    # For the purposes of this example, we will be going through common {0} options with a per_page value of 10

    general_search_start = "https://apiary.gtri.gatech.edu/api/v2/results/?search="
    general_search_end = "&embed=true&per_page=10"

    # Now we will get into the most common search parameters for a general search on apiary

    #DATE:
    #To search by date, use they keyword "last_ingested:[DATE_START+TO+DATE_END]"
    #where the date parameters are in %Y-%m-%d format
    #For example, to get all samples on July 4th, 2017, we would type:

    date_range = "sample.ingest_date:[2017-07-04+TO+2017-07-04]"
    query = general_search_start + date_range + general_search_end

    #and as we have done previously, we would get results by:

    date_data = get_json_url(s, query)

    #the date_data dictionary now contains information split into two fields:
    #"_meta" which contains an overview of the search:

    pprint.pprint(date_data["_meta"])

    '''
    {u'count': 764736,
     u'embed': True,
     u'fields': u'',
     u'first_page': u'https://apiary.gtri.gatech.edu/api/v2/results/?per_page=10&search=sample.ingest_date%3A%5B2017-07-04+TO+2017-07-04%5D&embed=true&start=0',
     u'last_page': u'https://apiary.gtri.gatech.edu/api/v2/results/?per_page=10&search=sample.ingest_date%3A%5B2017-07-04+TO+2017-07-04%5D&embed=true&start=764730',
     u'next_page': u'https://apiary.gtri.gatech.edu/api/v2/results/?per_page=10&search=sample.ingest_date%3A%5B2017-07-04+TO+2017-07-04%5D&embed=true&start=10',
     u'per_page': 10,
     u'prev_page': None,
     u'search': u'sample.ingest_date:[2017-07-04 TO 2017-07-04]',
     u'sort': u'',
     u'start': 0,
     u'this_page': u'https://apiary.gtri.gatech.edu/api/v2/results/?per_page=10&search=sample.ingest_date%3A%5B2017-07-04+TO+2017-07-04%5D&embed=true&start=0'}
    '''

    #count returns the total number of results. since results are returned in increments of 10, the ["_meta"]
    #field also included information about navigating to future pages, which will be required to proceed to new pages
    #Apiary operates under a 10,000 search restriction, so even though our search led to a count of over 700,000, the
    #first 10,000 results would be the only ones available. I am not going to print all the information from date_data["results"]
    #as it would return too much, so for this tutorial we are going to look at the first result:

    for each in date_data["results"]:
        pprint.pprint(each)
        break

    '''
    {u'_links': {u'collection': u'https://apiary.gtri.gatech.edu/api/v2/results/',
                 u'self': u'https://apiary.gtri.gatech.edu/api/v2/results/595bd4915737492a847b1635/'},
     u'android': None,
     u'av': None,
     u'cdf': None,
     u'configuration': {u'OS Selection': u'Windows 7 64-bit',
                        u'Run Time': 120,
                        u'Simulated Internet': u'No (connect to actual Internet)',
                        u'Take Screenshots': u'No'},
     u'dropped_files': [],
     u'estimated_region': None,
     u'executable': None,
     u'flash': None,
     u'id': u'595bd4915737492a847b1635',
     u'image': None,
     u'jpeg': None,
     u'module': u'Network Observation Module',
     u'network': {u'dns': [],
                  u'ftp': [],
                  u'http': [],
                  u'irc': [],
                  u'net': [{u'application': None,
                            u'as': [],
                            u'blacklist': [],
                            u'country': None,
                            u'data_received': 0,
                            u'data_sent': 2832,
                            u'ip': u'192.168.0.255',
                            u'port': 137,
                            u'proto': u'udp'},
                           {u'application': None,
                            u'as': [],
                            u'blacklist': [],
                            u'country': None,
                            u'data_received': 0,
                            u'data_sent': 2883,
                            u'ip': u'192.168.0.255',
                            u'port': 138,
                            u'proto': u'udp'},
                           {u'application': None,
                            u'as': [],
                            u'blacklist': [],
                            u'country': None,
                            u'data_received': 0,
                            u'data_sent': 630,
                            u'ip': u'ff02::1:2',
                            u'port': 547,
                            u'proto': u'udp'}],
                  u'protos_dissected': [],
                  u'smtp': [],
                  u'tcp': []},
     u'nids': None,
     u'office': None,
     u'other': None,
     u'pcap': {u'_links': {u'download': u'https://apiary.gtri.gatech.edu/api/v2/file/595d148dd8726131bd67ceb5/download',
                           u'self': u'https://apiary.gtri.gatech.edu/api/v2/file/595d148dd8726131bd67ceb5/'},
               u'id': u'595d148dd8726131bd67ceb5',
               u'mimetype': u'application/x-gzip',
               u'name': u'595bd4915737492a847b1635.gz',
               u'sha256': u'8234e889e5525881c04596cb18f5f717815e343b26181a059b909f03cb132791'},
     u'pdf': None,
     u'run_date': u'2017-07-05T16:32:13.088000+00:00',
     u'sample': {u'_links': {u'collection': u'https://apiary.gtri.gatech.edu/api/v2/samples/',
                             u'comments': u'https://apiary.gtri.gatech.edu/api/v2/samples/411283ee8eda6a1c751311a0e59c5c940a006187c088f3c33fb5aa8ac6bd48dd/comments/',
                             u'self': u'https://apiary.gtri.gatech.edu/api/v2/samples/411283ee8eda6a1c751311a0e59c5c940a006187c088f3c33fb5aa8ac6bd48dd/'},
                 u'dropped_by': [],
                 u'filename': u'e6394befad417d849923cb39c4dc6b45',
                 u'hashes': {u'md5': u'e6394befad417d849923cb39c4dc6b45',
                             u'sha1': u'947a5094d25e4d20a5e1e637a9a711a5afa1707e',
                             u'sha256': u'411283ee8eda6a1c751311a0e59c5c940a006187c088f3c33fb5aa8ac6bd48dd'},
                 u'ingest_date': u'2017-07-04T17:46:57.155000+00:00',
                 u'last_ingested': u'2017-07-04T17:46:57.155000+00:00',
                 u'readable_identifier': u'',
                 u'sources': [{u'customer': {u'_links': {u'collection': u'https://apiary.gtri.gatech.edu/api/v2/customers/',
                                                         u'self': u'https://apiary.gtri.gatech.edu/api/v2/customers/ga0xWZ_lu254QANgd4jK7A%3D%3D',
                                                         u'users': u'https://apiary.gtri.gatech.edu/api/v2/users/?customer=ga0xWZ_lu254QANgd4jK7A%3D%3D'},
                                             u'customer_since': u'2011-08-26T12:33:09+00:00',
                                             u'id': u'ga0xWZ_lu254QANgd4jK7A==',
                                             u'name': None},
                               u'original_email': None,
                               u'time': u'2017-07-04T17:46:57.155000+00:00',
                               u'user': None}],
                 u'suspicion': {u'score': 1.0, u'summary': {}, u'threat': 0},
                 u'tags': [],
                 u'type': u'pe',
                 u'url': None},
     u'sample_hash': u'411283ee8eda6a1c751311a0e59c5c940a006187c088f3c33fb5aa8ac6bd48dd',
     u'screenshots': [],
     u'start_time': u'2017-07-05T16:28:24.187000+00:00',
     u'strings': None,
     u'syscall': [],
     u'system': None,
     u'types': [u'pcap', u'network'],
     u'url': [],
     u'viex': None,
     u'virustotal': None,
     u'webexec': None}

        '''

    #this returns a loooot of information, as each result in an apiary search returns both
    #general information about a hash as well as the report information corresponding to that hash for the module
    #list in ["results"]["module"] -- as can be seen above, we get information about the network observation module for hash
    # 411283ee8eda6a1c751311a0e59c5c940a006187c088f3c33fb5aa8ac6bd48dd (which can be found under
    # ["results"]["sample_hash"] or ["results"]["sample"]["hashes"]["sha256"])
    # as well as the general overview for the hash.

    #All of the "overview" kind of informaiton is found in the subdictionary ["sample"], which
    # contains info like ingest date, the sample sources, various scores, etc.

    #While we get Network Ovservation Module results here for this hash, it is my recommendation that
    #for getting information regarding a sepcific report for a sepcific hash, you use the links
    #described for hash specific searches. Usually, the purpose of doing a general Apiary API search
    #is to gain a list of hashes correspoinding to certian criteria, which then can be cyclced through
    #to gain any specific information.

    #For example, say I wanted to do research on hashes from July 4th. I would take our query above,
    #saved in the date_data variable and do the following:

    date_hashes = list()

    for each in date_data["results"]:
        date_hashes.append(each["sample_hash"])

    #now I have a list of hashes from my query, all samples from July 4th, 2017-07

    for hash in date_hashes:
        print(hash)

    '''
    411283ee8eda6a1c751311a0e59c5c940a006187c088f3c33fb5aa8ac6bd48dd
    796c68bd26758876b2650865b27b7584385221bc06992a61b955ed88dfd6a5ef
    22643576b9e21cd2df2ff54a524b5056f721cb4bb317ff9b66878cb7a6b19505
    36e36b2491340f132c54473b05b9483a260ba06d27bc402d072b59530316d872
    50c028fd123cf75e46547217909b8938fe44abaea9ae00c1ec99fa8ccdf9a59b
    17cbf192f1fe7d1de43bf0cbb7901dfc4151dfdf6a582f63e4834f040a211cc9
    5c0ad0cf2550f33c433f0a88cfe2710381b6e024ca3fd7a9ca84b4ad897e0246
    012dd83354d55753cca469b666b3a0f6aba84a00eb82346094ee325dbf098481
    8e556c8e5ecbf9225d31500a873b4986a5f2d0d709e8b5377c3d1d62f618b450
    1a7b9e7a8cdbcbd981c0d7ba75d4f2d0a782074b767ab3b4c7c55f97ab7103f5
    '''

    #I could then take each of those hashes, mutuate new search URLs, and gain any
    #sort of specific information I wanted. Again, this is instead of taking the
    #Network Observation Module data from the general search page.

    #You might be asking -- well, there were over 700,000 search results and you got
    #a list of 10. What about the others?

    #To solve this, we simply store the next_page information for a search, construct
    #a while loop, and save data as necessary.

    #For example:

    next_page = date_data["_meta"]["next_page"]

    fifty_date_hashes = list()

    while not next_page == None:

        #we will break our search after gathering 50 hashes. However, this
        #could be 10,000!
        if len(fifty_date_hashes) > 50:
            break

        #set the next_page value
        next_page = date_data["_meta"]["next_page"]

        #cycle through and get hashes
        for each in date_data["results"]:
            fifty_date_hashes.append(each["sample_hash"])

        print("Loading: {}".format(next_page))

        #load the next page
        date_data = get_json_url(s, next_page)


    #now we have 50 hashes stored in date_hashes we can do something with!

    #TYPE:

    #For searching filetype, use the keyword:
    # sample.type:{0}
    #where {0} is
    # 'office', 'zip', 'url', 'ms-dos', 'pe', 'pdf', 'android'

    #SUSPICION SCORE:

    #for searching by suspicion score, use the keyword:
    # suspicion_score:[START+TO+END]
    # where start and end are numbers between 0 and 10

    #MODULE:

    #for searching for hashes with specific modules, use the keyword:
    # module:{0}
    # where {0} is any of the following:
    # 'Sentar ViEX', 'TrendAV', 'Multi-file Windows Examination', 'Network Observation Module', 'Suricata', 'ClamAV', 'Static Analysis', 'Baremetal', 'Strings'
    #  any spaces in module name must be replaced with a '+'

    # To put all of this together, let's do an example where we create a search that meets the following parameters:
    # Type: pe, Date: May, June and July of 2017, Suspicion Score: between 1 and 4, Module: Multi-file Windows Examination

    date = "sample.ingest_date:[2017-05-01+TO+2017-07-31]"
    type = "sample.type:pe"
    suspicion_score = "sample.suspicion_score:[1+TO+4]"
    module = "module:\"Multi-file+Windows+Examination\""

    #we generate our parameter string by separating our parameters by "+AND+"
    parameter_string = date+"+AND+"+type+"+AND+"+suspicion_score+"+AND+"+module

    #Now, we generate the search:
    search = general_search_start+parameter_string+general_search_end

    print("Getting url: {}".format(search))

    #And we get the information:

    restricted_search = get_json_url(s, search)

    pprint.pprint(restricted_search["_meta"])

    #Which gives us:

    '''
    {u'count': 45,
     u'embed': True,
     u'fields': u'',
     u'first_page': u'https://apiary.gtri.gatech.edu/api/v2/results/?per_page=10&search=sample.ingest_date%3A%5B2017-05-01+TO+2017-07-31%5D+AND+sample.type%3Ape+AND+sample.suspicion_score%3A%5B1+TO+4%5D+AND+module%3A%22Multi-file+Windows+Examination%22&embed=true&start=0',
     u'last_page': u'https://apiary.gtri.gatech.edu/api/v2/results/?per_page=10&search=sample.ingest_date%3A%5B2017-05-01+TO+2017-07-31%5D+AND+sample.type%3Ape+AND+sample.suspicion_score%3A%5B1+TO+4%5D+AND+module%3A%22Multi-file+Windows+Examination%22&embed=true&start=40',
     u'next_page': u'https://apiary.gtri.gatech.edu/api/v2/results/?per_page=10&search=sample.ingest_date%3A%5B2017-05-01+TO+2017-07-31%5D+AND+sample.type%3Ape+AND+sample.suspicion_score%3A%5B1+TO+4%5D+AND+module%3A%22Multi-file+Windows+Examination%22&embed=true&start=10',
     u'per_page': 10,
     u'prev_page': None,
     u'search': u'sample.ingest_date:[2017-05-01 TO 2017-07-31] AND sample.type:pe AND sample.suspicion_score:[1 TO 4] AND module:"Multi-file Windows Examination"',
     u'sort': u'',
     u'start': 0,
     u'this_page': u'https://apiary.gtri.gatech.edu/api/v2/results/?per_page=10&search=sample.ingest_date%3A%5B2017-05-01+TO+2017-07-31%5D+AND+sample.type%3Ape+AND+sample.suspicion_score%3A%5B1+TO+4%5D+AND+module%3A%22Multi-file+Windows+Examination%22&embed=true&start=0'}

    '''

    #our specific search has given us 45 results, all correspoinding to the parameters listed in ["_meta"]["search"]!


#function that takes a request session and a url and returns the information
#from the given url
def get_json_url(s, url):

    #using our session, we attempt to get the information at the given url

    try:

        #first, we query the API
        res = s.get(url)

        #we check our session for an error and exit the program if a problem is found
        if not res.status_code == 200:
            print ("Error on {}: {}".format(date, res.text))
            exit(1)

        #otherwise we return a dictionary of what we found at our url
        return res.json()


    #if an error occurs, we catch it and exit the program
    except requests.exceptions.RequestException as e:
        print("Error: [%s]" %(e))
        exit(1)



if __name__=='__main__':

    main()
