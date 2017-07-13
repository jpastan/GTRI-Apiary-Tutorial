James Pastan -- Using the Apiary API

The following information walks you through how to make simple Apiary API calls.

It is strongly recommended the user begin with the guided walk through in the general-setup.py file.

An index of this directory can be found below.

INDEX:

		An Apiary overview can be found in SEARCH OVERVIEW

		For a guided walk through to apiary requests, please navigate to the GENERAL-SETUP sub-header.

		The sub-header SEARCH-APIARY explains the search-apiary.py file, which can be used to get data from Apiary.


++++++++++++++++++++SEARCH OVERVIEW+++++++++++++++++++++++++

The Apiary API general search loads a page corresponding to your search parameters with up to 500 results per page. Each
result represents a report for a certain hash.

#For calling general API with search parameters
* https://apiary.gtri.gatech.edu/api/v2/results/?search={0}&embed=true&per_page={1}
	$ 0: search parameters separated by "+AND+"
	$ 1: results per page - default set at 10, max of 500
* ex: https://apiary.gtri.gatech.edu/api/v2/results/?search=module:ClamAV+AND+av.status:infected&embed=true&per_page=10
* useful result parameters:
	$ _meta:
		$ count: number of results for a search
		$ next_page: url for the next page of results
	$ results:
		$ sample_hash: the sha256 value for the result
		$ module: the report module for the result
		$ sample:
			$ ingest_date: ingest date
			$ hashes:
				$ sha256: sha256 value of result
				$ sha1: sha1 value of result
				$ md5: md5 value of result
			$ type: file type of the result
			$ suspicion:
				$ score: suspicion score for a result
				$ threat: threat level of a result

Sometimes an overview of information is wanted for just a single hash. The following api call can be used to do so:

#For loading an overview of a single hash
* https://apiary.gtri.gatech.edu/api/v1/samples/{0}
	$ 0: sha256 value
* ex: https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd
* useful result parameters:
	$ results:
		$ ingest_data: ingest date
		$ hashes:
			$ sha256:
				$ @Hash: sha256 value of result
			$ sha1:
				$ @Hash: sha1 value of result
			$ md5:
				$ @Hash: md5 value of result
		$ type: file type of the result
		$ suspicion:
			$ score: suspicion score for a result
			$ threat: threat level of a result


Generally, a user will search certain parameters with the hope of building out a list of hashes that correspond to a certain query.
For example, if the user wanted a list of hashes on a certain date with a certain suspicion score, it is strongly recommended NOT
to pull all of the data from the general search URL above. Instead, we recommend the following API commands to navigate to individual hash entries.
From here, the user can load the individual analysis pages for a hash.

#For getting the list of reports for a given hash and where those reports can be found
* https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/
	$ 0: sha256 value
* ex: https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/
* useful result parameters:
	$ results: all of the analysis data for a hash
		$ _id:
			$ $oid: id parameter to load a report as needed below

Each hash has certain analysis data with a specified analysis oid. Using a hash and the analysis oid gained from the search above,
the user can navigate to the individual analysis pages for a certain hash using the following command.

#Loading a report for a hash
* https://apiary.gtri.gatech.edu/api/v1/samples/{0}/results/{1}
	$ 0: sha256 value
	$ 1: report id, found at the call above
* ex: (for the Yara module from the page above):
	https://apiary.gtri.gatech.edu/api/v1/samples/07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd/results/59190f3aa9d1cb76a02dcdd4
* useful result parameters: dependent upon the analysis page -- familiarize yourself with the different JSON layouts for different apiary analysis modules

++++++++++++++++++++GENERAL-SETUP+++++++++++++++++++++++++

*NOTE: The following scripts are written such that a user can pipe in certain information
using argparser. However, this is expensive in that it requires the user to define cert location every time
a call is made. Please see the "general-setup.py" file for information as to how to best
configure a file for data scraping.

#general-setup.py
A file not meant to actually be used for any searches, but shows how to setup a script
for data scraping. Commented for easy explanation. Please read and start here.
The other file included, search-apiary.py has been for general use. However,
after reading general-setup.py, the user should have enough information to begin
writing his/her own scripts for apiary data scraping.

To begin, open the general-setup.py file, set your cert location, and begin reading.
From the terminal, calling:

python general-setup.py

will run the file and print the appropriate data as specified in the file. However,
everything needed for understanding is also included as comments in the file.



++++++++++++++++++++SEARCH APIARY+++++++++++++++++++++++++

#search-apiary.py
usage: search-apiary [-h] -cert CERT_FILE_LOCATION [-save FILE_NAME]
                     {search,hash} ...

User inputs flags in order to get basic data from the Apiary database.
    For more information on how to search Apiary GENERALLY, please enter:

        python search-apiary search -h

    For more informaiton on how to search Apiary BY A SPECIFIC HASH, please enter:

        python search-apiary hash -h


positional arguments:
  {search,hash}
    search              argument indicating user requesting general search of
                        Apiary

    hash                argument indicating user requesting hash-specific
                        search of Apiary

optional arguments:
  -h, --help            show this help message and exit

  -save FILE_NAME       flag that, when specified, saves the output in a file
                        named by the user instead of printing to stdout

required fields:
  -cert CERT_FILE_LOCATION
                        flag specifying location of user certification

#for hash specified search
usage: search-apiary -cert CERT_FILE_LOCATION [-save FILE_NAME] hash SHA256_VALUE [-h] [-info] [-getallreports] [-availablereports]
                          [-getreport [{mfwe,clamav,tav,yara,suricata,sfi,strings,nom,viex,static,baremetal,vt} [{mfwe,clamav,tav,yara,suricata,sfi,strings,nom,viex,static,baremetal,vt} ...]]]
                          [-ss] [-threat] [-ingestdate] [-type]

positional arguments:
  SHA256_VALUE          sha256 value for a hash search

optional arguments:
  -h, --help            show this help message and exit
  -info                 returns overview for a hash
  -getallreports        flag that, when specified, will return all analysis
                        results for a given hash
  -availablereports     returns list of available reports and their report ids
                        for a hash
  -getreport [{mfwe,clamav,tav,yara,suricata,sfi,strings,nom,viex,static,baremetal,vt} [{mfwe,clamav,tav,yara,suricata,sfi,strings,nom,viex,static,baremetal,vt} ...]]
                        returns all reports specified by user, multiple
                        options may be entered
  -ss                   returns the suspicion score of a hash
  -threat               returns the threat of a hash
  -ingestdate           returns the ingest date of a hash
  -type                 returns the file type of a hash


#for general search
usage: search-apiary -cert CERT_FILE_LOCATION [-save FILE_NAME] search [-h] [-daterange START_DATE END_DATE]
                            [-ssrange LOWER_BOUND UPPER_BOUND]
                            [-module {mfwe,clamav,tav,yara,suricata,sfi,strings,nom,viex,static,baremetal,vt}]
                            [-filetype {office,zip,url,ms-dos,pe,pdf,android}] [-limit #]

optional arguments:
  -h, --help            show this help message and exit
  -daterange START_DATE END_DATE
                        flag indicating user setting date ranges for a general
                        Apiary search
  -ssrange LOWER_BOUND UPPER_BOUND
                        flag indicating user setting suspicion score ranges
                        for a general Apiary search
  -module {mfwe,clamav,tav,yara,suricata,sfi,strings,nom,viex,static,baremetal,vt}
                        flag indicating user setting module requirement for
                        search results -- options listed above
  -filetype {office,zip,url,ms-dos,pe,pdf,android}
                        flag indicating user setting file type requirement for
                        search results -- options listed above
  -limit #              flag indicating number of hashes that should be
                        returned -- default of 10000

examples:

python search-apiary.py -cert ./certs/jane_doe.pem hash 07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd -getreport mfwe clamav
python search-apiary.py -cert ./certs/jane_doe.pem hash 07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd -getallreports

python search-apiary.py -cert ./certs/jane_doe.pem search -date 2016-09-15 2016-09-16
python search-apiary.py -cert ./certs/jane_doe.pem search -ss 4 6
python search-apiary.py -cert ./certs/jane_doe.pem search -ss 6 6.5 -module mfwe
