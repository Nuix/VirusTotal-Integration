# Nuix Worker side script for Virus Total lookup
# v1.0
# updated 2021-01-28

import urllib2
import json
import time

# APIKEY must be set. Get one from Virus Total
# Please note Virus Total's requirements for the Public API below
####
# The Public API is limited to 500 requests per day and a rate of 4 requests per minute.
# The Public API must not be used in commercial products or services.
# The Public API must not be used in business workflows that do not contribute new files.
APIKEY = ""

# For PoCs using a Public API key, there is a rate limit pf 4 requests/minute. 
# It is therefore advisable to set a sleep time here of 15 (seconds)
# When using a Premium Key this can be set to 0
SLEEP_TIME = 15 

# Virus Total API url for file ID check
FILEURL = "https://www.virustotal.com/api/v3/files/"

# List mime types to INCLUDE here. Can reduce processing files not of interest
# To run against every item with an md5, set MIME_INCLUSIONS = None
MIME_INCLUSIONS = [
    "application/exe",
    "application/java-class",
    "application/octet-stream",
    "application/pdf"
]

# Define which properties you wish to be set on the item here.
# Items set to True will be added as a property / tag (if available)
# Change to False if you do not wish to add a particular property / tag
SET_VHASH = True
SET_IMPHASH = True
SET_AUTHENTIHASH = True
SET_TAGS = True


def nuixWorkerItemCallback(worker_item):
    source_item = worker_item.getSourceItem()
    mime_type = source_item.getType().getName()
    if not MIME_INCLUSIONS or mime_type in MIME_INCLUSIONS:
        # Get this item's MD5
        md5 = worker_item.digests.md5
        if md5 is not None:
            fullUrl = FILEURL + str(md5)
            try:
                req = urllib2.Request(fullUrl)
                req.add_header('x-apikey', APIKEY)
                response = urllib2.urlopen(req)
                data = json.load(response)
                properties = source_item.getProperties()
                # The count of AVs identifying the file as Malicious
                worker_item.addCustomMetadata("AVs identifing item as malicious", data["data"]["attributes"]["last_analysis_stats"]["malicious"],'text','user')
                # vHash
                if SET_VHASH and data["data"]["attributes"].has_key("vhash"):
                	properties["vHash"] = data["data"]["attributes"]["vhash"]
                # Import Hash
                if SET_IMPHASH and data["data"]["attributes"].has_key("pe_info") and data["data"]["attributes"]["pe_info"].has_key("imphash"):
                	properties["Import Hash"] = data["data"]["attributes"]["vhash"]
                # Authentihash
                if SET_AUTHENTIHASH and data["data"]["attributes"].has_key("authentihash"):
                	properties["Authentihash"] = data["data"]["attributes"]["authentihash"]
                # Virus Total defined tags. Often this can be a list that needs to be looped through
                if SET_TAGS and data["data"]["attributes"].has_key("tags"):
                	for tag in data["data"]["attributes"]["tags"]:
                		worker_item.addTag("VirusTotal|" + tag)
                # Finally the analysis results provide the details from each AV, so loop through them
                for scanner, res in data["data"]["attributes"]["last_analysis_results"].iteritems():
                    if res["result"] is not None:
                       worker_item.addCustomMetadata("VirusTotal " + scanner,res["result"],'text','user')
                worker_item.setItemProperties(properties)
            except urllib2.HTTPError, e:
            	# 404 returned when the md5 doesn't exist on VT
                if str(e.code) == "404":
                    worker_item.addCustomMetadata("VirusTotal","Item md5 not matched in database",'text','user')
                # 401 Auth error, likely API key issue
                elif str(e.code) == "401":
                	worker_item.addCustomMetadata("VirusTotal","Unauthorised. Invalid API key?",'text','user')
                else:
                    worker_item.addCustomMetadata('Processing Error','HTTPError = ' + str(e.code),'text','user')
            except urllib2.URLError, e:
                worker_item.addCustomMetadata('Processing Error','URLError = ' + str(e.reason),'text','user')
            except Exception:
                import traceback
                worker_item.addCustomMetadata('Processing Error','exception: ' + traceback.format_exc(),'text','user')
            time.sleep(SLEEP_TIME)
