"""
Menu Title: VirusTotal Search

Description:
	Search all selected files against the third-party VirusTotal
	service. Should we find any results, store said results into custom
	metadata fields.

Dependencies:
	Must have an Internet connection, and must supply your own VirusTotal API
	key in the required variable.

Author: Nuix CTAT + Innovation Team

Tested On: Nuix 8.4
"""

import urllib2
import urllib
import json
import time
import javax.swing

# Must set this.
apikey = ""

# Public API provides 4 requests/minute. Should you have a private and/or 
# research API, please alter this accordingly. 
sleep_time = 15 

jp = javax.swing.JOptionPane

if apikey == "":
	jp.showMessageDialog(None, "VirusTotal API key must be set.")
else:
	url = "http://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"apikey": apikey}

	allFiles = currentSelectedItems
	total = len(allFiles)
	print("Selected " + str(total) + " items")
	discovered = 0
	for item in allFiles:
		parameters["resource"] = str(item.digests.md5)
		data = urllib.urlencode(parameters)
		try: 
			req = urllib2.Request(url, data)
			response = urllib2.urlopen(req)
			raw = response.read()
			json_data = json.loads(raw)
			if json_data["response_code"] == 1:
				discovered += 1
				cm = item.getCustomMetadata()
				cm.putInteger("VirusTotal Hits", json_data["positives"])
				for scanner, res in json_data["scans"].iteritems():
					cm.putText("VirusTotal " + scanner, res["result"])
		except urllib2.HTTPError, e:
			print('HTTPError = ' + str(e.code))
			break;
		except urllib2.URLError, e:
			print('URLError = ' + str(e.reason))
			break;
		except httplib.HTTPException, e:
			print('HTTPException')
			break;
		except Exception:
			import traceback
			print('generic exception: ' + traceback.format_exc())
			break
		time.sleep(sleep_time)

	msg = "VirusTotal Search script has finished. %d / %d found." % (discovered, total)
	print(msg)
	jp.showMessageDialog(None, msg)
