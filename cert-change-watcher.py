#!/usr/bin/python
import requests
import argparse
import json
import os
import re

# temp file
CERTSPOTTER_PATH = '.certspotter.json'

def update_issuances(apitoken,domain,stored_issuances):
    cert = stored_issuances[-1]
    last_id = cert['id']

    print ("Last ID ", last_id)
    issuances = grab_issuances(apitoken,domain,last_id)

    return issuances

def grab_issuances(apitoken,domain, last_id):
    issuances = [] 
    url = "https://api.certspotter.com/v1/issuances"
    headers = {
        'Authorization': "Bearer " + apitoken,
        'cache-control': "no-cache"
    }
    payload = ""
    if last_id:
        print ("last ID present running from ", last_id)
        querystring = {"after":last_id, "domain":domain, "expand":["dns_names","issuer"], "include_subdomains":"true"}
    else:
        querystring = {"domain":domain,"expand":["dns_names","issuer"],"include_subdomains":"true"}

    print ("final query string ", querystring)
    response = requests.request("GET", url, data=payload, headers=headers, params=querystring)


    # store for issuances 
    issuances = json.loads(response.text)
    
    # grab subsequent pages
    while 'Link' in response.headers:
        print ("processing subsequent pages: ", response.headers['Link'])
        m = re.search('</v1/issuances\?after=(\d+)\&.+', response.headers['Link'])
        if m:
            after = m.group(1)
            querystring = {"after":after, "domain":domain, "expand":["dns_names","issuer"], "include_subdomains":"true"}
            response = requests.request("GET", url, data=payload, headers=headers, params=querystring)
            for i in json.loads(response.text):
                issuances.append(i)
    return issuances

def sendslack(slackhook, domain, changes):

    slack_data = {'text': ":lock: certificate changes have been detected for: {0}\n```{1}```\n".format(str(d),json.dumps(changes,indent=4))}

    response = requests.post(
        slackhook, data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text)
    )


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="monitors certificate changes using cert spotter api and alerts to slack", epilog="""
    In order to use this tool you will need an API key from certspotter, and also provide the slack API web hook.""")
    parser.add_argument("-k", "--apitoken", required=True, help="api token for cert spotter, example 1234_adfdafasfdas")
    parser.add_argument("-s", "--slackhook", required=False, default="", help="slack web hook to notify of changes")
    parser.add_argument("-d", "--domains", required=True, default="", help="command delimited list of domains to monitor changes for, example \"splunk.com,elastic.com\"")

    # parse them
    args = parser.parse_args()
    apitoken = args.apitoken
    slackhook = args.slackhook
    slackhook = args.slackhook
    domains = args.domains.split(',')

    issuances = dict()
    update_state = False
    # check if the phistank temp file has been updated recently
    if os.path.exists(CERTSPOTTER_PATH):

        # grab our state file
        with open(CERTSPOTTER_PATH) as f:
            stored_issuances = json.load(f)

        for d in domains:

            # check if the domain passed is in our state file otherwise pull a state
            if d not in stored_issuances:
                update_state = True
                print("## domain {0} has never been seen .. fetching state ##".format(d))
                issuances[d] = grab_issuances(apitoken,d,"")
                continue

            # check for updates
            current_issuances = update_issuances(apitoken,d,stored_issuances[d])

            # if updates send alert, and otherwise just keep current state 
            if len(current_issuances) > 0:
                update_state = True
                print("## domain {0} has changes: ##".format(d))
                print(json.dumps(current_issuances, indent=4))
            
                if slackhook:
                    sendslack(slackhook,d,changes)
                for i in changes:
                    print(json.dumps(i, indent=4))
                issuances[d] = current_issuances
            else:

                issuances[d] = stored_issuances[d]

        if update_state:
            print("## updating state {0} ##".format(CERTSPOTTER_PATH))
            with open(CERTSPOTTER_PATH, 'w') as outfile:
                json.dump(issuances, outfile)
        else:
            print("## no changes ##")
    else:
        print "## seems this is our first run .. certspotter state file not present ##"
        print "## creating one at {0} ##".format(CERTSPOTTER_PATH)
        for d in domains:
            current_issuances = grab_issuances(apitoken,d,"")
            issuances[d] = current_issuances

        with open(CERTSPOTTER_PATH, 'w') as outfile:
            json.dump(issuances, outfile)



