#!/usr/bin/python
import requests
import argparse
import json
import os

# temp file
CERTSPOTTER_PATH = '.certspotter.json'

def grab_issuances(apitoken,domain):
    url = "https://api.certspotter.com/v1/issuances"
    headers = {
        'Authorization': "Bearer " + apitoken,
        'cache-control': "no-cache"
    }
    payload = ""
    querystring = {"domain":domain,"expand":["dns_names","issuer"],"include_subdomains":"true"}
    response = requests.request("GET", url, data=payload, headers=headers, params=querystring)
    return response.text

def is_changed(current_issuances,stored_issuances):
    parsed_current = []
    for cert in current_issuances:
        certificate = dict()
        domains = ','.join(cert['dns_names'])
        certificate['domains'] = domains
        certificate['issuer'] = cert['issuer']['name']
        certificate['pubkey_sha256'] = cert['pubkey_sha256']
        certificate['not_before'] = cert['not_before']
        certificate['not_after'] = cert['not_after']
        parsed_current.append(certificate)
    
    parsed_stored = []
    for cert in stored_issuances:
        certificate = dict()
        domains = ','.join(cert['dns_names'])
        certificate['domains'] = domains
        certificate['issuer'] = cert['issuer']['name']
        certificate['pubkey_sha256'] = cert['pubkey_sha256']
        certificate['not_before'] = cert['not_before']
        certificate['not_after'] = cert['not_after']
        parsed_stored.append(certificate)

    delta = list({dict2['domains'] for dict2 in parsed_stored} - 
             {dict1['domains'] for dict1 in parsed_current})
    delta_dict_domains = [{'domains': value} for value in delta]
    
    delta = list({dict2['issuer'] for dict2 in parsed_stored} - 
             {dict1['issuer'] for dict1 in parsed_current})
    delta_dict_issuer = [{'issuer': value} for value in delta]

    change = dict()
    changes = []
    
    if delta_dict_issuer:
        change = dict()
        for cert in parsed_current:
            for i in delta_dict_issuer:
                if cert['issuer'] == i['issuer']:
                    change['message'] = "issuer has changed"
                    change['certificate'] = cert 
                    changes.append(change)
        for cert in parsed_stored:
            for i in delta_dict_issuer:
                if cert['issuer'] == i['issuer']:
                    change['message'] = "issuer has changed"
                    change['certificate'] = cert 
                    changes.append(change)
    if delta_dict_domains:
        change = dict()
        for cert in parsed_current:
            for d in delta_dict_domains:
                if cert['domains'] == d['domains']:
                    change['message'] = "domains have changed"
                    change['certificate'] = cert 
                    changes.append(change)
        for cert in parsed_stored:
            for d in delta_dict_domains:
                if cert['domains'] == d['domains']:
                    change['message'] = "domains have changed"
                    change['certificate'] = cert 
                    changes.append(change)

    if len(changes) > 0:
        return True, changes
    else:
        return False, changes


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
        for d in domains:
            issuance = grab_issuances(apitoken,d)
            current_issuances = json.loads(issuance)
            issuances[d] = current_issuances

        with open(CERTSPOTTER_PATH) as f:
            stored_issuances = json.load(f)

        for d in domains:
            ischanged, changes = is_changed(issuances[d], stored_issuances[d])
            if ischanged:
                update_state = True
                print("## domain {0} has changes: ##".format(d))
                for i in changes:
                    print(json.dumps(i, indent=4))
        
        if update_state:
            print("## updating state {0} ##".format(CERTSPOTTER_PATH))
            with open(CERTSPOTTER_PATH, 'w') as outfile:
                json.dump(current_issuances, outfile)
        else:
            print("## no changes ##")
    else:
        print "## seems this is our first run .. certspotter state file not present ##"
        print "## creating one at {0} ##".format(CERTSPOTTER_PATH)
        for d in domains:
            issuance = grab_issuances(apitoken,d)
            current_issuances = json.loads(issuance)
            issuances[d] = current_issuances

        with open(CERTSPOTTER_PATH, 'w') as outfile:
            json.dump(issuances, outfile)



