#!/usr/bin/python
import requests
import argparse
import json
import os
import re
import datetime
from shodan import Shodan, APIError
import time

# temp file
CERTSPOTTER_PATH = '.certspotter.json'


def unique(list1):
    # init a null list
    unique_list = []
    # traverse for all elements
    for x in list1:
        # check if exists in unique_list or not
        if x not in unique_list:
            unique_list.append(x)
    return unique_list


def update_issuances(apitoken, domain, stored_issuances):
    cert = stored_issuances[-1]
    last_id = cert['id']

    issuances = grab_issuances(apitoken, domain, last_id)

    return issuances


def grab_issuances(apitoken, domain, last_id):
    issuances = []
    url = "https://api.certspotter.com/v1/issuances"
    headers = {
        'Authorization': "Bearer " + apitoken,
        'cache-control': "no-cache"
    }
    payload = ""
    if last_id:
        querystring = {"after": last_id, "domain": domain, "expand": ["dns_names", "issuer"], "include_subdomains": "true"}
    else:
        querystring = {"domain": domain, "expand": ["dns_names", "issuer"], "include_subdomains": "true"}

    print ("grabbing issuance for {0} with query string {1}".format(domain, querystring))
    response = requests.request("GET", url, data=payload, headers=headers, params=querystring)

    # store for issuances
    issuances = json.loads(response.text)

    # grab subsequent pages
    while 'Link' in response.headers:
        print ("processing subsequent pages: ", response.headers['Link'])
        m = re.search('</v1/issuances\?after=(\d+)\&.+', response.headers['Link'])
        if m:
            after = m.group(1)
            querystring = {"after": after, "domain": domain, "expand": ["dns_names", "issuer"], "include_subdomains": "true"}
            response = requests.request("GET", url, data=payload, headers=headers, params=querystring)
            for i in json.loads(response.text):
                issuances.append(i)
    return issuances


def shodan_scan(shoda_api_token, domain):
    api = Shodan(shoda_api_token)

    try:
        scan = api.scan(domain)
    except APIError as e:
        print ("## domain {0} - shodan scanning error: {1}".format(domain, e.value))
        return []

    # Start listening for results
    done = False
    while not done:
        print ("## domain {0} - shodan scanning".format(domain))
        time.sleep(2)
        scan = api.scan_status(scan['id'])
        if scan['status'] == 'DONE':
            done = True

    # if done lets grab all results
    scan = api.scan_status(scan['id'])
    sites = []
    if "DONE" == scan['status']:
        print ("## domain {0} - shodan completed scanning".format(domain))
        for banner in api.search_cursor('scan:{}'.format("XR8Ioe2oN7jeWkPJ")):

            domain = banner['_shodan']['options']['hostname']
            if len(sites) != 0:
                site = dict()
                for s in sites:
                    if s['domain'] == domain:
                        # if we already processed the scanned domain lets just add to it
                        site['protocols'].append(banner['_shodan']['module'])
                        site['ports'].append(banner['port'])
                        if "http" == banner['_shodan']['module'] or "https" == banner['_shodan']['module']:
                            s['server'].append(banner['http']['server'])
                            if 'components' in banner['http']:
                                s['components'].append(banner['http']['components'])
                    else:
                        # otherwise lets process the scanned domain
                        print("## domain {0} - shodan processing site".format(domain))
                        site = dict()
                        site['domain'] = domain
                        site['server'] = []
                        site['components'] = []
                        site['protocols'] = []
                        site['ports'] = []
                        site['protocols'].append(banner['_shodan']['module'])
                        site['ports'].append(banner['port'])
                        site['hosting_org'] = banner['org']
                        if "http" == banner['_shodan']['module'] or "https" == banner['_shodan']['module']:
                            site['server'].append(banner['http']['server'])
                            if 'components' in banner['http']:
                                site['components'].append(banner['http']['components'])

                        sites.append(site)

            else:
                # this is our first time on this domain lets process it
                print("## domain {0} - shodan processing site".format(domain))
                site = dict()
                site['domain'] = domain
                site['server'] = []
                site['components'] = []
                site['protocols'] = []
                site['ports'] = []
                site['protocols'].append(banner['_shodan']['module'])
                site['ports'].append(banner['port'])
                site['hosting_org'] = banner['org']
                if "http" == banner['_shodan']['module'] or "https" == banner['_shodan']['module']:
                    site['server'].append(banner['http']['server'])
                    if 'components' in banner['http']:
                        site['components'].append(banner['http']['components'])
                sites.append(site)

    # unique results
    final_sites = []
    for s in sites:
        site = dict()
        servers = unique(s['server'])
        components = unique(s['components'])
        ports = unique(s['ports'])
        protocols = unique(s['protocols'])

        site['domain'] = s['domain']
        site['servers'] = servers
        site['components'] = components
        site['ports'] = ports
        site['protocols'] = protocols
        final_sites.append(site)

    return final_sites


def sendslack(slackhook, domain, issuances, shodan_results):

    if shodan_results:
        s = shodan_results[0]
        protocols = ', '.join(map(str, s['protocols']))
        ports = ', '.join(map(str, s['ports']))
        servers = ', '.join(map(str, s['servers']))

        components = []
        for c in s['components']:
            for key in c:
                components.append(key)
        components = ', '.join(map(str, components))

        slack_data = {"attachments": [{
                "fallback": ":lock: certificate changes have been detected for: {0}\
                \n```{1}```\n".format(str(domain), json.dumps(issuances, indent=4)),
                "color": "#7236a6",
                "author_name": "cybersnitch",
                "author_link": "https://github.com/d1vious/cert-change-watcher",
                "title": ":lock: certificate changes have been detected for {0}".format(str(domain)),
                "mrkdwn_in": ["text", "title", "pretext", "fields"],
                "fields": [
                    {
                        "title": "cert material",
                        "value": "```{0}```".format(json.dumps(issuances, indent=4)),
                        "short": False
                    },
                    {
                        "title": "shodan results",
                        "value": "* protocols detected: {0}\
                              \n* ports detected: {1}\
                              \n* server header: {2}\
                              \n* components: {3}".format(protocols, ports, servers, components),
                        "short": False
                    }
                ]
        }]}
    else:
        slack_data = {"attachments": [{
            "fallback": ":lock: certificate changes have been detected for: {0}\
                                    \n```{1}```\n".format(str(domain), json.dumps(issuances, indent=4)),
            "color": "#7236a6",
            "author_name": "cybersnitch",
            "author_link": "https://github.com/d1vious/cert-change-watcher",
            "title": ":lock: certificate changes have been detected for {0}".format(str(domain)),
            "mrkdwn_in": ["text", "title", "pretext", "fields"],
            "fields": [
                {
                    "title": "cert material",
                    "value": "```{0}```".format(json.dumps(issuances, indent=4)),
                    "short": False
                }
            ]
        }]}

    response = requests.post(
        slackhook, data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )

    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text))


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="monitors certificate changes using cert spotter api and alerts to slack", epilog="""
    In order to use this tool you will need an API key from certspotter, and also provide the slack API web hook.""")
    parser.add_argument("-k", "--apitoken", required=True, help="api token for cert spotter, example 1234_adfdafasfdas")
    parser.add_argument("-s", "--slackhook", required=False, default="", help="slack web hook to notify of changes")
    parser.add_argument("-sh", "--shodan", required=False, default="", help="shodan api key, to add shodan scan results to alert")
    parser.add_argument("-d", "--domains", required=True, default="", help="command delimited list of domains to \
    monitor changes for, example \"splunk.com,elastic.com\"")
    parser.add_argument("-o", "--output", required=False, default="results.json", help="outputs results in JSON to a \
    localfile, defaults to results.json")

    # parse them
    args = parser.parse_args()
    apitoken = args.apitoken
    slackhook = args.slackhook
    shodan = args.shodan
    output = args.output
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
                issuances[d] = grab_issuances(apitoken, d, "")
                continue

            # check for updates
            current_issuances = update_issuances(apitoken, d, stored_issuances[d])

            # if updates send alert, and otherwise just keep current state
            if len(current_issuances) > 0:
                update_state = True
                print("## domain {0} has changes: ##".format(d))
                print(json.dumps(current_issuances, indent=4))

                # write results to output file
                result = dict()
                result['timestamp'] = str(datetime.datetime.utcnow().isoformat())
                result['changes'] = current_issuances
                result['domain'] = d
                with open(output, 'w') as outfile:
                    json.dump(result, outfile)

                # run shodan scan if requested
                shodan_results = []
                if shodan:
                    for i in current_issuances:
                        for dns in i['dns_names']:
                            shodan_results = shodan_scan(shodan, dns)
                            for s in shodan_results:
                                print ("## domain {0} - protocols detected: {1}".format(dns, s['protocols']))
                                print ("## domain {0} - ports detected: {1}".format(dns, s['ports']))
                                print ("## domain {0} - server header: {1}".format(dns, s['servers']))
                                print ("## domain {0} - components: {1}".format(dns, s['components']))

                # send slack notification
                if slackhook:
                    sendslack(slackhook, d, current_issuances, shodan_results)

                # finally update issuances
                issuances[d] = current_issuances
            else:
                issuances[d] = stored_issuances[d]

        if update_state:
            print("updating state {0}".format(CERTSPOTTER_PATH))
            with open(CERTSPOTTER_PATH, 'w') as outfile:
                json.dump(issuances, outfile)
        else:
            print("## no changes ##")
    else:
        print ("seems this is our first run .. certspotter state file not present")
        print ("creating one at {0}".format(CERTSPOTTER_PATH))
        for d in domains:
            current_issuances = grab_issuances(apitoken, d, "")
            issuances[d] = current_issuances

        with open(CERTSPOTTER_PATH, 'w') as outfile:
            json.dump(issuances, outfile)
