# cert-change-watcher
Alerts when a issuer or domain changes in your certificates

# Installation
1. Get a API key from: https://sslmate.com/certspotter/
2. `git clone https://github.com/d1vious/cert-change-watcher.git`
3. `cd cert-change-watcher && virtualenv venv && source venv/bin/activate && pip install -r requirements.txt`

## Usage

```
cert-change-monitor.py [-h] -k APITOKEN [-s SLACKHOOK] -d DOMAINS

monitors certificate changes using cert spotter api and alerts to slack

optional arguments:
  -h, --help            show this help message and exit
  -k APITOKEN, --apitoken APITOKEN
                        api token for cert spotter, example 1234_adfdafasfdas
  -s SLACKHOOK, --slackhook SLACKHOOK
                        slack web hook to notify of changes
  -d DOMAINS, --domains DOMAINS
                        command delimited list of domains to monitor changes
                        for, example "splunk.com,elastic.com"

In order to use this tool you will need an API key from certspotter, and also
provide the slack API web hook.
```

## Examples

Check changes for a domain

```
── # python cert-change-watcher.py -k $CERTSPOTTER_TOKEN -d splunk.com
## seems this is our first run .. certspotter state file not present ##
## creating one at .certspotter.json ##
── # python cert-change-watcher.py -k $CERTSPOTTER_TOKEN -d splunk.com
## no changes ##
```
