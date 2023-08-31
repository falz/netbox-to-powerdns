# netbox-to-powerdns
Script to create PowerDNS DNS records from Netbox Device IPs.

Edit script to set variables at top for the PowerDNS and Netbox API endpoint. 

Tested with PowerDNS 4.7.x and Netbox 3.5.x

```./netbox-to-powerdns.py --help
usage: netbox-to-powerdns.py [-h] [-q] [-d] [-w]

optional arguments:
  -h, --help   show this help message and exit
  -q, --quiet  Quiet, show less output
  -d, --debug  Debugging, show more output
  -w, --write  Write mode - actually make dns changes. This is required for
               this script to actually do something.
```
