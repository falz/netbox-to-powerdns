# netbox-to-powerdns
Script to create PowerDNS DNS records from Netbox Device IPs. Tested with PowerDNS 4.7.x and Netbox 3.5.x

Will add A, AAAA, PTR. Requires specifying zone sizes in config for PTR. defaults to /24 for IPv4, /48 for IPv6. Zones must exist in advance.

Will use Netbox API to find devices of certain devies and create or delete DNS records in powerdns based on:

* Device Role
* Device Manufacturer
* Device Status
  * Active == Add DNS
  * Failed / Offline / Decommissioning == Remove DNS


# Config
Edit script to set variables at top for the PowerDNS and Netbox API endpoint, as well as to match your device roles and manufacturers.


# Usage

```./netbox-to-powerdns.py --help
usage: netbox-to-powerdns.py [-h] [-q] [-d] [-w]

optional arguments:
  -h, --help   show this help message and exit
  -q, --quiet  Quiet, show less output
  -d, --debug  Debugging, show more output
  -w, --write  Write mode - actually make dns changes. This is required for
               this script to actually do something.
```
