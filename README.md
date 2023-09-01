# netbox-to-powerdns
Script to create PowerDNS DNS records from Netbox Device IPs. Tested with PowerDNS 4.7.x and Netbox 3.5.x

Will add A, AAAA, PTR. Requires specifying zone sizes in config for PTR. defaults to /24 for IPv4, /48 for IPv6. Zones must exist in advance.

Will use Netbox API to find devices of certain devies and create or delete DNS records in powerdns based on:

* Device Role
* Device Manufacturer
* Device Status
  * Active == Add DNS
  * Failed / Offline / Decommissioning == Remove DNS



If there's a Netbox Cisco device named "r-ciscocpe" with an IP on interface TenGigabitEthernet0/0/3 it will create:
* r-ciscodev-te0-0-3.ip4.example.com, A/AAAA as well as PTR.

A juniper device with interface et-0/0/1 would be:
* r-junpiperdev-et-0-0-1.ip4.example.com

.. and so on. Loopbacks are special, it will NOT create forward records for these, but will create PTR. This is for 'safety' in our environment (humans create that record as "r-juniperdev.example.com")

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

Exmaple output updating one device. This shows it adding a few records and correcting one:
```
Gathering Netbox Data..
Mapping Netbox data..
Getting Netbox Devices..
Getting Netbox IPs..
Checking for PowerDNS updates..
        Adding Record: r-ciscodev.ip4.example.com.       Content: 192.168.69.9
        Adding Record: r-ciscodev-te0-0-3.ip4.example.com.      Content: 192.168.69.62
        Adding Record: r-ciscodev-te0-0-4.ip4.example.com.      Content: 192.168.11.161
        Adding Record: 62.69.168.192.in-addr.arpa.      Content: r-ciscodev-te0-0-3.ip4.example.com.
        Updating Record: 161.11.168.192.in-addr.arpa.    Content: r-ciscodev-te0-0-4.ip4.example.com.    Was: r-ciscodev-gig0-1.example.com.
Complete! Added: 4 Updated:  1 Deleted: 0 Skipped: 2434 Total: 2439
```
