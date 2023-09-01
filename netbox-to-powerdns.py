#! /usr/bin/env python3
# 
# description:
#	fetch IP addresses from netbox devices of a specific status and role, create forward and reverse DNS entries
#	wopat wiscnet 2020-10
# 
# dependencies:
#	yum install python3-pip
#	python3 -m pip install argparse napalm pynetbox python-powerdns requests
#
# usage:
#	./netbox-to-powerdns.py -w - actually make changes (without args is a dry run)
#
# todo:
#	doesn't add dns for secondary IP's for netbox devices. determine if we care or not
#	add more things to 'interface_fixes_regex', currently only contains what's common
#	if we update (change) a dns record, report its old value
# 
# changelog:
#	2021-10-04	initial
#	2021-11-08	added ability to delete
#	2021-11-09	don't do hostname PTRs, only interfaces
#	2022-04-29	change interface name from display to name. display can sometimes have "(label)" in it if assigned
#	2022-05-09	bd -> bdi to match observiums port_label_short (and perhaps matches ciscos internal short name? idk)
#	2022-05-09	obey ttl in config - was using python-powerdns's default of 3600

import argparse
import datetime
from napalm.base import get_network_driver
from ipaddress import ip_address, ip_network
import pynetbox
import re
import requests
import sys
import powerdns		# https://github.com/outini/python-powerdns

##############################
# # config
config = {}
config['powerdns_api_url']		= "http://127.0.0.1:8081/api/v1"
config['powerdns_api_token']		= "<addme>"
config['netbox_url']			= "https://netbox.example.com/"
config['netbox_api_token']		= "<addme>"
config['netbox_device_status_add']	= [ "active" ]						# add IPs if device status
config['netbox_device_status_del']	= [ "failed", "offline", "decommissioning" ]		# delete IPs if device status
config['netbox_device_role']		= [ "cpe" ]						# only update records for these roles
config['domain_filter']			= ""							# optional arg if you ONLY want to make changes to one zone, usually for testing purposes. set to "" to do all zones
config['netbox_manufacturers']		= [ "Cisco", "Juniper" ]
config['request_timeout']		=  10
config['ttl']				= 14400
config['zone_parent']			= "example.com"
config['zone_v4_size']			= 24						# this will be the size of the in-addr.arpa zones
config['zone_v6_size']			= 48						# this will be the size of the ip6.arpa zones
config['zone_sub_v4']			= "ip4"						# IPv4 records go in ip4.example.com
config['zone_sub_v6']			= "ip6"						# IPv6 records go in ip6.example.com
config['interface_fixes_regex']		= {	'^lo0.\d$'		: '',
						'^Loopback.*'		: '',
						'^Loopback0'		: '',
						'^TenGigabitEthernet'	: 'te',
						'^GigabitEthernet'	: 'gi',
						'^FastEthernet'		: 'fa',
						'^BDI'			: 'bdi',
						'^Vlan'			: 'vl',
						'^Port-channel'		: 'po',
					}

config['character_fixes_regex']		= {	'\.':'-',		#	. to -
						'\/':'-', 		# 	/ to -
					}


##############################
## functions

def parse_cli_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-q', '--quiet',	action='store_true', help='Quiet, show less output')
	parser.add_argument('-d', '--debug',	action='store_true', help='Debugging, show more output')
	parser.add_argument('-w', '--write',	action='store_true', help='Write mode - actually make dns changes. This is required for this script to actually do something.')
	args = vars(parser.parse_args())
	return(args)


def get_netbox_devices(config):
	print("Getting Netbox Devices..")
	# add error checking
	nb = pynetbox.api(config['netbox_url'], config['netbox_api_token'])

	# get types we want to add and delete IPs from
	statuses = config['netbox_device_status_add'] + config['netbox_device_status_del']

	nb_devices = nb.dcim.devices.filter(status=statuses, role=config['netbox_device_role'])
	#for nb_device in nb_devices:
	#	print("nb_device:", nb_device)

	if args['debug'] == True:
		print("Netbox Devicess:", nb_devices)

	return(nb_devices)


def get_netbox_ips(config):
	print("Getting Netbox IPs..")
	# add error checking
	nb = pynetbox.api(config['netbox_url'], config['netbox_api_token'])
	# should be equal to: https://netbox.example.com/api/ipam/ip-addresses/?assigned_to_interface=true&status=active 
	nb_ips = nb.ipam.ip_addresses.filter(assigned_to_interface='true', status='active')
	if args['debug'] == True:
		print("Netbox IPs:", nb_ips)

	return(nb_ips)


def clean_interface_name(config, interface_full):
	for find, replace in config['interface_fixes_regex'].items():
		if re.match(find, interface_full):
			interface_short = re.sub(find, replace, interface_full)
			break
		else:
			interface_short = interface_full

	for find, replace in config['character_fixes_regex'].items():
		interface_done = re.sub(find, replace, interface_short)

	return(interface_done.lower())


def get_netbox_device_data(device_name, netbox_devices):

	netbox_manufacturers_list = [ x.lower() for x in config['netbox_manufacturers'] ]

	# find our device data
	#print(device_name)

	for netbox_device in netbox_devices:

		netbox_device_str = str(netbox_device)
		device_name_str = str(device_name)
		#print(netbox_device_str)


		# SOMETHING HERE DOESNT WORK EXCEPT ON ICEBOX WTF WOPAT
		#print(type(netbox_device), netbox_device, netbox_device_str)
		#print("device_name:", device_name, "netbox_device:", netbox_device, type(device_name), device_name)
		#test = "r-webstersd"
		#if test == netbox_device_str:
		#	print(test)

		if netbox_device_str == device_name_str:
			device_manufacturer	= str(netbox_device.device_type.manufacturer.name).lower()
			#print(device_manufacturer)
			if device_manufacturer in netbox_manufacturers_list:
				return(netbox_device)

	return(False)


def build_netbox_ip_dictionary(config):
	print("Mapping Netbox data..")
	netbox_devices = get_netbox_devices(config)
	netbox_ips = get_netbox_ips(config)

	ip_dict = {}
	for ip in netbox_ips:

		if ip.assigned_object_type == "dcim.interface" and ip.status.value == "active":
			device_name = ip.assigned_object.device.name
			device      =  get_netbox_device_data(device_name, netbox_devices)

			if device:
				#clean up device name a bit, after the above match. should do a better job at valid dns chars: 
				# https://stackoverflow.com/questions/2063213/regular-expression-for-validating-dns-label-host-name
				device_name = device_name.replace(" ", "")
				device_name = device_name.lower()

				interface = ip.assigned_object.name
				interface = interface.replace(" ", "")
				interface_short = clean_interface_name(config, interface)

				ip_str = str(ip.address)
				ip_split = ip_str.split('/')
				ip_only = ip_split[0]

				ip_dict[ip_only]			=	{}
				ip_dict[ip_only]['family']		=	ip.family.value
				ip_dict[ip_only]['interface_short']	=	interface_short
				ip_dict[ip_only]['interface_full']	=	interface
				ip_dict[ip_only]['device_id']		=	ip.assigned_object.device.id
				ip_dict[ip_only]['device_name']		=	device_name
				ip_dict[ip_only]['device_role']		=	str(device.device_role).lower()
				ip_dict[ip_only]['device_status']	=	str(device.status).lower()
				ip_dict[ip_only]['dns_name']		=	ip.dns_name
			#else:
			#	print("Couldnt correlate:", device_name)


	if args['debug'] == True:
		print("IP Dictionary", ip_dict)

	return(ip_dict)


def build_netbox_zone_dictionary(config):
	print("Gathering Netbox Data..")
	ip_dict = build_netbox_ip_dictionary(config)

	netbox_zone_dict = {}

	for ip, vals in ip_dict.items():
		if vals['family'] == 4:
			forward_zone = config['zone_sub_v4'] + "." + config['zone_parent']
			fwd_rec_type = "A"
			network = ip + "/" + str(config['zone_v4_size'])
			ipnetwork = ip_network(network, False)
			network_address = ipnetwork.network_address
			# THIS ONLY WORKS WITH /24! fixme
			trimlength = 2

		elif vals['family'] == 6:
			forward_zone = config['zone_sub_v6'] + "." + config['zone_parent']
			fwd_rec_type = "AAAA"
			network = ip + "/" + str(config['zone_v6_size'])
			ipnetwork = ip_network(network, False)
			network_address = ipnetwork.network_address
			trimlength = int(2 * (128 - ipnetwork.prefixlen) / 4)

		if vals['dns_name']:
			# maybe do more validation here, like check if dns_name contains our domain name (depending how we're using netbox)
			rec_name = vals['dns_name']
		else:
			# only append "-iface" if it exists (not if we removed it, like a loopback)
			if vals['interface_short']:
				rec_name = vals['device_name'] + "-"  + vals['interface_short']
				interfacerecord = True
			else: 
				rec_name = vals['device_name']
				interfacerecord = False

		rec_name_reverse = rec_name + "." + forward_zone + "."

		# set ip to enabled or disabled based on device status
		device_status = str(vals['device_status']).lower()
		if device_status in config['netbox_device_status_add']:
			disabled = False
		elif device_status in config['netbox_device_status_del']:
			disabled = True
		else:
			# temp
			print("\tUNKNOWN device_status! THIS SHOULD NEVER HAPPEN!")
			sys.exit(1)

		# FORWARD ZONES
		if forward_zone not in netbox_zone_dict:
			netbox_zone_dict[forward_zone]			= {}
			netbox_zone_dict[forward_zone]['type']		= "forward"
			netbox_zone_dict[forward_zone]['records']	= {}

		netbox_zone_dict[forward_zone]['records'][rec_name]			= {}
		netbox_zone_dict[forward_zone]['records'][rec_name]['disabled']		= disabled
		netbox_zone_dict[forward_zone]['records'][rec_name]['type']		= fwd_rec_type
		netbox_zone_dict[forward_zone]['records'][rec_name]['content']		= ip

		# REVERSE ZONES
		# only do PTRs on interface records (not hostnames, which should be manually done)
		if interfacerecord == True:
			ipaddress = ip_address(ip)
			reverse_zone = ipnetwork.network_address.reverse_pointer[trimlength:]

			if reverse_zone not in netbox_zone_dict:
				netbox_zone_dict[reverse_zone]			= {}
				netbox_zone_dict[reverse_zone]['type']		= "reverse"
				netbox_zone_dict[reverse_zone]['records']	= {}

			content = ipaddress.reverse_pointer + "."

			# ptr records have rec_name and content reversed from forward
			netbox_zone_dict[reverse_zone]['records'][content]			= {}
			netbox_zone_dict[reverse_zone]['records'][content]['disabled']		= disabled
			netbox_zone_dict[reverse_zone]['records'][content]['type']		= "PTR"
			netbox_zone_dict[reverse_zone]['records'][content]['content']		= rec_name_reverse

		# placeholder if we want to do something with host ptr records later
		#elif interfacerecord == False:
			# something

	return(netbox_zone_dict)

# check if zone exists in pdns
def check_pdns_zone_exists(pdns_zones, zone):
	zone = zone + "."
	for pdns_zone in pdns_zones:
		if pdns_zone.name == zone:
			return(True)

	return(False)			

# check if record exists in pdns
def check_pdns_record_exists(pdns_zones, zone, rec_name):
	zone = zone + "."
	for pdns_zone in pdns_zones:
		if pdns_zone.name == zone:
			for record in pdns_zone.records:
				if record['name'] == rec_name:
					# this is a list
					return(record['records'])
	return(False)			

def update_pdns_record(pdns_zone, name, vals, comments, update_type):
	if update_type == "create_records":
		results = pdns_zone.create_records([
			powerdns.RRSet(	name,
				vals['type'], 
				[( vals['content'], vals['disabled'] )],
				comments=comments,
				ttl=config['ttl'],
				)
			])
		return(results)

	elif update_type == "delete_records":
		results = pdns_zone.delete_records([
			powerdns.RRSet(	name,
				vals['type'], 
				[( vals['content'], vals['disabled'] )],
				comments=comments
				)
			])
		return(results)


	return(False)

# placeholder in case someone needs this functionality once zone updated. unsure if this is right, see
# https://github.com/outini/python-powerdns/blob/master/powerdns/interface.py#L444
# def send_notify(pdns_zone):
#	results = pdns_zone.notify()
#	return(True)

def update_pdns(config, netbox_zone_dict, args):
	#print("Checking for PowerDNS updates at", config['powerdns_api_url'], "..")
	print("Checking for PowerDNS updates..")

	# generate a human friendly timestamp
	now	= datetime.datetime.now()
	year	= str(now.year)
	month	= str(f"{now:%m}")
	day	= str(f"{now:%d}")
	hour	= str(f"{now:%H}")
	min	= str(f"{now:%M}")
	timestamp = year + "-" + month + "-" + day + " " + hour + ":" + min

	# https://github.com/outini/python-powerdns
	api_client = powerdns.PDNSApiClient(api_endpoint=config['powerdns_api_url'], api_key=config['powerdns_api_token'])
	api = powerdns.PDNSEndpoint(api_client)

	# get list of zones that exist on server
	pdns_zones = api.servers[0].zones

	add_count = 0
	update_count = 0
	delete_count = 0
	skip_count = 0

	for zone, records in netbox_zone_dict.items():
		# tbd if we want to keep this domain_filter thing?
		if config['domain_filter'] in zone and check_pdns_zone_exists(pdns_zones, zone) == True:
			pdns_zone = api.servers[0].get_zone(zone + ".")

			num_records = len(records['records'])
			if args['quiet'] == False:
				print("Checking", num_records, "records in zone:", zone)

			comments = [powerdns.Comment("netbox-to-powerdns.py " + timestamp, "admin")]

			if records['type'] == "reverse":
				reverse_zone = True
			else:
				reverse_zone = False

			for name, vals in records['records'].items():

				rec_content	= vals['content']
				rec_disabled	= vals['disabled']

				# foward and reverse zones are checked differently
				if reverse_zone:
					rec_name = name
				else: 
					rec_name = name + "." + zone + "."


				data	= "Record: " + rec_name +  "\tContent: " + rec_content

				if args['write'] == False:
					print("\tWrite Not enabled (-w), NOT Updating:", data)
					skip_count = skip_count +1

				else:
					pdns_content = check_pdns_record_exists(pdns_zones, zone, rec_name)

					# create / update / delete records as needed

					# doesn't exist and nb device is active, let's add it
					if pdns_content == False and rec_disabled == False:
						print("\tAdding", data)
						update_results = update_pdns_record(pdns_zone, name, vals, comments, "create_records")
						add_count = add_count +1

					elif pdns_content:

						# check content, update or delete if necessary. both are a list of dictionaries like:
						# we're lazy and checking only the first item in list. This should be right with how we use it.
						# [{'content': '216.56.249.89', 'disabled': False}]
						p_content	= pdns_content[0]['content']
						p_disabled	= pdns_content[0]['disabled']


						# exists in pdns already, not disabled in pdns nor disabled in netbox
						if rec_content == p_content and p_disabled == False and rec_disabled == False:
							skip_count = skip_count +1
							if args['debug'] == True:
								print("\tSkipping", data)

						#exists in pdns but disabled (via netbox device status), delete it
						elif rec_content == p_content and rec_disabled == True:
							print("\tDeleting", data)
							update_results = update_pdns_record(pdns_zone, name, vals, comments, "delete_records")
							delete_count = delete_count +1

						# catchall, exists in pdns but must need updating
						else:
							update_data = "\tWas: " + p_content
							print("\tUpdating", data, update_data)
							update_results = update_pdns_record(pdns_zone, name, vals, comments, "create_records")
							update_count = update_count + 1


	counts = [ add_count, update_count, delete_count, skip_count ]
	return(counts)


##############################
## main

if __name__ == "__main__":

	args = parse_cli_args()

	netbox_zone_dict = build_netbox_zone_dictionary(config)

	if args['debug'] == True:
		#print(netbox_zone_dict)
		pp = pprint.PrettyPrinter(indent=4)
		pp.pprint(netbox_zone_dict)

	counts		= update_pdns(config, netbox_zone_dict, args)

	add_count	= counts[0]
	update_count	= counts[1]
	delete_count	= counts[2]
	skip_count	= counts[3]
	total_count	= add_count + update_count + delete_count + skip_count

	print("Complete! Added:", add_count, "Updated: ", update_count, "Deleted:", delete_count, "Skipped:", skip_count, "Total:", total_count)

