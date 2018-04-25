#!/usr/bin/env python
# vim: set fileencoding=utf-8 :
#
# Copyright (C) 2018 Danny AFAHOUNKO <danny@redhat.com>
#
# This script is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with it.  If not, see <http://www.gnu.org/licenses/>.
#
# This is loosely based on the foreman inventory script
# -- Josh Preston <jpreston@redhat.com>
#

from __future__ import print_function
import argparse
import ConfigParser
import os
import sys
import re
from time import time
import requests
from requests.auth import HTTPBasicAuth
import warnings
from ansible.errors import AnsibleError

import subprocess
import shutil

try:
    import json
except ImportError:
    import simplejson as json

# Defaults values in case conf file does not exist
scm_defaults = dict(
    scm = dict ( url = '.',
                 name = 'file',
                 work_dir = '/tmp/work',
                 username = 'admin',
                 password = 'pass',
                 clean_group_keys = True,
                 nest_tags = False,
        ),
    cache = dict ( max_age = 600,

        )
    )

# end default settings

class ScmInventory(object):

    global scm_defaults


    def __init__(self):
        """
        Main execution path
        """
        self.inventory = dict()  # A list of groups and the hosts in that group
        self.hosts = dict()      # Details about hosts in the inventory

        # Parse CLI arguments
        self.parse_cli_args()

        # Read settings
        self.read_settings()

        # Cache
        if self.args.refresh_cache or not self.is_cache_valid():
            self.update_cache()
        else:
            self.load_inventory_from_cache()
            self.load_hosts_from_cache()

        data_to_print = ""

        # Data to print
        if self.args.host:
            if self.args.debug:
                print("Fetching host [%s]" % self.args.host)
            data_to_print += self.get_host_info(self.args.host)
        else:
            self.inventory['_meta'] = {'hostvars': {}}
            for hostname in self.hosts:
                self.inventory['_meta']['hostvars'][hostname] = {
                    'scm': self.hosts[hostname],
                }
                # include the ansible_ssh_host in the top level
                if 'ansible_ssh_host' in self.hosts[hostname]:
                    self.inventory['_meta']['hostvars'][hostname]['ansible_ssh_host'] = self.hosts[hostname]['ansible_ssh_host']

            data_to_print += self.json_format_dict(self.inventory, self.args.pretty)

        print(data_to_print)

    def is_cache_valid(self):
        """
        Determines if the cache files have expired, or if it is still valid
        """
        if self.args.debug:
            print("Determining if cache [%s] is still valid (< %s seconds old)" % (self.cache_path_hosts, self.cache_max_age))

        if os.path.isfile(self.cache_path_hosts):
            mod_time = os.path.getmtime(self.cache_path_hosts)
            current_time = time()
            if (mod_time + self.cache_max_age) > current_time:
                if os.path.isfile(self.cache_path_inventory):
                    if self.args.debug:
                        print("Cache is still valid!")
                    return True

        if self.args.debug:
            print("Cache is stale or does not exist.")

        return False

    def read_settings(self):
        """
        Reads the settings from the scm_inventory.ini file
        """
        config = ConfigParser.SafeConfigParser()
        config_paths = [
            os.path.dirname(os.path.realpath(__file__)) + '/inventory_scm.ini',
            "/etc/ansible/inventory_scm.ini",
        ]

        env_value = os.environ.get('scm_inventory.ini_PATH')
        if env_value is not None:
            config_paths.append(os.path.expanduser(os.path.expandvars(env_value)))

        if self.args.debug:
            for config_path in config_paths:
                print("Reading from configuration file [%s]" % config_path)

        config.read(config_paths)


        # scm API related
        if config.has_option('scm', 'url'):
            self.scm_url = config.get('scm', 'url')
        else:
            self.scm_url = scm_defaults['scm']['url']

        if self.args.debug:
            print("No url specified, using %s" % scm_defaults['scm']['url'])

        # scm work dir
        if config.has_option('scm', 'work_dir'):
            self.scm_work_dir = config.get('scm', 'work_dir')
        else:
            self.scm_work_dir = scm_defaults['scm']['work_dir']

        if self.args.debug:
            print("No work_dir specified, using %s" % scm_defaults['scm']['work_dir'])


        # scm name 
        if config.has_option('scm', 'name'):
            self.scm_name = config.get('scm', 'name')
        else:
            self.scm_name = scm_defaults['scm']['name']

        if self.args.debug:
            print("No name specified, using %s" % scm_defaults['scm']['name'])



        # if config.has_option('scm', 'username'):
        #     self.scm_username = config.get('scm', 'username')
        # else:
        #     self.scm_username = None

        # if not self.scm_username:
        #     warnings.warn("No username specified, you need to specify a scm username.")

        # if config.has_option('scm', 'password'):
        #     self.scm_pw = config.get('scm', 'password', raw=True)
        # else:
        #     self.scm_pw = None

        # if not self.scm_pw:
        #     warnings.warn("No password specified, you need to specify a password for the scm user.")

        # if config.has_option('scm', 'ssl_verify'):
        #     self.scm_ssl_verify = config.getboolean('scm', 'ssl_verify')
        # else:
        #     self.scm_ssl_verify = True

        # if config.has_option('scm', 'name'):
        #     self.scm_name = config.get('scm', 'name')
        # else:
        #     self.scm_version = None

        if config.has_option('scm', 'clean_group_keys'):
            self.scm_clean_group_keys = config.getboolean('scm', 'clean_group_keys')
        else:
            self.scm_clean_group_keys = scm_defaults['scm']['clean_group_keys'] #True

        if config.has_option('scm', 'nest_tags'):
            self.scm_nest_tags = config.getboolean('scm', 'nest_tags')
        else:
            self.scm_nest_tags =  scm_defaults['scm']['nest_tags'] #False

        if config.has_option('scm', 'suffix'):
            self.scm_suffix = config.get('scm', 'suffix')
            if self.scm_suffix[0] != '.':
                raise AnsibleError('Leading fullstop is required for scm suffix')
        else:
            self.scm_suffix = None


        # Ansible related
        try:
            group_patterns = config.get('ansible', 'group_patterns')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            group_patterns = "[]"

        self.group_patterns = eval(group_patterns)

        # Cache related
        try:
            cache_path = os.path.expanduser(config.get('cache', 'path'))
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            cache_path = '.'
        (script, ext) = os.path.splitext(os.path.basename(__file__))
        self.cache_path_hosts = cache_path + "/%s.hosts" % script
        self.cache_path_inventory = cache_path + "/%s.inventory" % script

        # self.cache_max_age = config.getint('cache', 'max_age')
        if config.has_option('cache', 'max_age'):
            self.cache_max_age = config.getint('cache', 'max_age')
        else:
            self.cache_max_age = scm_defaults['cache']['max_age']



        if self.args.debug:
            print("scm settings:")
            print("scm_url               = %s" % self.scm_url)
            print("scm_work_dir          = %s" % self.scm_work_dir)
            print("scm_clean_group_keys  = %s" % self.scm_clean_group_keys)
            print("scm_nest_tags         = %s" % self.scm_nest_tags)
            # print("scm_username          = %s" % self.scm_username)
            # print("scm_pw                = %s" % self.scm_pw)
            # print("scm_ssl_verify        = %s" % self.scm_ssl_verify)
            # print("scm_name              = %s" % self.scm_name)
            print("Cache settings:")
            print("cache_max_age        = %s" % self.cache_max_age)
            print("cache_path_hosts     = %s" % self.cache_path_hosts)
            print("cache_path_inventory = %s" % self.cache_path_inventory)

    def parse_cli_args(self):
        """
        Command line argument processing
        """
        parser = argparse.ArgumentParser(description='Produce an Ansible Inventory file based on scm managed VMs')
        parser.add_argument('--list', action='store_true', default=True, help='List instances (default: True)')
        parser.add_argument('--host', action='store', help='Get all the variables about a specific instance')
        parser.add_argument('--pretty', action='store_true', default=False, help='Pretty print JSON output (default: False)')
        parser.add_argument('--refresh-cache', action='store_true', default=False,
                            help='Force refresh of cache by making API requests to scm (default: False - use cache files)')
        parser.add_argument('--debug', action='store_true', default=False, help='Show debug output while running (default: False)')
        self.args = parser.parse_args()

    def _get_json(self, url):
        """
        Make a request and return the JSON
        """
        results = []

        ret = requests.get(url,
                           auth=HTTPBasicAuth(self.scm_username, self.scm_pw),
                           verify=self.scm_ssl_verify)

        ret.raise_for_status()

        try:
            results = json.loads(ret.text)
        except ValueError:
            warnings.warn("Unexpected response from {0} ({1}): {2}".format(self.scm_url, ret.status_code, ret.reason))
            results = {}

        if self.args.debug:
            print("=======================================================================")
            print("=======================================================================")
            print("=======================================================================")
            print(ret.text)
            print("=======================================================================")
            print("=======================================================================")
            print("=======================================================================")

        return results

    def _get_hosts(self):
        """
        Get all hosts by paging through the results
        """

        # print (subprocess.check_output(['ls','-l']) )

        # print(self.scm_url, '---', os.path.basename(self.scm_url))

        # sys.exit()

        # clean work repo


        # shutil.rmtree(self.scm_work_dir)

        # os.makedirs(self.scm_work_dir)

        # repo = self.scm_url

        # task = subprocess.check_output(['git', 'clone', repo, self.scm_work_dir ])




        results = [ 
            { 'name': 'hostA', 'path': 'EU/SITE1/ENV/PROD/inventory/hostsA', 'tags': [ { 'name': 'EU'} , { 'name': 'SITE1'} , { 'name': 'PROD'} ] } ,
            { 'name': 'hostB', 'path': 'EU/SITE1/ENV/DEV/inventory/hostsB', 'tags': [ { 'name': 'EU'} , { 'name': 'SITE1'} , { 'name': 'DEV'} ] } ,
            { 'name': 'hostC', 'path': 'EU/SITE1/LEGACY/DEV/inventory/hostsC', 'tags': [ { 'name': 'EU'} , { 'name': 'SITE1'} , { 'name': 'DEV'}, { 'name': 'LEGACY'} ] } ,
            ]

        # results = [ 
        #     { 'name': 'hostA', 'path': 'EU/SITE1/ENV/PRD/inventory/hostsA', 'tags': [ { 'name': 'EU/SITE1/ENV/PRD'} ] } ,
        #     { 'name': 'hostB', 'path': 'EU/SITE1/ENV/DEV/inventory/hostsB', 'tags': [ { 'name': 'EU/SITE1/ENV/DEV'} ] } ,
        #     { 'name': 'hostC', 'path': 'EU/SITE1/ENV/DEV/inventory/hostsC', 'tags': [ { 'name': 'EU/SITE1/LEGACY/DEV'} ] } , 
        #     ]

        _hosts = []
        _groups = dict()

        ext = [ ".yml", ".json" ]

        if self.scm_url in ['.'] and self.scm_name in ['file']:
            _workdir = '.'
        else:
            _workdir = self.scm_work_dir


        for root, dirs, files in os.walk( _workdir ):

            if '.git' in dirs:
                # don't go into any .git directories.
                dirs.remove('.git')

            path = root.split(os.sep)

            # print((len(path) - 1) * '---', os.path.basename(root))
            
            for file in files:

                # - host 

                if 'host_vars' in os.path.join(root, file):
                    # print(os.path.join(root, file))
                    _hostname = os.path.splitext(file)[0]
                    matchObj = re.search("^(all$|\\.).*", _hostname)
                    if not matchObj:
                        # print (_hostname)
                        _path = root.replace(self.scm_work_dir,'').replace('host_vars', '')
                        _hosts.append( dict(name=_hostname, tags=self.to_tag(_path), vars={}, hosts=[]) )


                # - group

                if 'group' in os.path.join(root, file):
                    # print(os.path.join(root, file))
                    if file not in _groups:
                        _groupname = os.path.splitext(file)[0]
                        _groups[_groupname] = dict(path=root, vars={}, hosts=[])
            
                # if file.endswith(tuple(ext)):
                #     print(len(path) * '---', file)
                #     print(os.path.join(root, file))



        # if 'all' in _hosts: del _hosts['all']
        # if 'all' in _groups: del _groups['all']

        # print(json.dumps(_hosts, sort_keys=True, indent=2))
        # print(json.dumps(_groups, sort_keys=True, indent=2))

        # sys.exit()


        # limit = self.scm_limit

        # page = 0
        # last_page = False

        # results = []

        # while not last_page:
        #     offset = page * limit
        #     ret = self._get_json("%s/api/vms?offset=%s&limit=%s&expand=resources,tags,hosts,&attributes=ipaddresses" % (self.scm_url, offset, limit))
        #     results += ret['resources']
        #     if ret['subcount'] < limit:
        #         last_page = True
        #     page += 1

        return _hosts

    def update_cache(self):
        """
        Make calls to scm and save the output in a cache
        """
        self.groups = dict()
        self.hosts = dict()

        if self.args.debug:
            print("Updating cache...")

        # # - debug output
        # print(json.dumps(self._get_hosts(), sort_keys=True, indent=2))
        # #input('press a key')
        # # sys.exit()
        # for host in self._get_hosts():
        #     print(json.dumps(host['name'], sort_keys=True, indent=2))
        # # sys.exit()



        # - end of debug output

        for host in self._get_hosts():
            if self.scm_suffix is not None and not host['name'].endswith(self.scm_suffix):
                host['name'] = host['name'] + self.scm_suffix

            # # Ignore VMs that are not powered on
            # if host['power_state'] != 'on':
            #     if self.args.debug:
            #         print("Skipping %s because power_state = %s" % (host['name'], host['power_state']))
            #     continue

            # # purge actions
            # if self.scm_purge_actions and 'actions' in host:
            #     del host['actions']

            # Create ansible groups for tags
            if 'tags' in host:

                # Create top-level group
                if 'tags' not in self.inventory:
                    self.inventory['tags'] = dict(children=[], vars={}, hosts=[])

                if not self.scm_nest_tags:
                    # don't expand tags, just use them in a safe way
                    for group in host['tags']:
                        # Add sub-group, as a child of top-level
                        safe_key = self.to_safe(group['name'])
                        if safe_key:
                            if self.args.debug:
                                print("Adding sub-group '%s' to parent 'tags'" % safe_key)

                            if safe_key not in self.inventory['tags']['children']:
                                self.push(self.inventory['tags'], 'children', safe_key)

                            self.push(self.inventory, safe_key, host['name'])

                            if self.args.debug:
                                print("Found tag [%s] for host which will be mapped to [%s]" % (group['name'], safe_key))
                else:
                    # expand the tags into nested groups / sub-groups
                    # Create nested groups for tags
                    safe_parent_tag_name = 'tags'
                    for tag in host['tags']:
                        tag_hierarchy = tag['name'][0:].split('/')

                        if self.args.debug:
                            print("Working on list %s" % tag_hierarchy)

                        for tag_name in tag_hierarchy:
                            if self.args.debug:
                                print("Working on tag_name = %s" % tag_name)

                            safe_tag_name = self.to_safe(tag_name)
                            if self.args.debug:
                                print("Using sanitized name %s" % safe_tag_name)

                            # Create sub-group
                            if safe_tag_name not in self.inventory:
                                self.inventory[safe_tag_name] = dict(children=[], vars={}, hosts=[])

                            # Add sub-group, as a child of top-level
                            if safe_parent_tag_name:
                                if self.args.debug:
                                    print("Adding sub-group '%s' to parent '%s'" % (safe_tag_name, safe_parent_tag_name))

                                if safe_tag_name not in self.inventory[safe_parent_tag_name]['children']:
                                    self.push(self.inventory[safe_parent_tag_name], 'children', safe_tag_name)

                            # Make sure the next one uses this one as it's parent
                            safe_parent_tag_name = safe_tag_name

                        # Add the host to the last tag
                        self.push(self.inventory[safe_parent_tag_name], 'hosts', host['name'])

            # Set ansible_ssh_host to the first available ip address
            if 'ipaddresses' in host and host['ipaddresses'] and isinstance(host['ipaddresses'], list):
                # If no preference for IPv4, just use the first entry
                if not self.scm_prefer_ipv4:
                    host['ansible_ssh_host'] = host['ipaddresses'][0]
                else:
                    # Before we search for an IPv4 address, set using the first entry in case we don't find any
                    host['ansible_ssh_host'] = host['ipaddresses'][0]
                    for currenthost in host['ipaddresses']:
                        if '.' in currenthost:
                            host['ansible_ssh_host'] = currenthost

            # # Create additional groups
            # for key in ('location', 'type', 'vendor'):
            #     safe_key = self.to_safe(host[key])

            #     # Create top-level group
            #     if key not in self.inventory:
            #         self.inventory[key] = dict(children=[], vars={}, hosts=[])

            #     # Create sub-group
            #     if safe_key not in self.inventory:
            #         self.inventory[safe_key] = dict(children=[], vars={}, hosts=[])

            #     # Add sub-group, as a child of top-level
            #     if safe_key not in self.inventory[key]['children']:
            #         self.push(self.inventory[key], 'children', safe_key)

            #     if key in host:
            #         # Add host to sub-group
            #         self.push(self.inventory[safe_key], 'hosts', host['name'])

            self.hosts[host['name']] = host
            self.push(self.inventory, 'all', host['name'])

        if self.args.debug:
            print("Saving cached data")

        self.write_to_cache(self.hosts, self.cache_path_hosts)
        self.write_to_cache(self.inventory, self.cache_path_inventory)

    def get_host_info(self, host):
        """
        Get variables about a specific host
        """
        if not self.hosts or len(self.hosts) == 0:
            # Need to load cache from cache
            self.load_hosts_from_cache()

        if host not in self.hosts:
            if self.args.debug:
                print("[%s] not found in cache." % host)

            # try updating the cache
            self.update_cache()

            if host not in self.hosts:
                if self.args.debug:
                    print("[%s] does not exist after cache update." % host)
                # host might not exist anymore
                return self.json_format_dict({}, self.args.pretty)

        return self.json_format_dict(self.hosts[host], self.args.pretty)

    def push(self, d, k, v):
        """
        Safely puts a new entry onto an array.
        """
        if k in d:
            d[k].append(v)
        else:
            d[k] = [v]

    def load_inventory_from_cache(self):
        """
        Reads the inventory from the cache file sets self.inventory
        """
        cache = open(self.cache_path_inventory, 'r')
        json_inventory = cache.read()
        self.inventory = json.loads(json_inventory)

    def load_hosts_from_cache(self):
        """
        Reads the cache from the cache file sets self.hosts
        """
        cache = open(self.cache_path_hosts, 'r')
        json_cache = cache.read()
        self.hosts = json.loads(json_cache)

    def write_to_cache(self, data, filename):
        """
        Writes data in JSON format to a file
        """
        json_data = self.json_format_dict(data, True)
        cache = open(filename, 'w')
        cache.write(json_data)
        cache.close()

    def to_safe(self, word):
        """
        Converts 'bad' characters in a string to underscores so they can be used as Ansible groups
        """
        if self.scm_clean_group_keys:
            regex = r"[^A-Za-z0-9\_]"
            return re.sub(regex, "_", word.replace(" ", ""))
        else:
            return word

    def to_tag(self, path):
        """
        Converts 'path' string into in a dict so they can be used as Ansible groups
        """
        _tags = []
        tagnames = path[1:].split('/')
        for tag in tagnames:
            if len(tag) > 0 :
                _tags.append( dict(name=tag, ) )

        return _tags


    def json_format_dict(self, data, pretty=False):
        """
        Converts a dict to a JSON object and dumps it as a formatted string
        """
        if pretty:
            return json.dumps(data, sort_keys=True, indent=2)
        else:
            return json.dumps(data)

ScmInventory()