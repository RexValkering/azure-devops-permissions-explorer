from datetime import datetime
import json
import logging
import logging.config
import logging.handlers
import os
import requests
import re
import hashlib
import time
import json
import operator
import yaml
from flask import Flask, request, abort, render_template

DIRECTORY = os.path.dirname(os.path.realpath(__file__))
HOUR = 60*60
DAY = 24*HOUR

NAMESPACES_URL = 'https://dev.azure.com/{organization}/_apis/securitynamespaces?api-version=5.0'
GROUPS_URL = 'https://vssps.dev.azure.com/{organization}/_apis/graph/groups?api-version=5.0-preview.1'
GROUP_URL = 'https://vssps.dev.azure.com/{organization}/_apis/Graph/Groups/{descriptor}?api-version=5.0-preview.1'
USERS_URL = 'https://vssps.dev.azure.com/{organization}/_apis/graph/users?api-version=5.0-preview.1'
MEMBERSHIP_URL = 'https://vssps.dev.azure.com/{organization}/_apis/Graph/Memberships/{descriptor}?direction={direction}'
PERMISSION_URL = 'https://dev.azure.com/{organization}/_apis/permissions/{permission_id}?api-version=5.0'
PERMISSIONS_URL = 'https://dev.azure.com/{organization}/_apis/security/permissionevaluationbatch?api-version=5.0'

app = None
api = None
browser = None


class DevopsEntity():

    entity_type = None
    members = None
    memberships = None
    descriptor = None

    def get_members(self):
        if self.members is None:
            self._load_connections()
        return self.members

    def get_groups(self):
        if self.memberships is None:
            self._load_connections()
        return self.memberships

    def _load_connections(self):
        if self.descriptor is None:
            raise Exception("Cannot get connections for entity without descriptor.")

        connections = browser.get_entity_connections(self.descriptor)
        self.members = connections['members']
        self.memberships = connections['memberships']

    def __lt__(self, other):
        return self.name < other.name

def hash(args):
    return hashlib.md5(args).hexdigest()


def unpack(data):
    return data['value'] if isinstance(data, dict) and 'count' in data else data


def debug(data):

    def debug_dumper(obj):
        try:
            return obj.toJSON()
        except:
            return obj.__dict__

    return '<pre>{}</pre>'.format(json.dumps(unpack(data), default=debug_dumper, indent=4,
                                             sort_keys=True))


"""Cache API calls using local file storage.

Class functions decorated with the @cache decorator will have their results cached in files in
the cache directory. This function only works for class methods where the arguments are json-
serializable.

Args:
    timeout: maximum cache time in seconds, defaults to a day
"""
def cache(timeout=86400):

    def decorator_cache(func):

        def wrapper_cache(self, *args, **kwargs):

            # Create cache hash from function name, args and kwargs
            cache_hash = hash(json.dumps((func.__name__, args, kwargs)).encode('utf-8'))
            path = '{}/cache/{}.txt'.format(DIRECTORY, cache_hash)

            # Check if cache exists, and if so, if it is recent.
            if os.path.exists(path):
                if os.path.getmtime(path) > time.time() - timeout:
                    with open(path) as infile:
                        return json.loads(infile.read())
                else:
                    os.remove(path)

            # Retrieve result and write to cache
            result = func(self, *args, **kwargs)
            with open(path, 'w') as outfile:
                outfile.write(json.dumps(result))

            return result
        return wrapper_cache
    return decorator_cache


def to_tuples(data):
    return [(item, None, None) for item in data]


def to_json(data):
    return json.dumps(data, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class DevopsBrowser():
    """Communicate with the DevopsCachedApi in a Python-friendly way.

    Args:
        api: the DevopsCachedApi instance to communicate with
    """
    api = None
    namespaces = None
    groups = None
    users = None
    lookup_table = None
    lookup_loaded = 0

    def __init__(self, api):
        self.api = api
        self.lookup_table = {}

    def lookup(self, descriptor):
        """Retrieve an entity by its descriptor

        Args:
            descriptor: entity descriptor
        """
        if self.lookup_loaded < 2:
            self.get_groups()
            self.get_users()
        return self.lookup_table.get(descriptor)

    def get_namespaces(self):
        """Retrieve namespaces from the API"""
        if self.namespaces is None:
            namespaces = unpack(self.api.get_namespaces())
            self.namespaces = {
                namespace['name']: DevopsSecurityNamespace(namespace)
                for namespace in namespaces
            }
        return self.namespaces

    def get_namespace(self, name):
        namespaces = self.get_namespaces()
        if name not in namespaces:
            abort(404)
        return namespaces[name]

    def get_sorted_namespaces(self):
        namespaces = self.get_namespaces()
        return sorted([namespaces[key] for key in namespaces.keys()], key=operator.attrgetter('name'))

    def get_groups(self):
        if self.groups is None:
            groups = unpack(self.api.get_groups())
            self.groups = {
                group['descriptor']: DevopsGroup(group)
                for group in groups
            }

            # Merge in lookup table
            self.lookup_table = {**self.lookup_table, **self.groups}
            self.lookup_loaded += 1
        return self.groups

    def get_group(self, descriptor):
        groups = self.get_groups()
        if descriptor not in groups:
            abort(404)
        return groups[descriptor]

    def get_sorted_groups(self):
        groups = self.get_groups()
        return sorted([groups[key] for key in groups.keys()], key=operator.attrgetter('name'))

    def get_users(self):
        if self.users is None:
            users = unpack(self.api.get_users())
            self.users = {
                user['descriptor']: DevopsUser(user)
                for user in users
            }

            # Merge in lookup table
            self.lookup_table = {**self.lookup_table, **self.users}
            self.lookup_loaded += 1

        return self.users

    def get_user(self, descriptor):
        users = self.get_users()
        if descriptor not in users:
            abort(404)
        return users[descriptor]

    def get_sorted_users(self):
        users = self.get_users()
        return sorted([users[key] for key in users.keys() if users[key].domain == 'Windows Live ID'], key=operator.attrgetter('name'))

    def get_entity_connections(self, descriptor):
        memberships = unpack(self.api.get_entity_memberships(descriptor))
        members = unpack(self.api.get_entity_members(descriptor))

        # return memberships

        parsed_memberships = sorted([x for x in [self.lookup(membership['containerDescriptor'])
                                                 for membership in memberships] if x is not None])
        # parsed_memberships = [membership['containerDescriptor'] for membership in memberships]
        parsed_members = sorted([x for x in [self.lookup(members['memberDescriptor'])
                                             for members in members] if x is not None])
        # parsed_members = [member['memberDescriptor'] for member in members]

        return {
            'members': parsed_members,
            'memberships': parsed_memberships
        }

    def get_related_entities(self, descriptor):

        connections = self.get_entity_connections(descriptor)
        users = []
        groups = []

        def parse_connection(entity, relation, direct=True):
            tup = (entity, relation, 'direct' if direct else 'indirect')
            if entity.entity_type == 'user':
                users.append(tup)
            elif entity.entity_type == 'group':
                groups.append(tup)

            entity_connections = self.get_entity_connections(entity.descriptor)
            for connection_item in entity_connections[relation]:
                parse_connection(connection_item, relation, False)

        for relation in ['members', 'memberships']:
            for item in connections[relation]:
                parse_connection(item, relation, True)

        return users, groups


class DevopsSecurityNamespace(DevopsEntity):

    entity_type = "namespace"

    def __init__(self, data):
        self.namespace_id = data['namespaceId']
        self.name = data['name']
        self.actions = data['actions']


class DevopsGroup(DevopsEntity):

    entity_type = "group"

    def __init__(self, data):
        self.descriptor = data['descriptor']
        self.name = data['principalName']
        self.display_name = data['displayName']
        self.description = data['description']


class DevopsUser(DevopsEntity):

    entity_type = "user"

    def __init__(self, data):
        self.descriptor = data['descriptor']
        self.name = data['principalName']
        self.display_name = data['displayName']
        self.domain = data['domain']


class DevopsCachedApi():

    def __init__(self, token, organization):
        self.token = token
        self.organization = organization

    @cache(timeout=HOUR)
    def _get_request(self, url, args=None):
        if args is None:
            args = {}

        args['organization'] = self.organization
        prepared_url = url.format(**args)

        r = requests.get(prepared_url, auth=(self.token, ''))
        # print(r.text)
        return r.json()

    @cache(timeout=30*DAY)
    def get_namespaces(self):
        return self._get_request(NAMESPACES_URL)

    @cache(timeout=30*DAY)
    def get_groups(self):
        return self._get_request(GROUPS_URL)

    @cache(timeout=30*DAY)
    def get_users(self):
        return self._get_request(USERS_URL)

    @cache(timeout=30*DAY)
    def get_entity_memberships(self, descriptor):
        return self._get_request(MEMBERSHIP_URL, {'descriptor': descriptor, 'direction': 'Up'})

    @cache(timeout=30*DAY)
    def get_entity_members(self, descriptor):
        return self._get_request(MEMBERSHIP_URL, {'descriptor': descriptor, 'direction': 'Down'})


def main():

    if not os.path.exists('{}/config.yaml'.format(DIRECTORY)):
        print('Please copy config-sample.yaml to config.yaml and update it with your values.')
        exit(1)

    if not os.path.exists('{}/cache'.format(DIRECTORY)):
        os.mkdir('{}/cache'.format(DIRECTORY))

    with open('{}/config.yaml'.format(DIRECTORY)) as infile:
        config = yaml.safe_load(infile)

    app = Flask(__name__)
    api = DevopsCachedApi(config['token'], config['organization'])
    browser = DevopsBrowser(api)

    @app.route('/')
    def index():
        users = to_tuples(browser.get_sorted_users())
        groups = to_tuples(browser.get_sorted_groups())
        namespaces = to_tuples(browser.get_sorted_namespaces())
        return render_template('index.html', users=users, groups=groups, namespaces=namespaces)

    @app.route('/namespace/<name>', methods=['GET'])
    def namespace(name):
        return debug(browser.get_namespace(name))

    @app.route('/group', methods=['GET'])
    def groups():
        groups = browser.get_sorted_groups()
        return render_template('groups.html', groups=groups)

    @app.route('/entity/<descriptor>', methods=['GET'])
    def entity(descriptor):
        entity = browser.lookup(descriptor)
        users, groups = browser.get_related_entities(descriptor)
        if isinstance(entity, DevopsUser):
            users.insert(0, (entity, 'subject', 'subject'))
        elif isinstance(entity, DevopsGroup):
            groups.insert(0, (entity, 'subject', 'subject'))
        return render_template('index.html', subject=entity, users=users, groups=groups)

    @app.route('/group/<descriptor>', methods=['GET'])
    def group(descriptor):
        # entity = browser.lookup(descriptor)
        # users, groups = browser.get_related_entities(descriptor)
        group = browser.lookup(descriptor)
        groups = [group]
        connections = browser.get_entity_connections(descriptor)
        groups += connections['memberships']
        users = connections['members']
        return render_template('index.html', subject=group, users=users, groups=groups)


    @app.route('/user', methods=['GET'])
    def users():
        users = browser.get_sorted_users()
        return render_template('users.html', users=users)

    @app.route('/user/<descriptor>', methods=['GET'])
    def user(descriptor):
        user = browser.lookup(descriptor)
        users = [user]
        _, groups = browser.get_related_entities(descriptor)
        print(groups)
        return render_template('index.html', subject=user, users=users, groups=groups)

    @app.route('/namespace', methods=['GET'])
    def namespaces():
        return debug(api.get_namespaces())

    @app.route('/debug', methods=['GET'])
    def debug_app():
        browser.get_users()
        browser.get_groups()
        return debug(browser.lookup_table)

    @app.route('/api/connections/<descriptor>', methods=['GET'])
    def api_connections(descriptor):
        return to_json(browser.get_related_entities(descriptor))

    app.run(debug=True)


if __name__ == '__main__':
    main()
