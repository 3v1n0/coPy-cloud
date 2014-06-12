#!/usr/bin/env python

import os
import sys
import json
import hashlib
import urllib3
import struct

class CoPyCloudError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class CoPyCloud:

    API_URI = 'http://api.copy.com'
    DEFAULT_HEADERS = {'X-Client-Type': 'api', 'X-Api-Version': '1.0',
                       'X-Authorization': '', 'Accept': 'text/plain' }

    def __init__(self, username, password):
        self.http = urllib3.connection_from_url(self.API_URI, block=True, maxsize=1)
        res = self.__post_req('auth_user', {'username': username, 'password' : password})

        if not res or 'auth_token' not in res:
            raise CoPyCloudError("Invalid Login")

        self.DEFAULT_HEADERS['X-Authorization'] = res['auth_token'].encode('ascii','ignore')
        print self.DEFAULT_HEADERS['X-Authorization']


    def __req(self, req_type, method, params={}, headers={}):
        headers = dict(self.DEFAULT_HEADERS.items() + headers.items())
        method = '/'+method if method[0] != '/' else method

        res = self.http.request_encode_body(req_type, method, {'data': json.dumps(params)},
                                            headers, encode_multipart=False)

        if res.status != 200:
            raise CoPyCloudError("Got HTTP error "+str(res.status))

        try:
            if 'content-type' in res.headers and res.headers['content-type'] == 'application/json':
                jd = json.loads(res.data, 'latin-1')

                if jd and 'result' in jd and jd['result'] == 'error':
                    raise CoPyCloudError("Error %s: %s" % (jd['error_code'], jd['error_string']))

                return jd
        except ValueError:
            pass

        return res.data

    def __post_req(self, method, params={}, headers={}):
        return self.__req('POST', method, params, headers)

    def __get_req(self, method, headers={}):
        return self.__req('GET', method,  headers)

    def __update_objects(self, parameters):
        p = [parameters] if isinstance(parameters, dict) else p
        self.__post_req('update_objects', {'meta': p})

    def __sanitize_path(self, path):
        return '/'+path if path[0] != '/' else path

    def list_files(self, path=None, max_items=sys.maxint, list_watermark=False,
                   include_total_items=False, recurse=False, include_parts=False,
                   include_attributes=False, include_sync_filters=False,
                   group_by_dir=False, include_child_counts=False,
                   filter_name=None, sort_field=None, sort_direction=None):
        path = '/' if not path or not len(path) else path
        parameters = {'path': path, 'max_items': max_items}

        if list_watermark:
            parameters['list_watermark'] = True
        if include_total_items:
            parameters['include_total_items'] = True
        if recurse:
            parameters['recurse'] = True
        if include_parts:
            parameters['include_parts'] = True
        if include_child_counts:
            parameters['include_child_counts'] = True
        if include_attributes:
            parameters['include_attributes'] = True
        if include_sync_filters:
            parameters['include_sync_filters'] = True
        if filter_name:
            parameters['filter_name'] = filter_name
        if group_by_dir:
            parameters['group_by_dir'] = True
        if sort_field:
            parameters['sort_field'] = sort_field
        if sort_direction:
            parameters['sort_direction'] = sort_direction

        res = self.__post_req('list_objects', parameters)

        if not res or 'children' not in res:
            raise CoPyCloudError("Impossible to retrieve the files")

        if 'object' in res and 'type' in res['object'] and res['object']['type'] == 'file':
            return res['object']

        return res['children']

    def create_folder(self, path):
        if not path or not len(path):
            raise CoPyCloudError("Impossible to create a folder with an empty path")

        self.__update_objects({'action': 'create', 'object_type': 'dir', 'path': self.__sanitize_path(path)})

    def move(self, src, dst):
        if not src or not len(src) or not dst or not len(dst):
            raise CoPyCloudError("Impossible to move a file from/to an empty path")

        self.__update_objects({'action': 'rename', 'path': self.__sanitize_path(src), 'new_path': self.__sanitize_path(dst)})

    def remove(self, path):
        if not path or not len(path):
            raise CoPyCloudError("Impossible to remove a file with an empty path")

        self.__update_objects({'action': 'remove', 'path': self.__sanitize_path(path)})

    def download(self, path):
        if not path or not len(path):
            raise CoPyCloudError("Impossible to download a file with an empty path")

        if not len(self.list_files(path, max_items=1)):
            raise CoPyCloudError("Impossible to download '"+path+"'")

        return self.__post_req('download_object', {'path': path})

    def upload(self, source, dest, share_id=0):
        pass


if __name__ == "__main__":
    copy = CoPyCloud('foo@bar.net', 'fobar')
    copy.create_folder("foodir")
    copy.create_folder("FooBarFolder")
    copy.create_folder("FooBarFolder/SecondaryLEvel")
    copy.move('foodir', "FooBarFolder/SecondaryLEvel/foobarrs")
    copy.remove("FooBarFolder")