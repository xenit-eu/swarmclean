#!/usr/bin/python3
import configargparse
import requests
import re
import logging
import time
import sys
import socket
from datetime import datetime
import os
import random
import urllib.parse
import records
from dataclasses import dataclass, asdict
import humanfriendly

sys.path.insert(0,sys.path[0]+'/castorsdk')
import scspHeaders

def yes_or_no(question):
    reply = str(input(question+' (y/n): ')).lower().strip()
    if reply[0] == 'y':
        return 1
    elif reply[0] == 'n':
        return 0
    else:
        return yes_or_no("Please Enter (y/n) ")

headersToCopy=[
  r'^Allow',
  r'^Allow-Encoding',
  r'^Cache-Control',
  r'^Castor-.+', 
  r'^Content-Base',
  r'^Content-Disposition',
  r'^Content-Encoding',
  r'^Content-Language',
  r'^Content-Location',
  r'^Content-MD5',
  r'^Content-Type',
  r'^Expires',
  r'^Policy-.+', 
  r'^X-.+-Meta-.+'
]

headersToSkip=[
  r'^Castor-System-.+',
  r'^Castor-Object-Count',
  r'^Castor-Bytes-Used.*', 
  r'^Policy-.+?-(?:Evaluated|Constrained)', 
  r'^X-Castor-Meta-Error-Message'
]

headersAllow = "(" + ")|(".join(headersToCopy) + ")"
#print('allow='+headersAllow)
headersAllow = re.compile(headersAllow, re.IGNORECASE) 

headersSkip = "(" + ")|(".join(headersToSkip) + ")"
#print('skip='+headersSkip)
headersSkip = re.compile(headersSkip, re.IGNORECASE) 



def script_init():
  hostname = socket.gethostname()
  parser = configargparse.ArgumentParser(
    default_config_files = ['swarmclean.conf'],
    description = """
Delete content from Swarm bucket.

Content selection:
  * filter_method = 'regex': object will be deleted if the object name matches the regex.
  * filter_method = 'alfresco_db': object will be deleted if it is not referenced in the alf_content_url table of the alfresco db.

The script will delete a single batch of objects with the total size of the objects in the batch < --batch_size.

When the objects have a 'deletable=no' lifepoint this will be replaced with 'deletable=yes'. This is a COPY operation and will cause the storage used for the object to be temporarily doubled.

---
""",
    formatter_class = configargparse.ArgumentDefaultsRawHelpFormatter
  )
  parser.add_argument(
    '-L',
    '--loglevel',
    env_var = 'SCL_LOGLEVEL',
    default = 'info',
    help = 'loglevel (critical | error | warning | info | trace | debug)'
  )
  group = parser.add_mutually_exclusive_group()
  group.add_argument(
    '-D',
    '--dryrun', 
    env_var = 'SCL_DRYRUN',
    action = "store_true",
    default = True,
    help = 'Dryrun mode'
  )
  group.add_argument(
    '-X',
    '--execute', 
    env_var = 'SCL_EXECUTE',
    action = "store_true",
    help = 'Execute mode'
  )
  parser.add_argument(
    '-C',
    '--confirm', 
    env_var = 'SCL_CONFIRM',
    action = "store_true",
    help = 'Request confirmation before doing deletes'
  )
  parser.add_argument(
    '-B',
    '--batch_size',
    env_var = 'SCL_BATCH_SIZE',
    default = '5 GiB',
    help = 'maximum size of batches'
  )
  parser.add_argument(
    '-R',
    '--report_folder',
    env_var = 'SCL_REPORT_FOLDER',
    default = f"/tmp/swarmclean",
    help = 'folder where report files will be written'
  )

  # swarm
  parser.add_argument(
    '-s',
    '--swarm_servers',
    env_var = 'SCL_SWARM_SERVERS',
    required = True,
    help = 'comma separated list of Swarm servers'
  )
  parser.add_argument(
    '-b',
    '--swarm_bucket',
    env_var = 'SCL_SWARM_BUCKET',
    required = True,
    help = 'Swarm bucket'
  )
  parser.add_argument(
    '-d',
    '--swarm_domain',
    env_var = 'SCL_SWARM_DOMAIN',
    required = True,
    help = 'Swarm domain'
  )
  parser.add_argument(
    '-x',
    '--swarm_proxy',
    env_var = 'SCL_PROXY',
    help='socks5://user:pass@host:port'
  )

  # swarm authentication
  parser.add_argument(
    '-g',
    '--swarm_use_contentgateway',
    env_var = 'SCL_SWARM_USE_CONTENTGATEWAY',
    default = False,
    help = 'set to True if using the Swarm Content Gateway (will enable authenticated calls)'
  )
  parser.add_argument(
    '-U',
    '--swarm_user',
    env_var = 'SCL_SWARM_USER',
    default = '',
    help = 'sets the Swarm username when using Swarm Content Gateway'
  )
  parser.add_argument(
    '-P',
    '--swarm_password',
    env_var = 'SCL_SWARM_PASSWORD',
    default = '',
    help = 'sets the Swarm password when using Swarm Content Gateway'
  )

  # content selection
  parser.add_argument(
    '-m',
    '--filter_method',
    env_var = 'SCL_FILTER_METHOD',
    required = True,
    help = 'alfresco_db | regex'
  )
  parser.add_argument(
    '-f',
    '--filter',
    env_var = 'SCL_FILTER',
    help = 'filter regex, objects that match will be deleted'
  )

  # Alfresco DB 
  parser.add_argument(
    '-u',
    '--db_user',
    env_var = 'SCL_DB_USER',
    default = 'ALFRESCO',
    help = 'Alfresco DB user id'
  )
  parser.add_argument(
    '-p',
    '--db_password',
    env_var = 'SCL_DB_PASSWORD',
    help = 'Alfresco DB password'
  )
  parser.add_argument(
    '-c',
    '--db_conn_string',
    env_var = 'SCL_DB',
    help = 'Alfresco DB connection string'
  )
  parser.add_argument(
    '-t',
    '--db_type',
    env_var = 'SCL_DB_TYPE',
    default = 'postgresql',
    help = 'Alfresco database type (oracle | postgresql)'
  )


  args = parser.parse_args()

  # set loglevel
  addLoggingLevel('TRACE', logging.DEBUG + 5) # level between info and debug
  numeric_level = getattr(logging, args.loglevel.upper(), None)
  if not isinstance(numeric_level, int):
    raise ValueError( f"Invalid log level: { loglevel }")
  logging.basicConfig(level=numeric_level,format='%(asctime)s %(name)-5s %(levelname)-8s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')

  return args
#end script_init

def addLoggingLevel(levelName, levelNum, methodName=None):
    # from https://stackoverflow.com/questions/2183233/how-to-add-a-custom-loglevel-to-pythons-logging-facility/35804945#35804945
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present 

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if not methodName:
        methodName = levelName.lower()

    if hasattr(logging, levelName):
       raise AttributeError('{} already defined in logging module'.format(levelName))
    if hasattr(logging, methodName):
       raise AttributeError('{} already defined in logging module'.format(methodName))
    if hasattr(logging.getLoggerClass(), methodName):
       raise AttributeError('{} already defined in logger class'.format(methodName))

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            self._log(levelNum, message, args, **kwargs)
    def logToRoot(message, *args, **kwargs):
        logging.log(levelNum, message, *args, **kwargs)

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)
#end addLoggingLevel


class AlfrescoDB:
  def __init__(self, args):
    db_connection_string = f"{ args['db_type'] }://{ args['db_user'] }:{ urllib.parse.quote_plus(args['db_password']) }@{ args['db_conn_string'] }"
    logging.debug(f"connecting to db { db_connection_string }")
    self.db = records.Database(db_connection_string)

  def __del__(self):
    if self.db:
      self.db.close()
  #end def __del__

  def do_query(self, query: str, arg_values={}):
    logging.debug(f"query: { query } arguments: { arg_values }")
    result = self.db.query(query, **arg_values)
    logging.debug(f"result:\n{ result.dataset }")
    return result
  #end def do_query

  def query_single_value(self, query: str, arg_values={}):
    return self.do_query(query, **arg_values)[0][0]
#end class AlfrescoDB

@dataclass
class SwarmObject:
  name: str
  bytes: int


class Swarm:

  def __init__(self, args):
    self.args = args
    self.swarm_servers = args['swarm_servers'].split(',')

    # setup Swarm session
    self.swarm_session = requests.Session()

    # if using swarm gateway, set up basic AUTH
    if args['swarm_use_contentgateway']:
      logging.debug(f"Using Swarm gateway, setting up basic auth.")
      self.swarm_session.auth = (args['swarm_user'], args['swarm_password'])

    if args['swarm_proxy']:
      self.swarm_session.proxies={'http': args['swarm_proxy']}
  #end def __init__

  def make_swarm_url(self, sub_path, args=''):
      url = f"http://{ random.choice(self.swarm_servers) }/{ sub_path }?domain={ self.args['swarm_domain'] }"
      if args:
        url = f"{ url }&{ args }"
      return url
  #end def make_swarm_url

  def list_bucket_contents(self, filter_function, max_batch_size):
    object_list = []
    batch_size = 0
    paging_marker = ''
    while True:
      response = self.swarm_session.get(self.make_swarm_url(self.args['swarm_bucket'], f"fields=name,content-length&format=json&paging_marker={ paging_marker }"))
      response.raise_for_status()
      logging.debug(response.content)
      objects = response.json()

      if not objects:
        return object_list

      for object in objects:
        swarm_object = SwarmObject(**object)
        if filter_function(swarm_object):
          if batch_size + swarm_object.bytes > max_batch_size:
            if batch_size == 0:
              raise ValueError( f"Object size for { swarm_object.name } ({ humanfriendly.format_size(swarm_object.bytes, binary=True) }) > max batch size ({ humanfriendly.format_size(max_batch_size, binary=True) })")
            return { 'list': object_list, 'size': batch_size }
          else:
            batch_size += swarm_object.bytes
            logging.trace(f"batch size { batch_size }")
          object_list.append(swarm_object)
  #end def list_bucket_contents

  def get_info(self, object_name):
    response = self.swarm_session.head(self.make_swarm_url(f"{ self.args['swarm_bucket'] }/{ object_name }"), allow_redirects=True)
    response.raise_for_status()
    logging.debug(response.headers)
    return response.headers
  #end def get_info

  def is_object_deletable(self, object_info):
    if 'Lifepoint' in object_info:
      lifepoints=scspHeaders.lifepointsFromString(object_info['Lifepoint'])
      for lp in lifepoints:
        if lp.end == None or time.time() <= lp.end.sinceEpoch():
          if lp.constraint == 'deletable=no':
            logging.debug(f"{ object_info['Castor-System-Name'] } has 'deletable=no' lifepoint")
            return False
    return True
  #end def is_object_deletable

  def update_lifepoint(self, object_info, lifepoint):
    headers={}
    # copy existing headers
    for header in object_info :
      if not headersSkip.match(header) and headersAllow.match(header):
        headers[header]=object_info[header]
    # add lifepoint header
    headers['Lifepoint']=lifepoint
    logging.debug(f"new headers: { headers }")
    if self.args['dryrun']:
      logging.info(f"DRYRUN - not updating lifepoint for { object_info['Castor-System-Name'] } from '{ object_info['Lifepoint'] }' to '{ lifepoint }'")
    else:
      logging.info(f"setting lifepoint for { object_info['Castor-System-Name'] } = '{ lifepoint }'")
      response = self.swarm_session.request(
        'COPY',
        self.make_swarm_url(f"{ self.args['swarm_bucket'] }/{ object_info['Castor-System-Name'] }"),
        headers=headers
      )
      response.raise_for_status()
  #end def update_lifepoint

  def delete_object(self, object_name):
    object_info = self.get_info(object_name)
    if not self.is_object_deletable(object_info):
      self.update_lifepoint(object_info, '[] deletable=yes')
    if self.args['dryrun']:
      logging.info(f"DRYRUN - not deleting { object_name }")
    else:
      logging.info(f"deleting { object_name }")
      response = self.swarm_session.delete(self.make_swarm_url(f"{ self.args['swarm_bucket'] }/{ object_name }"))
      response.raise_for_status()
  #end def delete_object
#end class Swarm

class SwarmClean:
  def __init__(self, args):
    self.args = args
    logging.debug(f"args={ args }")

    if self.args.execute:
      self.args.dryrun = False

    self.batch_size = humanfriendly.parse_size( args.batch_size )

    logging.info(f"max batch size: { self.batch_size } bytes")

    # create dir for batch reports
    self.args.start_time = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    self.report_folder = f"{self.args.report_folder}/swarm2s3_{ self.args.start_time }"
    os.makedirs(self.report_folder)
    logging.info(f"writing reports to {self.report_folder}")

    swarm_args = { key: value for key, value in vars(args).items() if key[0:5] == 'swarm' }
    swarm_args['dryrun'] = self.args.dryrun
    self.swarm = Swarm(swarm_args)

    if args.filter_method == 'alfresco_db':
      logging.info(f"using filter type 'alfresco_db' with database { args.db_conn_string }")
      db_args = { key: value for key, value in vars(args).items() if key[0:2] == 'db' }
      self.alfresco_db = AlfrescoDB(db_args)
    elif args.filter_method == 'regex':
      logging.info(f"using filter type 'regex' with regex { args.filter }")
      self.filterRegex=re.compile(args.filter)
    else:
      raise ValueError( f"Invalid filter_method: { args.filter_method }")
  #end def __init__

  def filter(self, swarm_object):
    if args.filter_method == 'alfresco_db':
      result = len(self.alfresco_db.do_query("select id from alf_content_url where content_url like :object_name", {'object_name': f"%/{swarm_object.name}"}).all()) == 0
    elif args.filter_method == 'regex':
      result = self.filterRegex.match(swarm_object.name)
    logging.trace(f"filter { swarm_object.name }: { bool(result) } - size { humanfriendly.format_size(swarm_object.bytes, binary=True) }")
    return result
  #end def filter

  def main(self):
    objects_to_delete = self.swarm.list_bucket_contents(self.filter, self.batch_size)
    for swarm_object in objects_to_delete['list']:
      logging.info(f"to delete: { swarm_object.name }")
    logging.info(f"total size: { humanfriendly.format_size(objects_to_delete['size'], binary=True) }")
    if not args.confirm or yes_or_no('delete ?'):
      for swarm_object in objects_to_delete['list']:
        self.swarm.delete_object(swarm_object.name)
  #end def main
#end class SwarmClean

if __name__ == '__main__':
  args = script_init()
  script = SwarmClean(args)
  script.main()



