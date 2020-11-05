#!/usr/bin/python3
import argparse
import requests
from urllib.parse import urlparse
import re
import logging

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


parser = argparse.ArgumentParser(description="delete bucket content",formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i','--swarm',required=True,help='swarm ip')
parser.add_argument('-u','--user',required=True,help='userid')
parser.add_argument('-p','--password',required=True,help='password')
parser.add_argument('-b','--bucket',required=True,help='swarm bucket')
parser.add_argument('-d','--domain',required=True,help='swarm domain')
parser.add_argument('-f','--file',required=True,help='file(s) to delete (regex)')
parser.add_argument('-x','--proxy',help='socks5://user:pass@host:port')
parser.add_argument('-l','--loglevel',default='info',help='Logging level')
parser.add_argument('-D','--dryrun',action="store_true", help='Dryrun mode')


args = parser.parse_args()

print(args)

# set loglevel & log format
numeric_level = getattr(logging, args.loglevel.upper())
if not isinstance(numeric_level, int):
  raise ValueError('Invalid log level: %s' % loglevel)
if args.loglevel.upper()=='DEBUG':
  format='%(asctime)s %(name)-25s %(levelname)-8s %(message)s'
else:
  format='%(asctime)s %(name)-5s %(levelname)-8s %(message)s'
logging.basicConfig(level=numeric_level,format=format,datefmt='%Y-%m-%d %H:%M:%S')

lifepoint='[] deletable=yes'

fileRegex=re.compile(args.file)

filesToDelete=[]

with requests.Session() as s :
  logging.info('getting list of files')
  if args.proxy:
    s.proxies={'http':args.proxy}
  marker=''
  swarmUrl='http://{0}/{1}?domain={2}&fields=name&format=json&marker={3}'.format(args.swarm,args.bucket,args.domain,marker)
  resp=s.get(swarmUrl, auth=(args.user,args.password), allow_redirects=True)
  files=resp.json()
  while len(files)>0:
    for file in files:
      if not args.loglevel.upper()=='DEBUG':
        print('.', end='', flush=True)
      if not fileRegex.match(file['name']):
        logging.debug("not deleted: {0}".format(file['name']))
      else:
        logging.debug("will be deleted: {0}".format(file['name']))
        filesToDelete.append(file['name'])
      # get next part of the filelist
      marker=file['name']
      swarmUrl='http://{0}/{1}?domain={2}&fields=name&format=json&marker={3}'.format(args.swarm,args.bucket,args.domain,marker)
      resp=s.get(swarmUrl, auth=(args.user,args.password), allow_redirects=True)
      files=resp.json()
  if not args.loglevel.upper()=='DEBUG':
    print('\n', end='', flush=True)

  if len(filesToDelete) == 0:
    logging.info('no files found')
  else:
    logging.info("files to delete:\n{0}".format('\n'.join(filesToDelete)))
    if not args.dryrun and yes_or_no('delete ?'):
      for file in filesToDelete:
        logging.info('deleting {0}'.format(file))
        # get object headers
        swarmUrl='http://{0}/{1}/{2}?domain={3}'.format(args.swarm,args.bucket,file,args.domain)
        resp=s.head(swarmUrl, auth=(args.user,args.password), allow_redirects=True)
        if resp.status_code==200:
          # set deletable=yes lifepoint
          if 'Lifepoint' not in resp.headers or resp.headers['Lifepoint'] != lifepoint :
            headers={}
            # copy existing headers
            for header in resp.headers :
              if not headersSkip.match(header) and headersAllow.match(header):
                headers[header]=resp.headers[header]
            # add lifepoint header
            headers['Lifepoint']=lifepoint
            logging.debug(swarmUrl)
            resp2=s.request('COPY',swarmUrl,headers=headers, auth=(args.user,args.password))
            if resp2.status_code != 200:
              logging.debug('HTTP '+str(resp2.status_code))
              logging.debug(resp2.text)
              logging.debug(resp2.headers)
          else:
            logging.debug('Lifepoint already set')
          # delete object
          resp3=s.request('DELETE',swarmUrl,headers=headers, auth=(args.user,args.password))
          if resp3.status_code != 200:
            logging.error('HTTP '+str(resp3.status_code))
            logging.error(resp3.text)
            logging.error(resp3.headers)
        else :
          logging.error(str(resp.status_code))
          logging.error(resp.text)
          logging.error(resp.headers)




