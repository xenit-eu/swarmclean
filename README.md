# README #

usage: swarmclean.py [-h] -i SWARM -u USER -p PASSWORD -b BUCKET -d DOMAIN -f FILE [-x PROXY] [-l LOGLEVEL] [-D]

delete bucket content

optional arguments:
  -h, --help            show this help message and exit
  -i SWARM, --swarm SWARM
                        swarm ip (default: None)
  -u USER, --user USER  userid (default: None)
  -p PASSWORD, --password PASSWORD
                        password (default: None)
  -b BUCKET, --bucket BUCKET
                        swarm bucket (default: None)
  -d DOMAIN, --domain DOMAIN
                        swarm domain (default: None)
  -f FILE, --file FILE  file(s) to delete (regex) (default: None)
  -x PROXY, --proxy PROXY
                        socks5://user:pass@host:port (default: None)
  -l LOGLEVEL, --loglevel LOGLEVEL
                        Logging level (default: info)
  -D, --dryrun          Dryrun mode (default: False)