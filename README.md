# README #

Script to delete content from a Swarm bucket.

```
usage: swarmclean.py [-h] [-L LOGLEVEL] 
					 [-D | -X] [-C]
					 [-B BATCH_SIZE] [-R REPORT_FOLDER] 
					 -s SWARM_SERVERS -b SWARM_BUCKET -d SWARM_DOMAIN [-x SWARM_PROXY] 
					 	[-g SWARM_USE_CONTENTGATEWAY] [-U SWARM_USER] [-P SWARM_PASSWORD] 
					 -m FILTER_METHOD 
					 	[-f FILTER] 
					 	[-u DB_USER] [-p DB_PASSWORD] [-c DB_CONN_STRING] [-t DB_TYPE]

Delete content from Swarm bucket.

Content selection:
  * filter_method = 'regex': object will be deleted if the object name matches the regex.
  * filter_method = 'alfresco_db': object will be deleted if it is not referenced in the alf_content_url table of the alfresco db.

The script will delete a single batch of objects with the total size of the objects in the batch < --batch_size.

When the objects have a 'deletable=no' lifepoint this will be replaced with 'deletable=yes'. This is a COPY operation and will cause the storage used for the object to be temporarily doubled. The object is deleted immediately after the copy.

---

options:
  -h, --help            show this help message and exit
  -L LOGLEVEL, --loglevel LOGLEVEL
                        loglevel (critical | error | warning | info | trace | debug)   [env var: SCL_LOGLEVEL] (default: info)
  -D, --dryrun          Dryrun mode   [env var: SCL_DRYRUN] (default: True)
  -X, --execute         Execute mode   [env var: SCL_EXECUTE] (default: False)
  -C, --confirm         Request confirmation before doing deletes   [env var: SCL_CONFIRM] (default: False)
  -B BATCH_SIZE, --batch_size BATCH_SIZE
                        maximum size of batches   [env var: SCL_BATCH_SIZE] (default: 5 GiB)
  -R REPORT_FOLDER, --report_folder REPORT_FOLDER
                        folder where report files will be written   [env var: SCL_REPORT_FOLDER] (default: /tmp/swarmclean)
  -s SWARM_SERVERS, --swarm_servers SWARM_SERVERS
                        comma separated list of Swarm servers   [env var: SCL_SWARM_SERVERS] (default: None)
  -b SWARM_BUCKET, --swarm_bucket SWARM_BUCKET
                        Swarm bucket   [env var: SCL_SWARM_BUCKET] (default: None)
  -d SWARM_DOMAIN, --swarm_domain SWARM_DOMAIN
                        Swarm domain   [env var: SCL_SWARM_DOMAIN] (default: None)
  -x SWARM_PROXY, --swarm_proxy SWARM_PROXY
                        socks5://user:pass@host:port   [env var: SCL_PROXY] (default: None)
  -g SWARM_USE_CONTENTGATEWAY, --swarm_use_contentgateway SWARM_USE_CONTENTGATEWAY
                        set to True if using the Swarm Content Gateway (will enable authenticated calls)   [env var: SCL_SWARM_USE_CONTENTGATEWAY] (default: False)
  -U SWARM_USER, --swarm_user SWARM_USER
                        sets the Swarm username when using Swarm Content Gateway   [env var: SCL_SWARM_USER] (default: )
  -P SWARM_PASSWORD, --swarm_password SWARM_PASSWORD
                        sets the Swarm password when using Swarm Content Gateway   [env var: SCL_SWARM_PASSWORD] (default: )
  -m FILTER_METHOD, --filter_method FILTER_METHOD
                        alfresco_db | regex   [env var: SCL_FILTER_METHOD] (default: None)
  -f FILTER, --filter FILTER
                        filter regex, objects that match will be deleted   [env var: SCL_FILTER] (default: None)
  -u DB_USER, --db_user DB_USER
                        Alfresco DB user id   [env var: SCL_DB_USER] (default: ALFRESCO)
  -p DB_PASSWORD, --db_password DB_PASSWORD
                        Alfresco DB password   [env var: SCL_DB_PASSWORD] (default: None)
  -c DB_CONN_STRING, --db_conn_string DB_CONN_STRING
                        Alfresco DB connection string   [env var: SCL_DB] (default: None)
  -t DB_TYPE, --db_type DB_TYPE
                        Alfresco database type (oracle | postgresql)   [env var: SCL_DB_TYPE] (default: postgresql)

Args that start with '--' (eg. -L) can also be set in a config file (swarmclean.conf). Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi). If an arg is specified in
more than one place, then commandline values override environment variables which override config file values which override defaults.

```

