# OP2 Example
### Setup
#### Client Management

To be able to start up the project you have to create a new client to the client_db.
This is done by the CLI applilcation client_manageent.py
The allowed redirect_uris must be given and the client_id, and client_secret are generated. 

See some samples below. 

##### Add new client 
Start client_management with -c and answer the upcoming questions. 
../../src/oic/utils/client_management.py -c client_db

##### List clients
../../src/oic/utils/client_management.py -l  client_db

##### Show values for a specific client
../../src/oic/utils/client_management.py -s  -i <client id>  client_db
 
{
'client_secret': 'e4d70473ac2db4adbf9fb765ec56d34076720fa52e8edebdbbc368c2', 
'redirect_uris': [['https://myserver.com/callback', None], ['https://eny5ndkgibofe.x.pipedream.net/', None]], 
'client_salt': 'vULdf5Q8', 
'client_id': '9D8nyeoaIfE8'
}

##### Show all command line options
../../src/oic/utils/client_management.py -h  client_db


### Good to know
If the max_age is not set in the authorization request the max_age will be 0 and the authorization cookie will never expire. 

