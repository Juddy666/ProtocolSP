servers need to be connected to their neighbouring servers for proper connection
TEST CASES 
##for local machines
#type in your terminal
# start server 1 
python server.py --host localhost --port 8088 --server_port 8090 --neighbours localhost:8091
# start server2
python server.py --host localhost --port 8089 --server_port 8091 --neighbours localhost:8090

# add client 1 on server 1
python client.py --host localhost --port 8088

# add client 2 on server 2
python client.py --host localhost --port 8089


## running server on different machines
add the ip of your host if of your machine
python server.py --host 192.168.1.2 --port 8088 --server_port 9000 --neighbours 192.168.1.3:9001
python server.py --host 192.168.1.3 --port 8089 --server_port 9001 --neighbours 192.168.1.2:9000
