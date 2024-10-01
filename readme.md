python server.py --host localhost --port 8088 --server_port 8090 --neighbours localhost:8091
python server.py --host localhost --port 8089 --server_port 8091 --neighbours localhost:8090
python client.py --host localhost --port 8088
python client.py --host localhost --port 8089
