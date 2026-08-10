from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus

username = "patilsankettech_db_user"
password = quote_plus("Sanket123")

uri = f"mongodb+srv://{username}:{password}@clusternetworksecurity.rlqjlll.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

client = MongoClient(uri)

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)