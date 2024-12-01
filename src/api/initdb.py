import json
from elasticsearch import Elasticsearch
from fastapi import APIRouter


client = Elasticsearch(
    "https://ef0f11f7fdfc4f1ab989ec910fb145c7.us-central1.gcp.cloud.es.io:443",
    api_key="ZGVWZGhKTUJkenR2MjNZWFpSY1M6NEZHZHBiRXNUZ0dySWZIOWFNWV9EUQ==",
)

with open("known_exploited_vulnerabilities.json", "r", encoding="utf8") as file:
    vuln_db = json.load(file)

router = APIRouter(tags=["init db"])

@router.post("/init-db")
def init_db():
    try:
        if not client.indices.exists(index="cve"):
            client.indices.create(index="cve")
        else: 
            return "Such database already exists!"
        
        client.index(index="cve", id=1, document=vuln_db)
        return "Congratulations! Data from json has migrated to elastic database"
    except Exception as e:
        return f"Error:{e}"