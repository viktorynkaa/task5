from fastapi import FastAPI, Query
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from elasticsearch import Elasticsearch
from api import initdb

client = Elasticsearch(
    "https://ef0f11f7fdfc4f1ab989ec910fb145c7.us-central1.gcp.cloud.es.io:443",
    api_key="ZGVWZGhKTUJkenR2MjNZWFpSY1M6NEZHZHBiRXNUZ0dySWZIOWFNWV9EUQ==",
)

app = FastAPI()

app.include_router(initdb.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/info")
def app_info():
    return {
        "application": "Application for CVE",
        "author": "Victoria Yakym",
        "description": "This application is created for getting information about CVE"
    }

@app.get("/get/all")
def cve_five_days():
    try:
        last_twenty_days = datetime.now() - timedelta(days=20)
        response = client.search(
            index="cve",
            body={
                "query": {
                    "range": {
                        "vulnerabilities.dateAdded": {
                            "gte": last_twenty_days.isoformat()
                        }
                    }
                },
                "size": 40
            }
        )
        export_cve = response['hits']['hits']
    except Exception as e:
        print(e)
        export_cve = []
    return export_cve

@app.get("/get/new")
def new_cve():
    response = client.search(
        index="cve",
        body={
            "query": {
                "match_all": {}
            },
            "sort": [
                {"vulnerabilities.dateAdded": {"order": "desc"}}
            ],
            "size": 10
        }
    )
    new_cve_ten = response['hits']['hits']
    return new_cve_ten

@app.get("/get/known")
def get_known_cve():
    try:
        response = client.search(
            index="cve",
            body={
                "query": {
                    "term": {
                        "vulnerabilities.knownRansomwareCampaignUse": "Known"
                    }
                },
                "size": 10
            }
        )
        ten_cve = response['hits']['hits']
    except Exception as e:
        print(e)
        ten_cve = []
    return ten_cve

@app.get("/get")
def key_cve(query: str = Query(...)):
    try:
        response = client.search(
            index="cve",
            body={
                "query": {
                    "match": {
                        "vulnerabilities.shortDescription": query
                    }
                }
            }
        )
        keyw_cve = response['hits']['hits']
    except Exception as e:
        print(e)
        keyw_cve = []
    return keyw_cve
