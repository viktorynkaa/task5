from fastapi import FastAPI
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
        export_cve = []
        response = client.get(index="cve", id=1)
        for i in response.get("_source", {}).get("vulnerabilities", []): 
            date_from = datetime.fromisoformat(i.get("dateAdded", ""))
            if date_from >= last_twenty_days:
                export_cve.append(i)
            if len(export_cve) == 40:
                break
    except Exception as e:
        print(e)
    return export_cve

@app.get("/get/new")
def new_cve():
    response = client.get(index="cve", id=1)
    new_cve_ten = sorted(response.get("_source", {}).get("vulnerabilities", []), key=lambda i: i["dateAdded"])
    return new_cve_ten[-10:]

@app.get("/get/known")
def get_known_cve():
    try:
        response = client.get(index="cve", id=1)
        ten_cve = []

        for i in response.get("_source", {}).get("vulnerabilities", []):
            if "Known" == i.get("knownRansomwareCampaignUse", ""):
                ten_cve.append(i)
            if len(ten_cve) == 10:
                break
    except Exception as e:
        print(e)
    return ten_cve

@app.get("/get")
def key_cve(query):
    try:
        response = client.get(index="cve", id=1)
        keyw_cve = []

        for i in response.get("_source", {}).get("vulnerabilities", []):
            if query.lower() in i.get("shortDescription", "").lower():
                keyw_cve.append(i)
    except Exception as e:
        print(e)
    return keyw_cve

