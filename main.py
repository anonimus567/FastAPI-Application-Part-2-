from elasticsearch import Elasticsearch
from fastapi import FastAPI, Query, HTTPException
import json
import re
from uuid import uuid4
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from pydantic import BaseModel
import os

templates = Jinja2Templates(directory="templates")

app = FastAPI()
es_url = os.environ.get('ES_URL')
es_token = os.environ.get('ES_TOKEN')
client = Elasticsearch(es_url, api_key=es_token)

my_users = {'mariana': {'username': 'mariana', 'position': 'developer'}}

class User(BaseModel):
    username: str
    position: str

@app.post('/users')
def create_user(user: User):
    username = user.username
    my_users[username] = user.dict()
    return {"message": "User created successfully", "user": user}

@app.get('/info', response_class=HTMLResponse)
def get_information_about_current_program_and_user(request: Request):
    creator = list(my_users.values())
    info = {
        "web app": "Web application for retriving  CVE Information from JSON file",
        "creator": creator 
    }
    return templates.TemplateResponse("info.html", {"request": request, "info": info})

@app.get("/init-db")
def create_cve_index():
    with open("known_exploited_vulnerabilities.json", "r") as file:
        data = json.load(file)
        vulnerabilities = data.get("vulnerabilities", [])
        
    for vuln in vulnerabilities:
        vuln_data = {
                'cveID': vuln.get('cveID'),
                'vendorProject': vuln.get('vendorProject'),
                'product': vuln.get('product'),
                'vulnerabilityName': vuln.get('vulnerabilityName'),
                'dateAdded': vuln.get('dateAdded'),
                'shortDescription': vuln.get('shortDescription'),
                'requiredAction': vuln.get('requiredAction'),
                'dueDate': vuln.get('dueDate'),
                'knownRansomwareCampaignUse': vuln.get('knownRansomwareCampaignUse'),
                'notes': vuln.get('notes'),
                'cwes': vuln.get('cwes', [])
            }
        client.create(index="cve_index", id=str(uuid4()), body=vuln_data)
    response = client.search(index="cve_index", body={
        "size": 100,
        "query": {"match_all": {}},
        "sort": [{"dateAdded": {"order": "desc"}}]  
    })
    return [doc['_source'] for doc in response.get('hits', {}).get('hits', [])]

@app.get("/get/all", response_class=HTMLResponse)
def get_all_cves_for_last_five_days(request: Request):
    response = client.search(index="cve_index", 
        body={
            "query": {
                "range": {
                "dateAdded": {
                    "gte": "2024-11-25",
                    "lte": "2024-11-30"
                }
            }}
        })
    result_of_searching = [doc['_source'] for doc in response.get('hits', {}).get('hits', {})]

    return templates.TemplateResponse(
    "all_cves.html",
    {"request": request, "result_of_searching": result_of_searching},
)

@app.get("/get/new", response_class=HTMLResponse)
def get_ten_latest_cve(request: Request):
    response = client.search(index="cve_index", 
        body={
            "size": 10,
        "query": {
    "range": {
        "dateAdded": {
            "lte": "2024-11-30"
        }
    }
}
})        
    newest_vulnerabilities = [doc['_source'] for doc in response.get('hits', {}).get('hits', {})]

    return templates.TemplateResponse(
        "new_cves.html",
        {"request": request, "newest_vulnerabilities": newest_vulnerabilities},
    )

@app.get("/get/known")
def get_ten_known_cve(request: Request):
      
        response = client.search(index="cve_index", 
        body={
                "query":{
                    "bool": {
                        "must": [
            {"match": {"knownRansomwareCampaignUse": "Known"}}]}} })

        known_cves = [doc['_source'] for doc in response.get('hits', {}).get('hits', {})]
        return templates.TemplateResponse(
        "known_cves.html",
        {"request": request, "known_cves": known_cves},
    )


@app.get("/get", response_class=HTMLResponse)
def get_results_with_query(request: Request, query: str):
    if not re.match(r"([a-zA-Z0-9]+(\s[a-zA-Z0-9]+)?)", query):
        raise HTTPException(
            status_code=400,
            detail="Your key phrase in url includes forbidden symbols. Please use only letters and digits.",
        )
    response = client.search(index="cve_index",
    body = {
    "query": {
        "bool": {
            "must": [
                {
                    "multi_match": {
                        "query": query,
                        "fields": ["vulnerabilityName", "shortDescription"]
                    }
                }
            ]
        }
    }
})
    
    result_of_searching= [doc['_source'] for doc in response.get('hits', {}).get('hits', [])]

    return templates.TemplateResponse(
        "search_for_query.html",
        {"request": request, "result_of_searching": result_of_searching})
