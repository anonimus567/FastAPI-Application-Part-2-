# FastAPI-Application-Part-2
This is my Homework FastAPI Application Part 2
In this homework I added to the FastAPI application the ability to save reports to the elastic database and modified the existing endpoints in such a way that the output from the endpoints of the application specified in part 1 of the task takes place from the database. Moreover, I added new endpoint /init-db -  that initializes the database with data from the file.
## Code for creating new  /init-db endpoint
```python
@app.get("/init-db")
def create_cve_index():
    with open("known_exploited_vulnerabilities.json", "r") as file: #readining json file
        data = json.load(file)#transforming JSON file into dictionary
        vulnerabilities = data.get("vulnerabilities", [])#geting vulnerabilities key from created dictionary
    for vuln in vulnerabilities:# iterating through each cve
        vuln_data = { #creating new dictionary to save each CVE
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
        client.create(index="cve_index", id=str(uuid4()), body=vuln_data)#creating "cve_index" index with unique identifier #and loading  vuln_data to cve_index
    response = client.search(index="cve_index", body={ #filtering cve_index for 100 latest vulnerabilities
        "size": 100,
        "query": {"match_all": {}},
        "sort": [{"dateAdded": {"order": "desc"}}] 
    })
    return [doc['_source'] for doc in response.get('hits', {}).get('hits', {})]#returning  list of 100 most recent cve #trough iterating over each document and extracting the _source field that contains  document data.
```
## JSON data saved in Elasticsearch
<pre> {{
  "mappings": {
    "properties": {
      "cveID": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "cwes": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "dateAdded": {
        "type": "date"
      },
      "dueDate": {
        "type": "date"
      },
      "knownRansomwareCampaignUse": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "notes": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "product": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "requiredAction": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "shortDescription": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "vendorProject": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "vulnerabilityName": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      }
    }
  }
}</pre>
## Results in FastApi and ElasticSearch
<img width="958" alt="image" src="https://github.com/user-attachments/assets/96f95451-d90c-458c-aea6-30dbb434b9a8">
<img width="955" alt="image" src="https://github.com/user-attachments/assets/102b23b7-3aa3-49ae-9958-885f59df08c7">


## Endpoints for creating new users and retrivieng information about my application
```python
my_users = {'mariana': {'username': 'mariana', 'position': 'developer'}}# creating dictionary to save my users

class User(BaseModel):# defining  model to validate fields in dictionary
    username: str# username of the user
    position: str# position of the user (e.g., developer)

@app.post('/users')# endpoint to create a new user
def create_user(user: User):
    username = user.username # extracting username from the request
    my_users[username] = user.dict()# storing user data in the dictionary
    return  user

@app.get('/info', response_class=HTMLResponse)# endpoint for retrieving information about the application and its creator
def get_information_about_current_program_and_user(request: Request):
    creator = list(my_users.values())# getting  list of users
    info = {
        "web app": "Web application for retriving  CVE Information from JSON file", #defining information to be displayed
        "creator": creator 
    }
    return templates.TemplateResponse("info.html", {"request": request, "info": info})#returning  information page using info.html template
```
## Results
![Screenshot 2024-12-01 235753](https://github.com/user-attachments/assets/4656cf65-35f9-46f3-9e54-9f0f5c56d6d4)

# Endpoint for getting all CVEs for last five days
```python
@app.get("/get/all", response_class=HTMLResponse)
def get_all_cves_for_last_five_days(request: Request):
    response = client.search(index="cve_index", #searching for cves added since 2024-11-25 to 2024-11-30 
        body={
            "query": {
                "range": {
                "dateAdded": {
                    "gte": "2024-11-25",
                    "lte": "2024-11-30"
                }
            }}
        })
    result_of_searching = [doc['_source'] for doc in response.get('hits', {}).get('hits', {})] # creating #"result_of_searching" list

    return templates.TemplateResponse(# returning created list from ElasticSearch and HTML template to display this list of #filtered CVEs
    "all_cves.html",
    {"request": request, "result_of_searching": result_of_searching},
)
```
## Results
<img width="946" alt="image" src="https://github.com/user-attachments/assets/4d951794-8c9e-4394-836f-701664be64be">

## Endpoint for retrivieng 10 latest CVEs
```python
@app.get("/get/new", response_class=HTMLResponse)
def get_ten_latest_cve(request: Request):
    response = client.search(index="cve_index", #filtering for 10 latest CVEs that are added since "2024-11-30"
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
    newest_vulnerabilities = [doc['_source'] for doc in response.get('hits', {}).get('hits', {})]# creating list of 10 #latest cves

    return templates.TemplateResponse( # returning created list from ElasticSearch and HTML template to display this list #of filtered CVEs
        "new_cves.html",
        {"request": request, "newest_vulnerabilities": newest_vulnerabilities},
    )
```
## Results
![Screenshot 2024-12-02 001411](https://github.com/user-attachments/assets/c85e2e59-582c-4004-967e-086c4c174434)
## Endpoint for retrieving 10 known CVEs
```python
@app.get("/get/known")
def get_ten_known_cve(request: Request):
        response = client.search(index="cve_index", # filtering for cves that have value "Known" in #"knownRansomwareCampaignUse" field 
        body={
                "query":{
                    "bool": {
                        "must": [
            {"match": {"knownRansomwareCampaignUse": "Known"}}]}} })

        known_cves = [doc['_source'] for doc in response.get('hits', {}).get('hits', {})]# creating list of known cves
        return templates.TemplateResponse(# returning created list from ElasticSearch and HTML template to display this #list of filtered CVEs
        "known_cves.html",
        {"request": request, "known_cves": known_cves},
    )
```
## Results
<img width="954" alt="image" src="https://github.com/user-attachments/assets/1894ac7d-b301-48f8-918e-97a8696e5ba5">

## Endpoint for searching CVEs with key phrase
```python
@app.get("/get", response_class=HTMLResponse)
def get_results_with_query(request: Request, query: str):
    if not re.match(r"([a-zA-Z0-9]+(\s[a-zA-Z0-9]+)?)", query):#regular expression to validate the query (one or two words # with letters and digits only are allowed )
        raise HTTPException(status_code=400, detail="Your key phrase in url includes forbidden symbols. Please use only letters and digits." )#reising error if user input is incorrect
    response = client.search(index="cve_index", # searching for CVEs that  include "query" in "vulnerabilityName" and #"shortDescription" fields 
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
    
    result_of_searching= [doc['_source'] for doc in response.get('hits', {}).get('hits', [])]# creating list of filtered #cves

    return templates.TemplateResponse(# returning created list from ElasticSearch and HTML template to display this list of #filtered CVEs
        "search_for_query.html",
        {"request": request, "result_of_searching": result_of_searching})
```
## Results
<img width="872" alt="image" src="https://github.com/user-attachments/assets/1b470cbe-0339-45b4-be17-5cd6d8bcc320">




