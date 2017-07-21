import hashlib
import requests
import time
import uuid
import os
import yaml

from .VTScrapping import getDetailed, getDetailedURL

config = yaml.load(open('classification/config.yml', 'r'))
KEY=config["VT_API_KEY"]

def getMD5(r):
	return hashlib.md5(r).hexdigest()

def scanVTFile(filename):
	params = {'apikey': KEY}
	files = {'file': (filename, open(filename, 'rb'))}
	response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
	response=response.json()
	return response['permalink']

def scanVTURL(url):
	params = {'apikey': KEY, 'url':url}
	response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', params=params)
	response=response.json()
	return response['permalink']

def getVTReport(h):
	params = {'apikey': KEY, 'resource': h}
	response = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	response = response.json()
	if response['response_code'] == 1:
		return response['permalink']
	elif response['response_code'] == -2:
		time.sleep(60)
		return getVTReport(h)
	else:
		0

def getScore(h):
	sc=0
	sTot=0

	params = {'apikey': KEY, 'resource': h}
	response = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	response = response.json()
	
	if response['response_code'] == 1:
		scans=response['scans']
	
		for s in scans:
			v=scans[s]
	
			if v['detected']:
				sc+=1
	
			sTot+=1

	if sTot > 0:
		return round(sc/sTot, 2)
	else:
		return 0

def extractReport(url):
	params = {'apikey': KEY}
	response = requests.post(url, params=params)

	filename=str(uuid.uuid4())
	
	tmp=open(filename,'w')
	tmp.write(response.text)
	tmp.close()

	return filename

def extractInfo(url):
	
	f=extractReport(url)
	tmp=open(f,'r')
	p=0
	res=""

	for line in tmp:
		if line.find("file-details") > 0:
			p=1
		elif line.find("id=\"comments\"") > 0:
			p=0
		if p > 0:
			res+=line 
	
	tmp.close()
	os.remove(f)

	return res

def VTHash2(h):
	resp=getVTReport(h)
	if resp:
		resp=extractInfo(resp)
		return getDetailed(resp)
	else:
		return 0

def VTHash(h):
	t=VTHash2(h)
	if t:
		return t
	else:
		return "Unsuccessfull request"

def VTFile(filename):
	h=getMD5(open(filename, 'b').read())
	resp=VTHash2(h)
	if resp:
		return resp
	else:
		resp=scanVTFile(filename)
		resp=extractInfo(resp)
		return getDetailed(resp)

def VTUrl(url):
	resp=getVTReport(url)
	if not resp:
		resp=scanVTURL(url)
	resp=extractInfo(resp)
	return getDetailedURL(resp)

def handle_uploaded_file(f):
	filename=str(uuid.uuid4())
	with open(filename, 'wb+') as destination:
		for chunk in f.chunks():
			destination.write(chunk)
	destination.close()
	return filename