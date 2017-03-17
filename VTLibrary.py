import hashlib
import requests
from bs4 import BeautifulSoup

KEY="86fa6b2362f22c5f7222ef3a59e52257c83c2dff5f9c54b6c918c327a69d8dac"

def getMD5(r):
	return hashlib.md5(r).hexdigest()

def getVTReport(hash):
	params = {'apikey': KEY, 'resource': hash}
	response = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	return response.json()

def getSpecificTag(text, sp):
	for info in sp:
		if info.contents[1].find(text) > 0:
			break
	return info

def getImports(sp):
	info=getSpecificTag("PE Imports", sp)
	s=""

	for c in info.findAllNext('a'):
		s+=str(c.string)

	s=s.split("[+]")
	c=s[len(s)-1].split('dll')[0]
	c+="dll"
	s=s[1:(len(s)-1)]
	s.append(c)
	return s

def getFilenames(sp):
	info=getSpecificTag("VirusTotal metadata", sp)
	s=""
	for c in info.findAllNext('td')[1]:
		s+=str(c).strip() 	
	return s.split("<br/>")[:-1]

def getOpenFiles(sp):
	info = getSpecificTag("Opened files",sp)
	for c in info.findAllNext('div', ('class','enum')):
		print(c.contents)

def getDetailed(res):
	soup = BeautifulSoup(res, "lxml")
	base = soup.find_all('h5')

	imports=getImports(base)
	filenames=getFilenames(base)
	openfiles=getOpenFiles(base)
	return 0

def scanVT(filename):
	params = {'apikey': KEY}
	files = {'file': (filename, open(filename, 'rb'))}
	response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
	return response.json()

def requestVT(filename):
	md5f=getMD5(open(filename, 'rb').read())
	current=getVTReport(md5f)
	if(current['response_code']>0):
		print('=== File already scanned ===\n')
		return current['permalink']
	else:
		print('File inexistant...\n')
		current = scanVT(filename)
		return current['permalink']

def extractInfo():
	tmp=open('tmp.txt','r')
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
	return res

def extractWebPage(url):
	params = {'apikey': KEY}
	response = requests.post(url, params=params)
	
	tmp=open('tmp.txt','w')
	tmp.write(response.text)
	tmp.close()

	res=extractInfo()

	return getDetailed(res)
	
def main():
	filename='infected.file'
	#url=requestVT(filename)
	getDetailed(extractInfo())

if __name__ == "__main__":
	main()