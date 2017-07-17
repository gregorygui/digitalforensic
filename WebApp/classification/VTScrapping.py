import re
from bs4 import BeautifulSoup

def getSpecificTag(text, sp):
	for info in sp:
		if info.contents[1].find(text) > 0:
			break
	return info

def getImports(sp):
	info=getSpecificTag("PE imports", sp)
	l=[]
	for c in info.findAllNext(name='a',attrs={'class':'expand-data'}):
		s=str(c.string)
		l.append(s[4:])
	return l

def getHash(sp):
	info=getSpecificTag("File identification", sp)
	l=[]
	for c in info.findAllNext(name='span', attrs={'class':'field-key'}):
		t=str(c.next_element.next_element)
		l.append(t[1:-2])
	return l[:3]

def getFilenames(sp):
	info=getSpecificTag("VirusTotal metadata", sp)
	l=[]
	c=info.findNext(name='td', attrs={'class':'field-value'})
	c=str(c.text)
	l=c[:-1].split("\n        \n        ")
	return l[1:]

def getSections(sp):
	info=getSpecificTag("PE sections",sp)
	d=dict()
	l=[]
	name=0
	c=info.findNextSibling(name='div')
	
	for j in c.find_all(name='span'):
		if re.search(r"(\.)[a-z]+",j.string,re.MULTILINE):
			if name:
				d.update({name:l})
			name=j.string.replace("\n  \n    ","").replace("\n  \n  ","")
			l=[]
		else:
			l.append(j.string.replace("\n  \n    ","").replace("\n  \n  ",""))
	d.update({name:l})
	return d

def getPEHeader(sp):
	info=getSpecificTag("PE header basic information",sp)
	c=info.findNextSibling(name='div', attrs={'class':'enum-container'})
	l=[]
	pattern1=r"0x[0-9A-F]{8}"
	pattern2=r"([0-9]{4})-((0|1)[0-9])-([0-3][0-9])"

	for j in c.find_all(name='div', attrs={'class':'enum'}):
		s=str(j.text)[1:-1]
		if re.search(pattern1, s):
			s=s.split(" ")[-1]
		elif re.search(pattern2, s):
			s=s.split(" ")[-2]
		l.append(s)
	return l[:-1]


def getDetailed(res):
	soup = BeautifulSoup(res, "lxml")
	base = soup.find_all('h5')

	result={'Imports':getImports(base), 'Filenames':getFilenames(base), 'Hash':getHash(base), 'Sections':getSections(base), 'Header':getPEHeader(base)}

	return result

def getDetailedURL(res):
	return 0

def main():
	filename='tmp.txt'
	print(getDetailed(open('tmp.txt','rb').read()))

if __name__ == "__main__":
	main()