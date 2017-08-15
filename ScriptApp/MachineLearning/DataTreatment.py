import sqlite3
import numpy as np

def dictTreatment(c):
	d=dict()

	for v in c.fetchall():
		d[v[0]]=v[1]

	return d

def listTreatment(c):
	l=[]

	for v in c.fetchall():
		l+=v

	return l

def get_default_criterion(c):
	l=[]
	c.execute("SELECT name FROM classification_defaultcriterion")
	
	return listTreatment(c)

def get_criterions(c, fid):
	l=[]
	t=(fid,)
	c.execute("SELECT name, score FROM classification_filecriterion WHERE file_id=?", t)

	return dictTreatment(c)

def get_files(c):
	l=[]
	c.execute("SELECT id FROM classification_file")

	return listTreatment(c)

def isMalicious(c, fid):
	t=(fid,)
	c.execute("SELECT maliciousness FROM classification_file WHERE id=?", t)
	m = (listTreatment(c))[0]

	if m > 6:
		return True
	else:
		return False

def get_data(c):
	dc = get_default_criterion(c)
	data = {}
	ar=[]
	targets = []

	for fid in get_files(c):
		row = [0] * len(dc)
		fc=get_criterions(c, fid)
		for crit in fc:
			row[dc.index(crit)]=fc[crit]

		ar.append(row)

		if isMalicious(c, fid):
			targets.append(1)
		else:
			targets.append(0)

	data['data']=ar
	data['targets']=targets
	
	return data

def build_dataset(d):
	db = sqlite3.connect(d)
	c = db.cursor()
	
	dataset={}
	dataset['features_names'] = get_default_criterion(c)
	dataset['data'] = (get_data(c))['data']
	dataset['targets'] = (get_data(c))['targets']
	dataset['description'] = "Automatic built dataset based on malware samples from the web application. Features are criterions to define if it is malicious or not"

	db.close()

	return dataset