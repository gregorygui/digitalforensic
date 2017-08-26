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
	c.execute("SELECT ismal FROM classification_file WHERE id=?", t)
	m = (listTreatment(c))[0]

	return m

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

def notInTraining(c, nb):
	t=(nb, )
	c.execute("SELECT id FROM classification_file WHERE training=0 LIMIT ?", t)

	return (listTreatment(c))

def inTraining(c, nb):
	ct=0
	i=0
	t=(nb, )
	c.execute("SELECT id FROM classification_file LIMIT ?", t)
	l=listTreatment(c)
	
	for f in l:
		if not isMalicious(c, f):
			ct+=1

	c.execute("SELECT id FROM classification_file WHERE ismal=0")
	l2=listTreatment(c)
	l3=[x for x in l2 if x not in l]

	while (ct/len(l2)) < 0.5:
		l.append(l3[i])
		ct+=1
		i+=1
	
	for f in l:
		t=(f,)
		c.execute("UPDATE classification_file SET training=1 WHERE id=?", t)

	return l

def get_data2(c, l):
	dc = get_default_criterion(c)
	data = {}
	ar=[]
	targets = []

	for fid in l:
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


def build_dataset2(d, nb, t):

	db = sqlite3.connect(d)
	c = db.cursor()
	
	dataset={}
	dataset['features_names'] = get_default_criterion(c)

	if t:
		c.execute("UPDATE classification_file SET training = 0")
		listTreatment(c)
		data=get_data2(c, inTraining(c, nb))
	else:
		data=get_data2(c, notInTraining(c, nb))

	dataset['data'] = data['data']
	dataset['targets'] = data['targets']
	dataset['description'] = "Automatic built dataset based on malware samples from the web application. Features are criterions to define if it is malicious or not"

	db.close()

	return dataset

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