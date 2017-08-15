'''
Created on 15 juil. 2017

@author: Gregory
'''
import sqlite3
import requests
import os
import shutil
import time
import yaml
import argparse

from MachineLearning import build_dataset, RandomForest, Bayesian, figure_feature_importances, feature_importances
from PEFileAnalyzer import peData

config = yaml.load(open('config.yml', 'r'))

def machineLearning(dbname):
	try:
		print("Building dataset...")
		dataset = build_dataset(dbname)
		rf = RandomForest(dataset, 10, 'gini', True, True)
		feature_importances(rf, dataset['features_names'])
		print("nb of samples: "+str(len(dataset['data'])))
		# plt=figure_feature_importances(rf, dataset['features_names'])
		# plt.show()
	except Exception as e:
		print("Error: "+str(e))

def purgeDB(dbname):
	try:
		db = sqlite3.connect(dbname)
		c = db.cursor()

		l=[]

		c.execute("SELECT name FROM sqlite_master WHERE type='table';")

		for t in c.fetchall():
			l+=t

		for t in l:
			if 'sqlite' in t:
				continue
			elif 'classification' not in t:
				print("Deleting "+t+ " table...")
				c.execute("DROP TABLE IF EXISTS %s" % t)
		
		db.commit()

		db.close()
		print("Success !")

	except Exception as e:
		print("Failed: "+str(e)+"....")

def uploadFile(f):
	start = time.clock()
	print("Uploading \""+f+"\" ...")
	base_url = config['HOST']
	client = requests.session()
	client.get(base_url)
	
	headers={'Referer':base_url+'add/'}
	files={'f':open(f, 'rb')}
	data={'csrfmiddlewaretoken':client.cookies['csrftoken'], 'Content-Type':'multipart/form-data'}

	r = client.post(base_url+'add/', headers=headers, data=data, files=files)

	if r.ok:
		if "files/details" in r.text:
			print(f+" has been uploaded...")
		else:
			print("Error was redirected to / for "+f)
	else:
		print("### ERROR during upload process of "+f+" ###")

def analyzeFile(f):
	mal=0
	coefTot=0
	ana = peData(f,os.environ['VIRTUAL_ENV']+'/../WebApp/MalwareAnalysis/userdb.txt')
	
	print("Analyze is running...\n")
	
	crit = ana.getCriterions()
	for c in crit:
		p=crit[c]
		print(p['name']+": "+str(round(p['score'], 2))+"/10 (coeff "+str(p['coef'])+")")
		mal+=p['score']*p['coef']
		coefTot+=p['coef']
	print("\nTotal: "+str(round(mal,2))+" ("+str(round(mal/coefTot,2))+"/10)")

def main(dbname, old_db, DIR):	
	try:
		
		for f in os.listdir(DIR):
			start = time.clock()
			uploadFile(DIR+"/"+f)
			print("("+str(round(time.clock()-start,3))+"s)\n\n")
			time.sleep(5)
		
		shutil.copy2(old_db, dbname)
		purgeDB(dbname)
		print("Database purged...\nEnd of process...")
			
	except Exception as e:
		print("Error: "+str(e))
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Performing actions (database, machine learning, uploads,...)")

    parser.add_argument("-u", "--upload", nargs=1, metavar="PATH", help="perform uploads from PATH location (-d and --original-db required)")
    parser.add_argument("--originaldb", nargs=1, metavar="DB_PATH", help="selecting a database to copy")
    parser.add_argument("-p", "--purge", help="purge db (required -d)", action="store_true")
    parser.add_argument("-d", "--database", nargs=1, metavar="DB_PATH", help="selecting database")
    parser.add_argument("-ml", "--mLearning", action="store_true", help="bulding dataset and machine learning model (requires -d)")
    parser.add_argument("-f", "--file", nargs=1, metavar="FILE", help="perfom PEAnalysis")

    args = parser.parse_args()

    if args.purge:
    	
    	if args.database:
    		print("Purging database "+str(args.database[0])+"...")
    		purgeDB(args.database[0])
    	
    	else:
    		print("Missing database name...")
    
    elif args.upload:
    	
    	if args.database:
    		
    		if args.originaldb:
    			print("Performing Uploads from \""+str(args.upload[0])+"\" ... ("+str(args.originaldb[0])+" --> "+str(args.database[0])+")\n")
    			main(args.database[0], args.originaldb[0], args.upload[0])
    		else:
    			print("Missing original db PATH")
    	
    	else:
    		print("Missing new db PATH")
    
    elif args.mLearning:
    	
    	if args.database:
    		machineLearning(args.database[0])
    	
    	else:
    		print("Missing database PATH")

    elif args.file:
    	analyzeFile(args.file[0])

