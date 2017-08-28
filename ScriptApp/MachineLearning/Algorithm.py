import numpy as np

import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import BernoulliNB

from operator import itemgetter

from math import sqrt

def figure_feature_importances(clf, features):
	plt.figure()
	plt.title("Features Importances")

	importances = clf.feature_importances_
	indices = np.argsort(importances)[::-1]
	
	for f in range(len(features)):
		print("%d. feature %d - %s (%f)" % (f + 1, indices[f], features[indices[f]], importances[indices[f]]))

	plt.bar(range(len(features)), importances[indices], color='r', align="center")	
	plt.xticks(range(len(features)), indices)

	return plt

def feature_importances(clf, features):
	d=dict()
	importances = clf.feature_importances_
	indices = np.argsort(importances)[::-1]
	
	for f in range(len(features)):
		d[features[indices[f]]]=round(importances[indices[f]]*100, 2)
		#print("%d. feature %d - %s (%f)" % (f + 1, indices[f], features[indices[f]], importances[indices[f]]))

	return sorted(d.items(), key=itemgetter(1), reverse=True)

def RandomForest(ds,t,c,b,w):
	clf = RandomForestClassifier(n_estimators=t, criterion=c, bootstrap=b, max_depth=int(sqrt(len(ds['data']))))
	
	if w:
		clf.set_params(class_weight='balanced')

	clf.fit(ds['data'], ds['targets'])
	
	return clf

def Bayesian(ds, a):
	clf = BernoulliNB(alpha=a)

	clf.fit(ds['data'], ds['targets'])

	return clf