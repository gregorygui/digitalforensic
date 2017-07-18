import numpy as np

import matplotlib.pyplot as plt

from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import BernoulliNB

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

def RandomForest(ds):
	
	clf = RandomForestClassifier()

	clf.fit(ds['data'], ds['targets'])
	
	return clf

def Bayesian(ds):
	clf = BernoulliNB()

	clf.fit(ds['data'], ds['targets'])

	return clf