import numpy as np

import matplotlib.pyplot as plt

from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier

def figure_feature_importances(clf, features):
	plt.figure()
	plt.title("Features Importances")

	importances = clf.feature_importances_
	indices = np.argsort(importances)[::-1]

	for f in range(len(features)):
		print("%d. feature %d (%f)" % (f + 1, indices[f], importances[indices[f]]))

	plt.bar(range(len(features)), importances[indices], color='r', align="center")	
	plt.xticks(range(len(features)), indices)

	return plt


def main():
	iris = load_iris()

	features = iris['feature_names']
	iris_data = iris['data']
	print(iris_data)
	iris_target = iris['target']
	
	clf = RandomForestClassifier()

	clf.fit(iris_data, iris_target)
	fig = figure_feature_importances(clf, features)
	
	#fig.show()
	

if __name__ == '__main__':
 	main() 