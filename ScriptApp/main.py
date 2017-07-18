'''
Created on 15 juil. 2017

@author: Gregory
'''
import yaml

from MachineLearning import build_dataset, RandomForest, Bayesian

config=yaml.load(open('config.yml','r'))

BASE=config['SAMPLES_DIRECTORY']

def main():
    dataset = build_dataset('samples.sqlite3')
    algo1 = RandomForest(dataset)
    print(algo1)
    algo2 = Bayesian(dataset)
    print(algo2)
    
if __name__ == '__main__':
    main()