'''
Created on 15 juil. 2017

@author: Gregory
'''
import yaml

config=yaml.load(open('config.yml','r'))

BASE=config['SAMPLES_DIRECTORY']

def main():
    print(BASE)

if __name__ == '__main__':
    main()