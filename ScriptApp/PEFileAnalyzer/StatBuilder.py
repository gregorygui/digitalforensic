from statistics import mean, pvariance, mode

class StatBuilder(object):
    """docstring for StatBuilder"""
    def __init__(self, s):
        super(StatBuilder, self).__init__()
        self.stat = s
    
    def fileStatistics(self):
        d=dict()
        
        d['Total']=self.stat['f']
        d['Malware']=str(self.stat['m'])+' ('+str(round(self.stat['m']*100/self.stat['f'], 2))+'%)'
        d['Safe']=str(self.stat['s'])+' ('+str(round(self.stat['s']*100/self.stat['f'], 2))+'%)'
        
        return d

    def structStatistics(self):
        d=dict()

        d['Mean Size']=str(round(mean(self.stat['size'])))+' bytes'

        d['Mean Number of Sections']=round(mean(self.stat['nbsect']))

        d['Nb of Packed']=str(self.stat['pack'])+' ('+str(round(self.stat['pack']*100/self.stat['f'], 2))+'%)'

        return d

    def malStatistics(self):
        d=dict()
        s=self.stat['mal']

        d['Mean']=round(mean(s), 2)
        d['Variance']=round(pvariance(s), 2)
        d['Min']=min(s)
        d['Max']=max(s)
        d['Mode']=round(max(set(s),key=s.count), 2)

        return d

    def anaStatistics(self):
        d=dict()

        return d

    def learningStatistics(self):
        d=dict()

        return d

    def durStatistics(self):
        d=dict()

        s=self.stat['dur']

        d['Mean']=str(round(mean(s), 2))+'s'
        d['Variance']=str(round(pvariance(s), 2))+'s'
        d['Min']=str(min(s))+'s'
        d['Max']=str(max(s))+'s'
        d['Mode']=str(round(mode(s), 2))+'s'

        return d