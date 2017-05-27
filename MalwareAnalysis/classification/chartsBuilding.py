from highcharts.views import HighChartsMultiAxesView
from datetime import date, timedelta

from .models import File

class ChartIndex(HighChartsMultiAxesView):

	now = date.today()
	
	title='Weekly new Files'
	subtitle='How the app lives'
	chart_type='area'
	credits={'enabled':'false'}

	categories=[]
	safe=[]
	mal=[]
	# for i in range(0,8):
	# 	d=now-timedelta(days=i)
	# 	f=File.objects.filter(added_date=d)
	# 	categories.append(d.strftime('%m%d'))
	# 	safe.append(len(f))
	# 	mal.append(len(f.filter(malware=True)))

	tooltip={
	'shared':'true', 
	'valueSuffix': ' files'
	}

	legend={
	'layout': 'vertical',
  	'align': 'right',
  	'verticalAlign': 'middle',
  	'borderWidth': 0
	}

	@property
	def yaxis(self):
		y_axis=[
		]

		return y_axis

	@property
	def series(self):
		series=[
		{'name':'Safe',
		'data':self.safe},
		{'name':'Malwares',
		'data':self.mal}
		]

		return series