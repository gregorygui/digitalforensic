from django.conf.urls import url

from . import views

from .chartsBuilding import ChartIndex

app_name= 'classification'
urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^informations/$', views.informations, name='informations'),

    url(r'^parameters/$', views.parameters, name='parameters'),
    url(r'^parameters/criterions/$', views.parametersCriterions, name='parametersCriterions'),
    url(r'^parameters/malware_decision/$', views.parametersLearning, name='parametersLearning'),
    url(r'^parameters/malware_decision/train/$', views.performTraining, name='performTraining'),

    url(r'^virustotal/$', views.virusTotal, name='virusTotal'),
    url(r'^virustotal/analyze/$', views.analyzeVT, name='analyzeVT'),

    url(r'^add/$', views.addNewFiles, name='addNewFiles'),
    url(r'^files/$', views.filesView, name='filesView'),
    url(r'^malwares/$', views.malwaresView, name='malwaresView'),
    url(r'^files/details/(?P<file_hash>[a-z0-9]{32})/$', views.fileDetails, name='fileDetails'),
    url(r'^files/details/(?P<file_hash>[a-z0-9]{32})/maliciousness/$', views.fileMaliciousness, name='fileMaliciousness'),
    url(r'^files/details/(?P<file_hash>[a-z0-9]{32})/delete/$', views.delFile, name='delFile'),

    url(r'^indexchart/$', view=ChartIndex.as_view(), name='ChartIndex')
    ]
