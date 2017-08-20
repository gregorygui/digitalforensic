from django.conf.urls import url

from . import views

from .chartsBuilding import ChartIndex

app_name= 'classification'

urlpatterns = [

    url(r'^$', views.index, name='index'),
    url(r'^informations/$', views.informations, name='informations'),
    url(r'^statistics/$', views.statistics, name='statistics'),
    url(r'^results/$', views.results, name='results'),

    url(r'^parameters/$', views.parameters, name='parameters'),
    url(r'^parameters/criterions/$', views.parametersCriterions, name='parametersCriterions'),
    
    url(r'^parameters/learning/$', views.parametersLearning, name='parametersLearning'),
    
    url(r'^parameters/strings/$', views.parametersStrings, name='parametersStrings'),
    url(r'^parameters/strings/delete/(?P<str_id>[0-9]+)$', views.delString, name='delString'),

    url(r'^virustotal/$', views.virusTotal, name='virusTotal'),

    url(r'^add/$', views.addNewFiles, name='addNewFiles'),

    url(r'^list/(?P<action>(?:malware)|(?:files))/$', views.listFiles, name='list'),
    
    url(r'^files/details/(?P<file_hash>[a-z0-9]{32})/$', views.fileDetails, name='fileDetails'),
    url(r'^files/details/(?P<file_hash>[a-z0-9]{32})/maliciousness/$', views.fileMaliciousness, name='fileMaliciousness'),
    url(r'^files/details/(?P<file_hash>[a-z0-9]{32})/delete/$', views.delFile, name='delFile'),

    url(r'^indexchart/$', view=ChartIndex.as_view(), name='ChartIndex')
    
    ]
