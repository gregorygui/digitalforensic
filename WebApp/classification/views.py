from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.conf import settings

from .forms import HashForm, URLForm, FileForm, AlgoRFForm, AlgoNBForm, StringsForm, IndexForm

from .models import File, FileImport, FileFct, FileSection, FileExport, FileCriterion, DefaultCriterion, DefaultStrings, Analysis

from PEFileAnalyzer import handle_uploaded_file, VTHash, VTUrl, VTFile, peData, defaultCriterions, StatBuilder
from MachineLearning import RandomForest, Bayesian, build_dataset, feature_importances

import os
import uuid
import time
import re
from decimal import Decimal

def makeDict(qset):
    d=dict()
    for q in qset:
        d[q.string]=q.imp
    return d

def index(request):
    tot=File.objects.all()
    
    if len(tot)>0:
        pct=len(File.objects.filter(ismal=True))*100/len(File.objects.all())
        pct=round(pct,2)
    else:
        pct=0

    context={
    'title':"Dashboard",
    'nbfiles':len(File.objects.all()),
    'nbmalwares':len(File.objects.filter(ismal=True)),
    'percentmal':pct,
    'form':IndexForm()
    }
    
    return render(request, 'classification/index.html', context)

def handle_file(f):
    filename='Uploads/'+str(uuid.uuid4())
    with open(os.path.join(settings.PROJECT_ROOT,filename), 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    destination.close()
    return filename

def updateDefaultCriterions():
    default=DefaultCriterion.objects.all()

    for d in default:
        crit=FileCriterion.objects.filter(name=d.name)
        
        if len(crit) != d.nbFiles:
            tot=0
            
            d.nbFiles=len(crit)
            d.nbMalwares=len(File.objects.filter(ismal=True).filter(filecriterion__name=d.name))
            
            for i in crit:
                tot+=i.score

            d.average=round(tot/(d.nbFiles+1), 2)
        
        d.save()

def addNewFiles(request):
    if request.method == 'POST':
        form=IndexForm(request.POST, request.FILES)
        files=request.FILES.getlist('f')

        if form.is_valid():
            for fi in files:
                start = time.clock()
                f=handle_file(fi)

                ana=peData(os.path.join(settings.PROJECT_ROOT, f), os.path.join(settings.PROJECT_ROOT, 'userdb.txt'), makeDict(DefaultStrings.objects.all()))
                md5=ana.getMD5()

                try:
                    File.objects.get(md5=md5)

                except:

                    file=File.objects.create(
                        name=fi.name,
                        md5=md5,
                        sha=ana.getSHA256(),
                        compile_date=ana.getDate(),
                        packer=ana.isPacked(),
                        entropy=ana.getEntropy(),
                        oep=ana.getOEP(),
                        size=ana.getSize(),
                        ismal=form.cleaned_data['mal']
                        )

                    file.save()

                    for key, value in ana.getSections().items():
                        file.filesection_set.create(name=key,va=value)

                    for key, value in ana.getImports().items():
                        file.fileimport_set.create(dll=key)
                        for v in value:
                            d=file.fileimport_set.get(dll=key)
                            d.filefct_set.create(function=v)

                    exports=ana.getExports()
                    if exports:
                        for value in exports:
                            file.fileexport_set.create(function=value)

                    for value in ana.getStrings():
                        file.filestrings_set.create(string=value)

                    coefTot=0
                    mal=0
                    crit=ana.getCriterions()

                    for c in crit:
                        val=crit[c]
                        DefaultCriterion.objects.get_or_create(name=val['name'])
                        file.filecriterion_set.create(name=val['name'], score=val['score'])
                        mal+=val['score']
                        coefTot+=1

                    if coefTot > 0:
                        file.maliciousness=round(mal/coefTot, 2)
                    else:
                        file.maliciousness=0

                    file.anaTime=round(time.clock()-start, 2)

                    file.save()
                    
                    try:
                        updateDefaultCriterions()
                    finally:
                        os.remove(os.path.join(settings.PROJECT_ROOT, f))   

            return redirect('classification:fileDetails', file_hash=md5)
        else:
            return HttpResponseRedirect('/')
    else:
        return HttpResponseRedirect('/')

def delFile(request, file_hash):
    file = File.objects.get(md5=file_hash)
    file.delete()
    return redirect('classification:list', action='files')

def delString(request, str_id):
    string = DefaultStrings.objects.get(id=str_id)
    update_strings(string.string, string.imp, 'neg')
    string.delete()
    return redirect('classification:parametersStrings')

def informations(request):
    return render(request, 'classification/informations.html', {'title':"Informations"})

def parameters(request):
    return render(request, 'classification/parameters.html', {'title':"Parameters"})

def stat():

    d=dict()
    lsize=[]
    lmal=[]
    lsect=[]
    ldur=[]
    nbPacked=0
    
    d['f']=len(File.objects.all())
    d['m']=len(File.objects.filter(ismal=True))
    d['s']=d['f']-d['m']

    for f in File.objects.all():
        lsize.append(f.size)

        if f.maliciousness > 0:
            lmal.append(f.maliciousness)
        
        lsect.append(len(f.filesection_set.all()))
        
        if f.anaTime > 0:
            ldur.append(f.anaTime)

        if ('None' or 'C++' or '.Net') not in f.packer:
            nbPacked+=1

    d['pack']=nbPacked

    d['size']=lsize
    d['mal']=lmal
    d['nbsect']=lsect
    d['dur']=ldur

    return d

def statistics(request):
    s=StatBuilder(stat())

    context={
    'title':'Application Statistics',
    'fstat':s.fileStatistics(),
    'structstat':s.structStatistics(),
    'malstat':s.malStatistics(),
    'durstat':s.durStatistics(),
    'astat':s.anaStatistics(),
    'lstat':s.learningStatistics()
    }

    return render(request, 'classification/statistics.html', context)

def results(request):
    context={
    'title':'Learning Results',
    'analysis':Analysis.objects.all().order_by('-date')
    }
    return render(request, 'classification/results.html', context)

def update_strings(val, imp, op):
    regex='(?:'+val+')'

    for f in File.objects.all():
        
        strTot=f.filestrings_set.all()
        
        for s in strTot:
            
            if re.match(regex, s.string, flags=re.IGNORECASE):

                crit=f.filecriterion_set.get_or_create(name='Malicious String(s)')

                if 'neg' in op:
                    (crit[0]).score-=Decimal(imp/len(DefaultStrings.objects.all()))
                elif 'pos' in op:
                    (crit[0]).score+=Decimal(imp/len(DefaultStrings.objects.all()))
                
                crit[0].save()
               
                v=0
                
                for c in f.filecriterion_set.all():
                    v+=c.score

                f.maliciousness=round(v/len(f.filecriterion_set.all()), 2)
                f.save()

                break

def parametersStrings(request):

    context={
    'title':'Malicious Strings Definition',
    'formStrings':StringsForm
    }

    if request.method == 'POST':
        formStr = StringsForm(request.POST)

        if formStr.is_valid():
            DefaultStrings.objects.get_or_create(string=formStr.cleaned_data['string'], imp=formStr.cleaned_data['imp'])
            update_strings(formStr.cleaned_data['string'], formStr.cleaned_data['imp'], 'pos')
            context['title']+=' - \"'+formStr.cleaned_data['string']+'\" was added...'

    context['strings']=DefaultStrings.objects.all().order_by('string')

    return render(request, 'classification/parametersStrings.html', context)

def parametersCriterions(request):

    context={
    'title':"Criterions",
    'criterions':DefaultCriterion.objects.all().order_by('-nbFiles')
    }

    return render(request, 'classification/parametersCriterions.html', context)

def parametersCriterionsDetails(request, id):

    context={
    'title':"Maliciousness Criterions Details",
    'files':File.objects.filter(filecriterion__id=id)
    }

    return render(request, 'classification/filesList.html', context)

def parametersLearning(request):
    if request.method == 'POST':

        formRF = AlgoRFForm(request.POST)
        formNB = AlgoNBForm(request.POST)
        dataset=build_dataset('db.sqlite3')
        context={
            'title':'Results - ',
            'samples':len(File.objects.all()),
            'crit':len(DefaultCriterion.objects.all())
        } 

        if formRF.is_valid():
            trees=formRF.cleaned_data['trees']
            criterion=formRF.cleaned_data['criterion']
            bootstrap=formRF.cleaned_data['bootstrap']
            weight = formRF.cleaned_data['weighted']
            start = time.clock()
            clf = RandomForest(dataset, trees, criterion, bootstrap, weight)
            context['title']+='Random Forest'
            context['fimp']=feature_importances(clf, dataset['features_names'])

            ana=Analysis.objects.create(
                        algoname='Random Forest',
                        args='Trees: '+str(trees)+', Bootstrap: '+str(bootstrap)+', Weighted: '+str(weight)+', Splitting: '+str(criterion),
                        files=len(dataset['data']),
                        duration=round(time.clock()-start, 2),
                        malware=len(dataset['data'])
                        )

            ana.save()
            
            context.update({'clf':clf})

            return render(request, 'classification/resultTraining.html', context)

        elif formNB.is_valid():
            alpha=formNB.cleaned_data['alpha']
            clf = Bayesian(dataset, alpha)
            context['title']+='Naive Bayes'

            context.update({'clf':clf})

            return render(request, 'classification/resultTraining.html', context)

    context={
    'title':"Learning Algorithm Parameters",
    'nbFiles':len(File.objects.all()),
    'nbSafe':len(File.objects.all())-len(File.objects.filter(ismal=True)),
    'nbMal':len(File.objects.filter(ismal=True)),
    'formRF':AlgoRFForm(),
    'formNB':AlgoNBForm()
    }

    return render(request, 'classification/parametersLearning.html', context)

def virusTotal(request):

    if request.method == 'POST':
        formH = HashForm(request.POST)
        formU = URLForm(request.POST)
        formF = FileForm(request.POST, request.FILES)
        
        name="Virus Total Results - "
        
        if formH.is_valid():
            h=formH.cleaned_data['h']
            name+=h
            return render(request, 'classification/analyzeVT.html', {'title':name, 'res':VTHash(h)})
       
        elif formU.is_valid():
            u=formU.cleaned_data['u']
            name+=u
            return render(request, 'classification/analyzeVT.html', {'title':name, 'res':VTUrl(u)})
        
        elif formF.is_valid():
            f=handle_uploaded_file(request.FILES['f'])
            return render(request, 'classification/analyzeVT.html', {'title':name, 'res':VTFile(f)})

    formU = URLForm()
    formH = HashForm()
    formF = FileForm()
    
    return render(request, 'classification/virusTotal.html', {'title':"Virus Total Toolkit", 'formhash':formH, 'formURL':formU, 'formfile':formF})

def listFiles(request, action):

    if action == 'malware':
        files = File.objects.filter(ismal=True).order_by('-added_date')
        
        context={
        'title':"Malware Profiles",
        'files':files
        }

        return render(request, 'classification/filesList.html', context)

    else:
        files = File.objects.all().order_by('-added_date')
        
        context={
        'title':"Last Analyses",
        'files':files
        }

        return render(request, 'classification/filesList.html', context)

def fileDetails(request, file_hash):
    file = File.objects.get(md5=file_hash)

    context={
    'title': "Details",
    'file': file,
    'sections': file.filesection_set.all(),
    'imports': file.fileimport_set.all(),
    'exports': file.fileexport_set.all(),
    'strings': file.filestrings_set.all()
    }

    return render(request, 'classification/fileDetails.html', context)

def fileMaliciousness(request, file_hash):
    file = File.objects.get(md5=file_hash)

    context={
    'title':file.name,
    'criterion':file.filecriterion_set.all(),
    'hash':file_hash
    }

    return render(request, 'classification/fileCriterion.html', context)