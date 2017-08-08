from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.conf import settings

from .forms import HashForm, URLForm, FileForm, AlgoSVMForm

from .models import File, FileImport, FileSection, FileExport, FileCriterion, DefaultCriterion

from PEFileAnalyzer import handle_uploaded_file, VTHash, VTUrl, VTFile, peData, defaultCriterions

import os
import uuid


def index(request):
    tot=File.objects.all()
    
    if len(tot)>0:
        pct=len(File.objects.filter(maliciousness__gt=6))*100/len(File.objects.all())
        pct=round(pct,2)
    else:
        pct=0

    context={
    'title':"Dashboard",
    'nbfiles':len(File.objects.all()),
    'nbmalwares':len(File.objects.filter(maliciousness__gt=6)),
    'percentmal':pct,
    'form':FileForm()
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
            d.nbMalwares=len(File.objects.filter(maliciousness__gt=6).filter(filecriterion__name=d.name))
            
            for i in crit:
                tot+=i.score

            d.average=round(tot/(d.nbFiles+1), 2)
        
        d.save()

def addNewFiles(request):
    if request.method == 'POST':
        form=FileForm(request.POST, request.FILES)
        files=request.FILES.getlist('f')

        if form.is_valid():
            for fi in files:
                f=handle_file(fi)

                ana=peData(os.path.join(settings.PROJECT_ROOT, f), os.path.join(settings.PROJECT_ROOT, 'userdb.txt'))
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
                        oep=ana.getOEP()
                        )

                    file.save()

                    for key, value in ana.getSections().items():
                        file.filesection_set.create(name=key,va=value)

                    for key, value in ana.getImports().items():
                        file.fileimport_set.create(dll=key, function=value)

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
                        file.filecriterion_set.create(name=val['name'], score=val['score'], coef=val['coef'])
                        mal+=val['score']*val['coef']
                        coefTot+=val['coef']

                    if coefTot > 0:
                        file.maliciousness=round(mal/coefTot, 2)
                    else:
                        file.maliciousness=0

                    file.save()

                    updateDefaultCriterions()

                    os.remove(os.path.join(settings.PROJECT_ROOT, f))   

            return redirect('classification:fileDetails', file_hash=md5)
        else:
            return HttpResponseRedirect('/')
    else:
        return HttpResponseRedirect('/')

def delFile(request, file_hash):
    file = File.objects.get(md5=file_hash)
    file.delete()
    return redirect('classification:filesView')

def informations(request):
    return render(request, 'classification/informations.html', {'title':"Informations"})

def parameters(request):
    return render(request, 'classification/parameters.html', {'title':"Parameters"})

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

    context={
    'title':"Learning Algorithm Parameters",
    'nbFiles':len(File.objects.all()),
    'nbSafe':len(File.objects.filter(maliciousness__lt=4)),
    'nbSusp':len(File.objects.filter(maliciousness__gt=4).filter(maliciousness__lt=6)),
    'nbMal':len(File.objects.filter(maliciousness__gt=6)),
    'formAlgo':AlgoSVMForm()
    }

    return render(request, 'classification/parametersLearning.html', context)

def virusTotal(request):
    formU = URLForm()
    formH = HashForm()
    formF = FileForm()
    return render(request, 'classification/virusTotal.html', {'title':"Virus Total Toolkit", 'formhash':formH, 'formURL':formU, 'formfile':formF})

def analyzeVT(request):
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
        
        else:
        	return HttpResponseRedirect('/')
    else:
    	return HttpResponseRedirect('/')

def malwaresView(request):
    files = File.objects.filter(maliciousness__gt=6).order_by('-added_date')
    context={
    'title':"Malware Profiles",
    'files':files
    }
    return render(request, 'classification/filesList.html', context)

def filesView(request):
    files = File.objects.all().order_by('-added_date')[:10]
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