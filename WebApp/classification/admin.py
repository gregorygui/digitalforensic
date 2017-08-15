from django.contrib import admin

# Register your models here.
from .models import File, FileSection, FileImport, FileExport, FileStrings, FileCriterion, DefaultCriterion, DefaultStrings, Analysis, AnalysisFigures

class FileSectionInline(admin.TabularInline):
	model=FileSection
	extra=3

#admin.site.register(FileSection, FileSectionAdmin)

class FileImportInline(admin.TabularInline):
	model=FileImport
	extra=1

#admin.site.register(FileImport, FileImportAdmin)

class FileExportInline(admin.TabularInline):
	model=FileExport
	extra=1

#admin.site.register(FileExport, FileExportAdmin)

class FileStringsInline(admin.TabularInline):
	model=FileStrings
	extra=3

#admin.site.register(FileStrings, FileStringsAdmin)

class FileCriterionInline(admin.TabularInline):
	model=FileCriterion
	extra=2

#admin.site.register(FileStrings, FileStringsAdmin)

class FileAdmin(admin.ModelAdmin):
	list_display=('name', 'md5', 'size', 'anaTime', 'added_date', 'isMalicious')
	list_filter=('added_date', 'maliciousness')
	inlines=[FileSectionInline, FileImportInline, FileExportInline, FileCriterionInline, FileStringsInline]

admin.site.register(File, FileAdmin)

class DefaultCriterionAdmin(admin.ModelAdmin):
	list_display=('name', 'coef', 'average')

admin.site.register(DefaultCriterion, DefaultCriterionAdmin)

class DefaultStringsAdmin(admin.ModelAdmin):
	list_display=('string', 'imp')
	list_filter=('string', 'imp')

admin.site.register(DefaultStrings, DefaultStringsAdmin)

class AnalysisFiguresInline(admin.TabularInline):
	model=AnalysisFigures
	extra=2

#admin.site.register(FileStrings, FileStringsAdmin)

class AnalysisAdmin(admin.ModelAdmin):
	list_display=('date', 'algoname', 'args', 'duration')
	list_filter=('algoname', 'date')
	inlines=[AnalysisFiguresInline]

admin.site.register(Analysis, AnalysisAdmin)