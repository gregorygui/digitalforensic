from django.db import models
from datetime import time

# Create your models here.

class File(models.Model):
	name=models.CharField(max_length=150)
	md5=models.CharField(max_length=32, unique=True)
	sha=models.CharField(max_length=64)
	packer=models.CharField(max_length=250, null=True)
	compile_date=models.DateTimeField()
	added_date=models.DateTimeField(auto_now_add=True)
	maliciousness=models.DecimalField(max_digits=3, decimal_places=2, default=0)
	entropy=models.DecimalField(max_digits=4, decimal_places=2, default=0)
	oep=models.IntegerField(default=0)
	size=models.IntegerField(default=0)
	anaTime=models.DecimalField(max_digits=4, decimal_places=2, default=0)

	def isPacked(self):
		return (packer!=null)

	def isMalicious(self):
		return self.maliciousness>6
	
	isMalicious.boolean = True
	isMalicious.short_description = 'Is Malicious?'

	def __str__(self):
		return self.name

class FileSection(models.Model):
	file=models.ForeignKey(File, on_delete=models.CASCADE)
	name=models.CharField(max_length=20)
	va=models.IntegerField(default=40000)

	def __str__(self):
		return self.name

class FileImport(models.Model):
	file=models.ForeignKey(File, on_delete=models.CASCADE)
	dll=models.CharField(max_length=250)
	mal=models.BooleanField(default=False)

class FileFct(models.Model):
	dll=models.ForeignKey(FileImport, on_delete=models.CASCADE)
	function=models.CharField(max_length=250)
	mal=models.BooleanField(default=False)

class FileExport(models.Model):
	file=models.ForeignKey(File, on_delete=models.CASCADE)
	function=models.CharField(max_length=250)

class FileStrings(models.Model):
	file=models.ForeignKey(File, on_delete=models.CASCADE)
	string=models.CharField(max_length=400)
	mal=models.BooleanField(default=False)

class FileCriterion(models.Model):
	file=models.ForeignKey(File, on_delete=models.CASCADE)
	name=models.CharField(max_length=100)
	score=models.DecimalField(max_digits=4, decimal_places=2, default=0)
	coef=models.PositiveSmallIntegerField(default=0)

class DefaultCriterion(models.Model):
	name=models.CharField(max_length=100)
	coef=models.PositiveSmallIntegerField(default=0)
	average=models.DecimalField(max_digits=4, decimal_places=2, default=0)
	nbFiles=models.PositiveSmallIntegerField(default=0)
	nbMalwares=models.PositiveSmallIntegerField(default=0)

class DefaultStrings(models.Model):
	string=models.CharField(max_length=400)
	imp=models.FloatField(default=1.0)
	average=models.DecimalField(max_digits=4, decimal_places=2, default=0)
	nbFiles=models.PositiveSmallIntegerField(default=0)
	nbMalwares=models.PositiveSmallIntegerField(default=0)