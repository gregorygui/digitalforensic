from django import forms

class HashForm(forms.Form):
	h = forms.CharField(label='value',max_length=32,widget=forms.TextInput(attrs={'class': 'form-control','placeholder': '79054025255fb1a26e4bc422aef54eb4'}))

class URLForm(forms.Form):
	u = forms.URLField(label='url',max_length=400,widget=forms.TextInput(attrs={'class': 'form-control','placeholder':'https://google.com'}))

class FileForm(forms.Form):
	f = forms.FileField(widget=forms.ClearableFileInput(attrs={'multiple': True}))

class AlgoSVMForm(forms.Form):
	C = forms.FloatField(label='Penalty parameter C',initial=1.0,min_value=0.00001,max_value=100,widget=forms.TextInput(attrs={'class':'form-control'}))
	iterations = forms.IntegerField(label='Number of iterations', initial=1000, min_value=100, max_value=1000000, widget=forms.TextInput(attrs={'class':'form-control'}))
