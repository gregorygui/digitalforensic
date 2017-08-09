from django import forms

class HashForm(forms.Form):
	h = forms.CharField(label='value',max_length=32,widget=forms.TextInput(attrs={'class': 'form-control','placeholder': '79054025255fb1a26e4bc422aef54eb4'}))

class URLForm(forms.Form):
	u = forms.URLField(label='url',max_length=400,widget=forms.TextInput(attrs={'class': 'form-control','placeholder':'https://google.com'}))

class FileForm(forms.Form):
	f = forms.FileField(widget=forms.ClearableFileInput(attrs={'multiple': True}))

class AlgoRFForm(forms.Form):
	trees = forms.IntegerField(label='Number of trees', initial=10, min_value=1, max_value=1000, widget=forms.TextInput(attrs={'class':'form-control'}))
	#max_depth = forms.IntegerField(label='Max Depth', min_value=1, max_value=1000)
	CHOICES = (
		('GINI', 'Gini'),
		('ENTROPY', 'Entropy'))
	criterion = forms.ChoiceField(label='Function to measure the quality of a split', choices=CHOICES, required=True)
	bootstrap = forms.BooleanField(label='Bootstrap', initial=True)

class AlgoNBForm(forms.Form):
	alpha = forms.FloatField(label='Additive smoothing parameter', initial=1.0, min_value=0.0, max_value=10.0, widget=forms.TextInput(attrs={'class':'form-control'}))