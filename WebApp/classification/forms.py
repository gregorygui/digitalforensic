from django import forms

class HashForm(forms.Form):
	h = forms.CharField(label='value',
		max_length=32,
		widget=forms.TextInput(attrs={'class': 'form-control','placeholder': '79054025255fb1a26e4bc422aef54eb4'})
		)

class URLForm(forms.Form):
	u = forms.URLField(label='url',
		max_length=400,
		widget=forms.TextInput(attrs={'class': 'form-control','placeholder':'https://google.com'}))

class FileForm(forms.Form):
	f = forms.FileField(widget=forms.ClearableFileInput())

class IndexForm(forms.Form):
	f = forms.FileField(widget=forms.ClearableFileInput(attrs={'multiple': True}))
	mal = forms.BooleanField(label='Malicious',
		required=False,
		initial=False)

class SamplesForm(forms.Form):
	training=forms.IntegerField(label='Number os samples for training', initial=25, min_value=10, max_value=2000, widget=forms.TextInput(attrs={'class':'form-control'}))
	testing=forms.IntegerField(label='Number os samples for testing', initial=25, min_value=10, max_value=2000, widget=forms.TextInput(attrs={'class':'form-control'}))

class AlgoRFForm(SamplesForm):
	trees = forms.IntegerField(label='Number of trees',
		initial=10,
		min_value=1,
		max_value=1000,
		widget=forms.TextInput(attrs={'class':'form-control'}))
	#max_depth = forms.IntegerField(label='Max Depth', min_value=1, max_value=1000)
	CHOICES = (
		('gini', 'Gini'),
		('entropy', 'Entropy'))
	criterion = forms.ChoiceField(label='Function to measure the quality of a split', choices=CHOICES)
	bootstrap = forms.BooleanField(label='Bootstrap', required=False, initial=True)
	weighted = forms.BooleanField(label='Weighted', required=False, initial=True)

class AlgoNBForm(SamplesForm):
	alpha = forms.FloatField(label='Additive smoothing parameter (alpha)', initial=1.0, min_value=0, max_value=10.0, widget=forms.TextInput(attrs={'class':'form-control'}))

class StringsForm(forms.Form):
	string = forms.CharField(label='string',
		max_length=300,
		widget=forms.TextInput(attrs={'class': 'form-control','placeholder': 'malicious string'}))
	imp = forms.FloatField(label='Importance',
		max_value=10.0,
		min_value=0.0)