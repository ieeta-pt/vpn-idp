from django import forms

class Oauth2ImplicitTokenForm(forms.Form):
    oauth2_token = forms.CharField(label='token', widget=forms.HiddenInput(), max_length=100)
