from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model

User = get_user_model()


class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # REMOVE DEFAULT DJANGO PASSWORD TEXT
        self.fields["password1"].help_text = ""
        self.fields["password2"].help_text = "Re-enter password for verification."

    def clean_email(self):
        """Validate that email is unique"""
        email = self.cleaned_data.get('email')
        
        if not email:
            raise forms.ValidationError("Email is required.")
        
        # Check if email already exists (case-insensitive)
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                "An account with this email already exists. Please use a different email or try logging in."
            )
        
        return email

    def clean_username(self):
        """Validate that username is unique"""
        username = self.cleaned_data.get('username')
        
        if not username:
            raise forms.ValidationError("Username is required.")
        
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError(
                "An account with this username already exists. Please use a different username."
            )
        
        return username


class AdminUserCreationForm(forms.ModelForm):
    """Form for admins to create a user and set a password directly."""
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput, required=True)
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput, required=True)
    role = forms.ChoiceField(label='Role', choices=[('ADMIN','Admin'),('ANALYST','SOC Analyst'),('VIEWER','Viewer')], required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')

    def clean_password2(self):
        p1 = self.cleaned_data.get('password1')
        p2 = self.cleaned_data.get('password2')
        if not p1 or p1 != p2:
            raise forms.ValidationError('Passwords do not match')
        return p2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.is_active = True
            user.save()
            # create or update profile role
            from .models import UserProfile
            UserProfile.objects.update_or_create(user=user, defaults={'role': self.cleaned_data.get('role', 'VIEWER')})
        return user