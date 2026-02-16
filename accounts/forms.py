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