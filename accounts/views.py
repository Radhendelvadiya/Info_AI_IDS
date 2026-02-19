from django.shortcuts import render, redirect
from django.contrib.auth import login
from .forms import RegisterForm
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .forms import AdminUserCreationForm
from django.contrib.auth import get_user_model
from accounts.models import UserProfile

User = get_user_model()

def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("login")
    else:
        form = RegisterForm()
    return render(request, "accounts/register.html", {"form": form})


class CustomLoginView(LoginView):
    template_name = "accounts/login.html"


@login_required
def user_management(request):
    """Admin view to create users with password and manage roles."""
    try:
        profile = UserProfile.objects.get(user=request.user)
        if profile.role != 'ADMIN':
            return render(request, 'accounts/settings_restricted.html', {'user_role': profile.role})
    except UserProfile.DoesNotExist:
        return render(request, 'accounts/settings_restricted.html', {'user_role': 'VIEWER'})

    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            return redirect('accounts:user-management')
    else:
        form = AdminUserCreationForm()

    users = User.objects.all().order_by('-date_joined')[:50]
    return render(request, 'accounts/user_management.html', {'form': form, 'users': users})