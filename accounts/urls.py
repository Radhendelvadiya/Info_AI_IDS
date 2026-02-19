from django.urls import path
from .views import register, CustomLoginView
from django.contrib.auth.views import LoginView, LogoutView
from .views import user_management

urlpatterns = [
    path("register/", register, name="register"),
    path("login/", LoginView.as_view(template_name="accounts/login.html"), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("user-management/", user_management, name="user-management"),
]
