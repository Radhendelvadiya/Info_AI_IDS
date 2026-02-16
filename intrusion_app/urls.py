from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),  # homepage
    path('ai-check/', views.ai_check),
    path("dashboard-data/", views.dashboard_data, name="dashboard-data"),
    path('block-ip/', views.block_ip, name='block-ip'),
    path('unblock-ip/', views.unblock_ip, name='unblock-ip'),

]