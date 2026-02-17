from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),  # homepage
    path('ai-check/', views.ai_check),
    path("dashboard-data/", views.dashboard_data, name="dashboard-data"),
    path('block-ip/', views.block_ip, name='block-ip'),
    path('unblock-ip/', views.unblock_ip, name='unblock-ip'),
    path('log-attack/', views.log_attack_detection, name='log-attack'),
    path('attack-statistics/', views.get_attack_statistics, name='attack-statistics'),
    path('settings/', views.settings, name='settings'),
    path('train-model/', views.train_ml_model, name='train-model'),
    path('model-status/', views.get_model_status, name='model-status'),

]