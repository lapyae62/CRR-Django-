"""
Definition of urls for Crime_Report___Record_System.
"""

from datetime import datetime
from django.urls import path
from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from app import forms, views
from django.urls import path
from app.views import CustomLoginView

urlpatterns = [
    path('', views.home, name='home'),
    path('contact/', views.contact, name='contact'),
    path('about/', views.about, name='about'),
    path('report_crime', views.report_crime, name='report_crime'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(next_page='/'), name='logout'),
    path('admin/', admin.site.urls),

    path('admin_reports/', views.admin_reports, name='admin_reports'),
    path("admin_users/", views.admin_users, name="admin_users"),
    path("edit_user/", views.edit_user, name="edit_user"),
    path("delete_user/", views.delete_user, name="delete_user"),
    path("admin_requests/", views.admin_requests, name="admin_requests"),
    path("user_dashboard/", views.user_dashboard, name="user_dashboard"),
    path('regional_reports/', views.regional_reports, name='regional_reports'),
    path('assign_case/', views.assign_case, name='assign_case'),
    path('status_change_requests/', views.status_change_requests, name='status_change_requests'),
    path('process_change_request/<str:request_type>/<int:request_id>/<str:action>/', views.process_change_request, name='process_change_request'),
    path('user_profile/', views.user_profile, name='user_profile'),
    path('request_region_change/', views.request_region_change, name='request_region_change'),
    path('request_rank_change/', views.request_rank_change, name='request_rank_change'),
    path('user_dashborad1/', views.user_dashboard1, name='user_dashboard1'),
    path('regional_reports1/', views.regional_reports1, name='regional_reports1'),
    path('assigned_cases/', views.assigned_cases, name='assigned_cases'),
    path('manage_cases/', views.manage_cases, name='manage_cases'),
    path('update_case/<int:case_id>/', views.update_case, name='update_case'),
    path('user_profile1/', views.user_profile1, name='user_profile1'),
]
