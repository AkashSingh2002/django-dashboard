from django.contrib import admin
from django.urls import path, re_path, include
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    path('admin', admin.site.urls),  # Admin URL pattern
    path('signup', views.signup, name='signup'),
    path('', views.home_or_dashboard, name='home_or_dashboard'),  # Redirect based on authentication
    path('signin', views.signin, name='signin'),  # Separate signin URL
    path('signout', views.signout, name='signout'),
    path('dashboard', login_required(views.index, login_url='signin'), name='dashboard'),  # Protected dashboard
    re_path(r'^.*$', views.page_not_found),  # Catch-all pattern for undefined URLs
]

