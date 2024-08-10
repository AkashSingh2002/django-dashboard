from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from modernize import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
# from django.utils.encoding import force_bytes, force_text
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import authenticate, login, logout
from . tokens import generate_token
from django.core.exceptions import ValidationError
import re

# Create your views here.
# def home(request):
#     return render(request, "authentication/index.html")

def page_not_found(request, exception=None):
    return redirect('home_or_dashboard')

def home_or_dashboard(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    else:
        return redirect('signin')

def signup(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == "POST":
        name = request.POST.get('name', '').strip()
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        
        # Check for empty fields
        if not name or not username or not email or not password:
            messages.error(request, "All fields are required!")
            return redirect('signup')
        
        # Check if email or username already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists! Please try a different email.")
            return redirect('signup')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists! Please try a different username.")
            return redirect('signup')
        
        # Validate username
        if not username.isalnum():
            messages.error(request, "Username must be alphanumeric!")
            return redirect('signup')
        
        # Validate password strength
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters long!")
            return redirect('signup')
        
        # Optionally: Use a regex to check for password complexity
        if not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
            messages.error(request, "Password must contain both letters and numbers!")
            return redirect('signup')
        
        # Create the user
        try:
            myuser = User.objects.create_user(username=username, email=email, password=password)
            myuser.first_name = name  # Use 'first_name' for the name field in User model
            myuser.save()
            messages.success(request, "Your account has been created successfully!")
            return redirect('signin')
        except ValidationError as e:
            messages.error(request, f"Error: {e}")
            return redirect('signup')
        
    return render(request, "dist/main/authentication-register.html")

from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import redirect, render

def signin(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        
        # Check for empty fields
        if not username or not password:
            messages.error(request, "Both username and password are required!")
            return redirect('signin')
        
        # Authenticate the user
        user = authenticate(username=username, password=password)
        
        if user is not None:
            login(request, user)
            messages.success(request, "Logged in successfully!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials. Please try again.")
            return redirect('signin')
    
    return render(request, "dist/main/authentication-login.html")



def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully!")
    return redirect('signin')

# View for the dashboard (index page)
def index(request):
    return render(request, "dist/main/index.html", {"name": request.user.username})