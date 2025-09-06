# Django Backend System Analysis for Portfolio Website

## 1. Website Analysis

### Current Website Structure
The portfolio website is a single-page application featuring:
- Hero section with personal introduction
- About section with profile information
- Skills section with technical competencies
- Projects showcase with filtering
- Education timeline
- Contact information and form
- Newsletter subscription
- Social media links

### Key Features Requiring Backend Support
1. **Contact Form Processing**
2. **Newsletter Subscription Management**
3. **Project Portfolio Management**
4. **Skills & Education Management**
5. **Admin Authentication & User Management**
6. **Content Management System**
7. **Analytics & Visitor Tracking**
8. **File Upload (CV, Project Images)**

## 2. Django Backend Architecture

### 2.0 Authentication System

```python
# authentication/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid

class CustomUser(AbstractUser):
    """Extended User model with additional fields"""
    USER_TYPES = [
        ('admin', 'Administrator'),
        ('editor', 'Content Editor'),
        ('viewer', 'Viewer'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    user_type = models.CharField(max_length=20, choices=USER_TYPES, default='viewer')
    profile_image = models.ImageField(upload_to='admin_profiles/', null=True, blank=True)
    phone = models.CharField(max_length=15, blank=True)
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.UUIDField(default=uuid.uuid4, unique=True)
    password_reset_token = models.UUIDField(null=True, blank=True)
    password_reset_expires = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']
    
    class Meta:
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.get_full_name()} ({self.email})"
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration"""
        self.account_locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save()
    
    def unlock_account(self):
        """Unlock account and reset failed attempts"""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save()
    
    def can_manage_content(self):
        """Check if user can manage content"""
        return self.user_type in ['admin', 'editor'] and self.is_active
    
    def is_admin(self):
        """Check if user is admin"""
        return self.user_type == 'admin' and self.is_active

class LoginAttempt(models.Model):
    """Track login attempts for security"""
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=100, blank=True)
    attempted_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-attempted_at']
        indexes = [
            models.Index(fields=['email', 'attempted_at']),
            models.Index(fields=['ip_address', 'attempted_at']),
        ]

class UserSession(models.Model):
    """Track active user sessions"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-last_activity']
```

```python
# authentication/forms.py
from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordResetForm
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import CustomUser
import re

class CustomLoginForm(AuthenticationForm):
    """Custom login form with enhanced security"""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autofocus': True
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password'
        })
    )
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    def __init__(self, request=None, *args, **kwargs):
        super().__init__(request, *args, **kwargs)
        # Remove username field and use email instead
        if 'username' in self.fields:
            del self.fields['username']
    
    def clean(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')
        
        if email and password:
            # Check if user exists
            try:
                user = CustomUser.objects.get(email=email)
                
                # Check if account is locked
                if user.is_account_locked():
                    raise ValidationError(
                        "Account is temporarily locked due to multiple failed login attempts. "
                        "Please try again later."
                    )
                
                # Authenticate user
                self.user_cache = authenticate(
                    self.request,
                    username=email,
                    password=password
                )
                
                if self.user_cache is None:
                    # Increment failed attempts
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= 5:
                        user.lock_account(30)  # Lock for 30 minutes
                    user.save()
                    
                    raise ValidationError("Invalid email or password.")
                else:
                    # Reset failed attempts on successful login
                    if user.failed_login_attempts > 0:
                        user.failed_login_attempts = 0
                        user.save()
                    
                    self.confirm_login_allowed(self.user_cache)
                    
            except CustomUser.DoesNotExist:
                raise ValidationError("Invalid email or password.")
        
        return self.cleaned_data

class CustomUserCreationForm(UserCreationForm):
    """Custom user creation form"""
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    first_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    last_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    user_type = forms.ChoiceField(
        choices=CustomUser.USER_TYPES,
        required=True,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'user_type', 'password1', 'password2')
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email
    
    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        
        # Custom password validation
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one digit.")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("Password must contain at least one special character.")
        
        return password

class CustomPasswordResetForm(PasswordResetForm):
    """Custom password reset form"""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address'
        })
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not CustomUser.objects.filter(email=email, is_active=True).exists():
            raise ValidationError("No active user found with this email address.")
        return email
```

```python
# authentication/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib import messages
from django.views.generic import TemplateView, FormView
from django.urls import reverse_lazy, reverse
from django.http import JsonResponse, HttpResponseRedirect
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.contrib.sessions.models import Session
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import CustomUser, LoginAttempt, UserSession
from .forms import CustomLoginForm, CustomUserCreationForm, CustomPasswordResetForm
import uuid
import logging

logger = logging.getLogger(__name__)

def is_admin(user):
    """Check if user is admin"""
    return user.is_authenticated and user.is_admin()

def can_manage_content(user):
    """Check if user can manage content"""
    return user.is_authenticated and user.can_manage_content()

class AdminLoginView(FormView):
    """Admin login view with enhanced security"""
    template_name = 'authentication/login.html'
    form_class = CustomLoginForm
    success_url = reverse_lazy('admin_dashboard')
    
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(self.success_url)
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        user = form.get_user()
        
        # Log successful login attempt
        LoginAttempt.objects.create(
            email=user.email,
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        # Login user
        login(self.request, user)
        
        # Update last login IP
        user.last_login_ip = self.get_client_ip()
        user.save()
        
        # Create user session record
        UserSession.objects.create(
            user=user,
            session_key=self.request.session.session_key,
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Set session expiry based on remember me
        if not form.cleaned_data.get('remember_me'):
            self.request.session.set_expiry(0)  # Browser session
        else:
            self.request.session.set_expiry(1209600)  # 2 weeks
        
        messages.success(self.request, f'Welcome back, {user.get_full_name()}!')
        
        # Redirect to next URL if provided
        next_url = self.request.GET.get('next')
        if next_url:
            return redirect(next_url)
        
        return super().form_valid(form)
    
    def form_invalid(self, form):
        email = form.data.get('email')
        if email:
            # Log failed login attempt
            LoginAttempt.objects.create(
                email=email,
                ip_address=self.get_client_ip(),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                failure_reason='Invalid credentials'
            )
        
        messages.error(self.request, 'Invalid email or password. Please try again.')
        return super().form_invalid(form)
    
    def get_client_ip(self):
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip

@method_decorator(login_required, name='dispatch')
class AdminLogoutView(TemplateView):
    """Admin logout view"""
    
    def get(self, request, *args, **kwargs):
        # Deactivate user session
        try:
            user_session = UserSession.objects.get(
                user=request.user,
                session_key=request.session.session_key
            )
            user_session.is_active = False
            user_session.save()
        except UserSession.DoesNotExist:
            pass
        
        # Logout user
        user_name = request.user.get_full_name()
        logout(request)
        
        messages.success(request, f'You have been successfully logged out. Goodbye, {user_name}!')
        return redirect('admin_login')

@method_decorator([login_required, user_passes_test(can_manage_content)], name='dispatch')
class AdminDashboardView(TemplateView):
    """Admin dashboard view"""
    template_name = 'authentication/dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Dashboard statistics
        from portfolio.models import Project, ContactMessage, NewsletterSubscriber
        
        context.update({
            'total_projects': Project.objects.filter(is_active=True).count(),
            'featured_projects': Project.objects.filter(is_featured=True, is_active=True).count(),
            'unread_messages': ContactMessage.objects.filter(is_read=False).count(),
            'total_subscribers': NewsletterSubscriber.objects.filter(is_active=True).count(),
            'recent_messages': ContactMessage.objects.filter(is_read=False)[:5],
            'recent_login_attempts': LoginAttempt.objects.filter(success=False)[:10],
            'active_sessions': UserSession.objects.filter(
                user=self.request.user,
                is_active=True
            ).count(),
        })
        
        return context

@method_decorator([login_required, user_passes_test(is_admin)], name='dispatch')
class UserManagementView(TemplateView):
    """User management view for admins"""
    template_name = 'authentication/user_management.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['users'] = CustomUser.objects.all().order_by('-created_at')
        context['form'] = CustomUserCreationForm()
        return context

@login_required
@user_passes_test(is_admin)
def create_user(request):
    """Create new user (Admin only)"""
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, f'User {user.get_full_name()} created successfully!')
            return redirect('user_management')
        else:
            messages.error(request, 'Please correct the errors below.')
    
    return redirect('user_management')

@login_required
@user_passes_test(is_admin)
def toggle_user_status(request, user_id):
    """Toggle user active status"""
    user = get_object_or_404(CustomUser, id=user_id)
    
    if user == request.user:
        messages.error(request, 'You cannot deactivate your own account.')
        return redirect('user_management')
    
    user.is_active = not user.is_active
    user.save()
    
    status_text = 'activated' if user.is_active else 'deactivated'
    messages.success(request, f'User {user.get_full_name()} has been {status_text}.')
    
    return redirect('user_management')

@login_required
def profile_view(request):
    """User profile view"""
    return render(request, 'authentication/profile.html', {
        'user': request.user,
        'recent_sessions': UserSession.objects.filter(user=request.user)[:10]
    })

@login_required
def change_password(request):
    """Change password view"""
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Validate current password
        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return redirect('profile')
        
        # Validate new password
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return redirect('profile')
        
        if len(new_password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return redirect('profile')
        
        # Update password
        request.user.set_password(new_password)
        request.user.save()
        
        # Re-authenticate user
        user = authenticate(username=request.user.email, password=new_password)
        login(request, user)
        
        messages.success(request, 'Password changed successfully!')
        return redirect('profile')
    
    return redirect('profile')

# API Views for Token Authentication
@api_view(['POST'])
def api_login(request):
    """API login endpoint"""
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        return Response({
            'error': 'Email and password are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = authenticate(username=email, password=password)
    
    if user:
        if not user.is_active:
            return Response({
                'error': 'Account is deactivated'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if user.is_account_locked():
            return Response({
                'error': 'Account is temporarily locked'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Get or create token
        token, created = Token.objects.get_or_create(user=user)
        
        # Log successful API login
        LoginAttempt.objects.create(
            email=user.email,
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        return Response({
            'token': token.key,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'full_name': user.get_full_name(),
                'user_type': user.user_type,
                'is_admin': user.is_admin(),
                'can_manage_content': user.can_manage_content(),
            }
        }, status=status.HTTP_200_OK)
    
    else:
        # Log failed API login
        LoginAttempt.objects.create(
            email=email,
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=False,
            failure_reason='Invalid credentials'
        )
        
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_logout(request):
    """API logout endpoint"""
    try:
        # Delete the token
        request.user.auth_token.delete()
        return Response({
            'message': 'Successfully logged out'
        }, status=status.HTTP_200_OK)
    except:
        return Response({
            'error': 'Error logging out'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_profile(request):
    """Get current user profile via API"""
    return Response({
        'user': {
            'id': str(request.user.id),
            'email': request.user.email,
            'username': request.user.username,
            'full_name': request.user.get_full_name(),
            'user_type': request.user.user_type,
            'is_admin': request.user.is_admin(),
            'can_manage_content': request.user.can_manage_content(),
            'last_login': request.user.last_login,
            'date_joined': request.user.date_joined,
        }
    })
```

```python
# authentication/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Web Authentication URLs
    path('login/', views.AdminLoginView.as_view(), name='admin_login'),
    path('logout/', views.AdminLogoutView.as_view(), name='admin_logout'),
    path('dashboard/', views.AdminDashboardView.as_view(), name='admin_dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('change-password/', views.change_password, name='change_password'),
    
    # User Management (Admin only)
    path('users/', views.UserManagementView.as_view(), name='user_management'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/<uuid:user_id>/toggle/', views.toggle_user_status, name='toggle_user_status'),
    
    # API Authentication URLs
    path('api/login/', views.api_login, name='api_login'),
    path('api/logout/', views.api_logout, name='api_logout'),
    path('api/profile/', views.api_profile, name='api_profile'),
]
```

```python
# authentication/templates/authentication/login.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Portfolio</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .login-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px 15px 0 0;
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 25px;
            padding: 12px 30px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="login-card">
                    <div class="login-header text-center py-4">
                        <i class="fas fa-user-shield fa-3x mb-3"></i>
                        <h3>Admin Login</h3>
                        <p class="mb-0">Portfolio Management System</p>
                    </div>
                    
                    <div class="card-body p-4">
                        {% if messages %}
                            {% for message in messages %}
                                <div class="alert alert-{{ message.tags }} alert-dismissible fade show" role="alert">
                                    {{ message }}
                                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                </div>
                            {% endfor %}
                        {% endif %}
                        
                        <form method="post">
                            {% csrf_token %}
                            
                            <div class="mb-3">
                                <label for="{{ form.email.id_for_label }}" class="form-label">
                                    <i class="fas fa-envelope me-2"></i>Email Address
                                </label>
                                {{ form.email }}
                                {% if form.email.errors %}
                                    <div class="text-danger small mt-1">
                                        {{ form.email.errors.0 }}
                                    </div>
                                {% endif %}
                            </div>
                            
                            <div class="mb-3">
                                <label for="{{ form.password.id_for_label }}" class="form-label">
                                    <i class="fas fa-lock me-2"></i>Password
                                </label>
                                {{ form.password }}
                                {% if form.password.errors %}
                                    <div class="text-danger small mt-1">
                                        {{ form.password.errors.0 }}
                                    </div>
                                {% endif %}
                            </div>
                            
                            <div class="mb-3 form-check">
                                {{ form.remember_me }}
                                <label class="form-check-label" for="{{ form.remember_me.id_for_label }}">
                                    Remember me for 2 weeks
                                </label>
                            </div>
                            
                            {% if form.non_field_errors %}
                                <div class="alert alert-danger">
                                    {{ form.non_field_errors.0 }}
                                </div>
                            {% endif %}
                            
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-login">
                                    <i class="fas fa-sign-in-alt me-2"></i>Login
                                </button>
                            </div>
                        </form>
                        
                        <div class="text-center mt-4">
                            <small class="text-muted">
                                <i class="fas fa-shield-alt me-1"></i>
                                Secure Admin Access Only
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

```python
# authentication/templates/authentication/dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Portfolio</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .sidebar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .stat-card {
            border-radius: 15px;
            border: none;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 sidebar text-white p-0">
                <div class="p-4">
                    <h4><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h4>
                    <hr class="text-white">
                    
                    <div class="nav flex-column">
                        <a href="{% url 'admin_dashboard' %}" class="nav-link text-white active">
                            <i class="fas fa-home me-2"></i>Dashboard
                        </a>
                        <a href="/admin/" class="nav-link text-white">
                            <i class="fas fa-cog me-2"></i>Django Admin
                        </a>
                        {% if user.is_admin %}
                        <a href="{% url 'user_management' %}" class="nav-link text-white">
                            <i class="fas fa-users me-2"></i>User Management
                        </a>
                        {% endif %}
                        <a href="{% url 'profile' %}" class="nav-link text-white">
                            <i class="fas fa-user me-2"></i>Profile
                        </a>
                        <a href="{% url 'admin_logout' %}" class="nav-link text-white">
                            <i class="fas fa-sign-out-alt me-2"></i>Logout
                        </a>
                    </div>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-9 col-lg-10">
                <div class="p-4">
                    <!-- Header -->
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <div>
                            <h2>Welcome back, {{ user.get_full_name }}!</h2>
                            <p class="text-muted">Here's what's happening with your portfolio</p>
                        </div>
                        <div class="text-end">
                            <small class="text-muted">Last login: {{ user.last_login|date:"M d, Y H:i" }}</small>
                        </div>
                    </div>
                    
                    {% if messages %}
                        {% for message in messages %}
                            <div class="alert alert-{{ message.tags }} alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                    
                    <!-- Statistics Cards -->
                    <div class="row mb-4">
                        <div class="col-md-3 mb-3">
                            <div class="card stat-card">
                                <div class="card-body d-flex align-items-center">
                                    <div class="stat-icon bg-primary me-3">
                                        <i class="fas fa-project-diagram"></i>
                                    </div>
                                    <div>
                                        <h5 class="card-title mb-0">{{ total_projects }}</h5>
                                        <small class="text-muted">Total Projects</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-3 mb-3">
                            <div class="card stat-card">
                                <div class="card-body d-flex align-items-center">
                                    <div class="stat-icon bg-success me-3">
                                        <i class="fas fa-star"></i>
                                    </div>
                                    <div>
                                        <h5 class="card-title mb-0">{{ featured_projects }}</h5>
                                        <small class="text-muted">Featured Projects</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-3 mb-3">
                            <div class="card stat-card">
                                <div class="card-body d-flex align-items-center">
                                    <div class="stat-icon bg-warning me-3">
                                        <i class="fas fa-envelope"></i>
                                    </div>
                                    <div>
                                        <h5 class="card-title mb-0">{{ unread_messages }}</h5>
                                        <small class="text-muted">Unread Messages</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-3 mb-3">
                            <div class="card stat-card">
                                <div class="card-body d-flex align-items-center">
                                    <div class="stat-icon bg-info me-3">
                                        <i class="fas fa-users"></i>
                                    </div>
                                    <div>
                                        <h5 class="card-title mb-0">{{ total_subscribers }}</h5>
                                        <small class="text-muted">Newsletter Subscribers</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Recent Activity -->
                    <div class="row">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h5><i class="fas fa-envelope me-2"></i>Recent Messages</h5>
                                </div>
                                <div class="card-body">
                                    {% if recent_messages %}
                                        {% for message in recent_messages %}
                                            <div class="d-flex justify-content-between align-items-center border-bottom py-2">
                                                <div>
                                                    <strong>{{ message.name }}</strong>
                                                    <br>
                                                    <small class="text-muted">{{ message.subject }}</small>
                                                </div>
                                                <small class="text-muted">{{ message.created_at|timesince }} ago</small>
                                            </div>
                                        {% endfor %}
                                        <div class="text-center mt-3">
                                            <a href="/admin/portfolio/contactmessage/" class="btn btn-sm btn-outline-primary">
                                                View All Messages
                                            </a>
                                        </div>
                                    {% else %}
                                        <p class="text-muted text-center">No unread messages</p>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h5><i class="fas fa-shield-alt me-2"></i>Security Activity</h5>
                                </div>
                                <div class="card-body">
                                    <div class="mb-3">
                                        <strong>Active Sessions:</strong> {{ active_sessions }}
                                    </div>
                                    
                                    {% if recent_login_attempts %}
                                        <h6>Recent Failed Login Attempts:</h6>
                                        {% for attempt in recent_login_attempts %}
                                            <div class="d-flex justify-content-between align-items-center border-bottom py-1">
                                                <div>
                                                    <small>{{ attempt.email }}</small>
                                                    <br>
                                                    <small class="text-muted">{{ attempt.ip_address }}</small>
                                                </div>
                                                <small class="text-danger">{{ attempt.attempted_at|timesince }} ago</small>
                                            </div>
                                        {% endfor %}
                                    {% else %}
                                        <p class="text-success">No recent failed login attempts</p>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

```python
# authentication/middleware.py
from django.utils import timezone
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib import messages
from .models import UserSession
import logging

logger = logging.getLogger(__name__)

class SessionSecurityMiddleware:
    """Middleware for enhanced session security"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Update session activity for authenticated users
        if request.user.is_authenticated and hasattr(request, 'session'):
            try:
                user_session = UserSession.objects.get(
                    user=request.user,
                    session_key=request.session.session_key,
                    is_active=True
                )
                user_session.last_activity = timezone.now()
                user_session.save()
            except UserSession.DoesNotExist:
                # Create new session record if not exists
                UserSession.objects.create(
                    user=request.user,
                    session_key=request.session.session_key,
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
        
        response = self.get_response(request)
        return response
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class AccountLockoutMiddleware:
    """Middleware to handle account lockouts"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Check if authenticated user's account is locked
        if request.user.is_authenticated and request.user.is_account_locked():
            logout(request)
            messages.error(
                request,
                'Your account has been temporarily locked due to security reasons. '
                'Please try again later.'
            )
            return redirect('admin_login')
        
        response = self.get_response(request)
        return response
```

### 2.1 Django Models

```python
# models.py
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator, EmailValidator
from django.utils import timezone
import uuid

class Profile(models.Model):
    """Main profile information"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    title = models.CharField(max_length=200)
    tagline = models.CharField(max_length=300)
    bio = models.TextField()
    profile_image = models.ImageField(upload_to='profile/', null=True, blank=True)
    cv_file = models.FileField(upload_to='documents/', null=True, blank=True)
    location = models.CharField(max_length=100)
    phone = models.CharField(
        max_length=15,
        validators=[RegexValidator(r'^\+?1?\d{9,15}$')]
    )
    email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.full_name

class SocialLink(models.Model):
    """Social media links"""
    PLATFORM_CHOICES = [
        ('linkedin', 'LinkedIn'),
        ('github', 'GitHub'),
        ('twitter', 'Twitter'),
        ('facebook', 'Facebook'),
        ('whatsapp', 'WhatsApp'),
        ('instagram', 'Instagram'),
    ]
    
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='social_links')
    platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES)
    url = models.URLField()
    is_active = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order']
        unique_together = ['profile', 'platform']

class SkillCategory(models.Model):
    """Skill categories (e.g., Programming, Tools, etc.)"""
    name = models.CharField(max_length=100)
    icon = models.CharField(max_length=50, help_text="FontAwesome icon class")
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['order']
        verbose_name_plural = "Skill Categories"

    def __str__(self):
        return self.name

class Skill(models.Model):
    """Individual skills"""
    category = models.ForeignKey(SkillCategory, on_delete=models.CASCADE, related_name='skills')
    name = models.CharField(max_length=100)
    proficiency = models.PositiveIntegerField(
        help_text="Proficiency level (0-100)",
        validators=[models.validators.MinValueValidator(0), 
                   models.validators.MaxValueValidator(100)]
    )
    icon = models.CharField(max_length=50, blank=True, help_text="FontAwesome icon class")
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['category', 'order']

    def __str__(self):
        return f"{self.name} ({self.proficiency}%)"

class ProjectCategory(models.Model):
    """Project categories for filtering"""
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name_plural = "Project Categories"

    def __str__(self):
        return self.name

class Project(models.Model):
    """Portfolio projects"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    description = models.TextField()
    short_description = models.CharField(max_length=300)
    image = models.ImageField(upload_to='projects/')
    category = models.ForeignKey(ProjectCategory, on_delete=models.CASCADE, related_name='projects')
    technologies = models.ManyToManyField('Technology', blank=True)
    github_url = models.URLField(blank=True)
    live_url = models.URLField(blank=True)
    is_featured = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_featured', 'order', '-created_at']

    def __str__(self):
        return self.title

class Technology(models.Model):
    """Technologies used in projects"""
    name = models.CharField(max_length=100, unique=True)
    color = models.CharField(max_length=7, default="#6c5ce7", help_text="Hex color code")
    icon = models.CharField(max_length=50, blank=True)

    class Meta:
        verbose_name_plural = "Technologies"

    def __str__(self):
        return self.name

class Education(models.Model):
    """Education history"""
    DEGREE_TYPES = [
        ('certificate', 'Certificate'),
        ('diploma', 'Diploma'),
        ('bachelor', 'Bachelor\'s Degree'),
        ('master', 'Master\'s Degree'),
        ('phd', 'PhD'),
        ('other', 'Other'),
    ]

    institution = models.CharField(max_length=200)
    degree_type = models.CharField(max_length=20, choices=DEGREE_TYPES)
    field_of_study = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    logo = models.ImageField(upload_to='education/', null=True, blank=True)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    is_current = models.BooleanField(default=False)
    grade = models.CharField(max_length=50, blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-start_date']

    def __str__(self):
        return f"{self.degree_type} in {self.field_of_study} - {self.institution}"

class ContactMessage(models.Model):
    """Contact form submissions"""
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    is_read = models.BooleanField(default=False)
    is_replied = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Message from {self.name} - {self.subject}"

class NewsletterSubscriber(models.Model):
    """Newsletter subscriptions"""
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    subscribed_at = models.DateTimeField(auto_now_add=True)
    unsubscribed_at = models.DateTimeField(null=True, blank=True)
    confirmation_token = models.UUIDField(default=uuid.uuid4, unique=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return self.email

class VisitorAnalytics(models.Model):
    """Basic visitor analytics"""
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    referrer = models.URLField(blank=True)
    page_visited = models.CharField(max_length=200)
    session_id = models.CharField(max_length=100)
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    visited_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Visitor Analytics"
```

### 2.2 URL Patterns

```python
# urls.py (main project)
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include('portfolio.urls')),
    path('', include('portfolio.frontend_urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# portfolio/urls.py (API URLs)
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'projects', views.ProjectViewSet)
router.register(r'skills', views.SkillViewSet)
router.register(r'education', views.EducationViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('contact/', views.ContactMessageView.as_view(), name='contact'),
    path('newsletter/subscribe/', views.NewsletterSubscribeView.as_view(), name='newsletter-subscribe'),
    path('newsletter/unsubscribe/<uuid:token>/', views.NewsletterUnsubscribeView.as_view(), name='newsletter-unsubscribe'),
    path('analytics/track/', views.AnalyticsTrackView.as_view(), name='analytics-track'),
]

# portfolio/frontend_urls.py (Frontend URLs)
from django.urls import path
from . import frontend_views

urlpatterns = [
    path('', frontend_views.IndexView.as_view(), name='home'),
    path('projects/<slug:slug>/', frontend_views.ProjectDetailView.as_view(), name='project-detail'),
]
```

### 2.3 Views and ViewSets

```python
# views.py
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from django.views.generic import TemplateView, DetailView
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .models import *
from .serializers import *
from .permissions import IsOwnerOrReadOnly
import logging

logger = logging.getLogger(__name__)

class ProfileView(generics.RetrieveAPIView):
    """Get profile information"""
    serializer_class = ProfileSerializer
    
    def get_object(self):
        return Profile.objects.select_related('user').prefetch_related('social_links').first()

class ProjectViewSet(viewsets.ReadOnlyModelViewSet):
    """Project CRUD operations"""
    serializer_class = ProjectSerializer
    lookup_field = 'slug'
    
    def get_queryset(self):
        queryset = Project.objects.filter(is_active=True).select_related('category').prefetch_related('technologies')
        category = self.request.query_params.get('category')
        featured = self.request.query_params.get('featured')
        
        if category:
            queryset = queryset.filter(category__slug=category)
        if featured:
            queryset = queryset.filter(is_featured=True)
            
        return queryset
    
    @action(detail=False, methods=['get'])
    def categories(self, request):
        """Get all project categories"""
        categories = ProjectCategory.objects.filter(is_active=True)
        serializer = ProjectCategorySerializer(categories, many=True)
        return Response(serializer.data)

class SkillViewSet(viewsets.ReadOnlyModelViewSet):
    """Skills CRUD operations"""
    serializer_class = SkillSerializer
    
    def get_queryset(self):
        return Skill.objects.filter(is_active=True).select_related('category')
    
    @action(detail=False, methods=['get'])
    def by_category(self, request):
        """Get skills grouped by category"""
        categories = SkillCategory.objects.filter(is_active=True).prefetch_related('skills')
        serializer = SkillCategorySerializer(categories, many=True)
        return Response(serializer.data)

class EducationViewSet(viewsets.ReadOnlyModelViewSet):
    """Education CRUD operations"""
    serializer_class = EducationSerializer
    queryset = Education.objects.all()

class ContactMessageView(generics.CreateAPIView):
    """Handle contact form submissions"""
    serializer_class = ContactMessageSerializer
    
    def create(self, request, *args, **kwargs):
        # Add IP address and user agent
        request.data['ip_address'] = self.get_client_ip(request)
        request.data['user_agent'] = request.META.get('HTTP_USER_AGENT', '')
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Save message
        message = serializer.save()
        
        # Send email notification
        try:
            send_mail(
                subject=f"New Contact Message: {message.subject}",
                message=f"From: {message.name} ({message.email})\n\n{message.message}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[settings.CONTACT_EMAIL],
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Failed to send contact email: {e}")
        
        return Response(
            {"message": "Your message has been sent successfully!"},
            status=status.HTTP_201_CREATED
        )
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class NewsletterSubscribeView(generics.CreateAPIView):
    """Handle newsletter subscriptions"""
    serializer_class = NewsletterSubscriberSerializer
    
    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        
        # Check if already subscribed
        subscriber, created = NewsletterSubscriber.objects.get_or_create(
            email=email,
            defaults={'is_active': True}
        )
        
        if not created and subscriber.is_active:
            return Response(
                {"message": "You are already subscribed to our newsletter."},
                status=status.HTTP_200_OK
            )
        
        if not created:
            subscriber.is_active = True
            subscriber.subscribed_at = timezone.now()
            subscriber.save()
        
        # Send confirmation email (optional)
        try:
            send_mail(
                subject="Welcome to Our Newsletter!",
                message="Thank you for subscribing to our newsletter.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
        except Exception as e:
            logger.error(f"Failed to send newsletter confirmation: {e}")
        
        return Response(
            {"message": "Successfully subscribed to newsletter!"},
            status=status.HTTP_201_CREATED
        )

class NewsletterUnsubscribeView(generics.UpdateAPIView):
    """Handle newsletter unsubscriptions"""
    queryset = NewsletterSubscriber.objects.all()
    lookup_field = 'confirmation_token'
    lookup_url_kwarg = 'token'
    
    def update(self, request, *args, **kwargs):
        subscriber = self.get_object()
        subscriber.is_active = False
        subscriber.unsubscribed_at = timezone.now()
        subscriber.save()
        
        return Response(
            {"message": "Successfully unsubscribed from newsletter."},
            status=status.HTTP_200_OK
        )

class AnalyticsTrackView(generics.CreateAPIView):
    """Track visitor analytics"""
    serializer_class = VisitorAnalyticsSerializer
    
    def create(self, request, *args, **kwargs):
        # Add IP address and user agent
        request.data['ip_address'] = self.get_client_ip(request)
        request.data['user_agent'] = request.META.get('HTTP_USER_AGENT', '')
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response(status=status.HTTP_201_CREATED)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

# Frontend Views
class IndexView(TemplateView):
    """Main portfolio page"""
    template_name = 'portfolio/index.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['profile'] = Profile.objects.select_related('user').prefetch_related('social_links').first()
        context['featured_projects'] = Project.objects.filter(is_featured=True, is_active=True)[:6]
        context['skills'] = SkillCategory.objects.filter(is_active=True).prefetch_related('skills')
        context['education'] = Education.objects.all()[:3]
        return context

class ProjectDetailView(DetailView):
    """Individual project detail page"""
    model = Project
    template_name = 'portfolio/project_detail.html'
    context_object_name = 'project'
    slug_field = 'slug'
```

### 2.4 Serializers

```python
# serializers.py
from rest_framework import serializers
from .models import *

class SocialLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = SocialLink
        fields = ['platform', 'url']

class ProfileSerializer(serializers.ModelSerializer):
    social_links = SocialLinkSerializer(many=True, read_only=True)
    
    class Meta:
        model = Profile
        fields = [
            'full_name', 'title', 'tagline', 'bio', 'profile_image',
            'cv_file', 'location', 'phone', 'email', 'social_links'
        ]

class TechnologySerializer(serializers.ModelSerializer):
    class Meta:
        model = Technology
        fields = ['name', 'color', 'icon']

class ProjectCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectCategory
        fields = ['name', 'slug', 'description']

class ProjectSerializer(serializers.ModelSerializer):
    category = ProjectCategorySerializer(read_only=True)
    technologies = TechnologySerializer(many=True, read_only=True)
    
    class Meta:
        model = Project
        fields = [
            'id', 'title', 'slug', 'description', 'short_description',
            'image', 'category', 'technologies', 'github_url', 'live_url',
            'is_featured', 'created_at'
        ]

class SkillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = ['name', 'proficiency', 'icon']

class SkillCategorySerializer(serializers.ModelSerializer):
    skills = SkillSerializer(many=True, read_only=True)
    
    class Meta:
        model = SkillCategory
        fields = ['name', 'icon', 'skills']

class EducationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Education
        fields = [
            'institution', 'degree_type', 'field_of_study', 'description',
            'logo', 'start_date', 'end_date', 'is_current', 'grade'
        ]

class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactMessage
        fields = ['name', 'email', 'subject', 'message']
        extra_kwargs = {
            'ip_address': {'write_only': True},
            'user_agent': {'write_only': True},
        }

class NewsletterSubscriberSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewsletterSubscriber
        fields = ['email']

class VisitorAnalyticsSerializer(serializers.ModelSerializer):
    class Meta:
        model = VisitorAnalytics
        fields = ['page_visited', 'referrer', 'session_id']
        extra_kwargs = {
            'ip_address': {'write_only': True},
            'user_agent': {'write_only': True},
        }
```

### 2.5 Authentication & Permissions

```python
# permissions.py
from rest_framework import permissions

class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner of the object.
        return obj.user == request.user

class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow admin users to edit.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user and request.user.is_staff
```

### 2.6 Admin Configuration

```python
# admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import *

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['full_name', 'title', 'email', 'is_active', 'updated_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['full_name', 'email', 'title']
    readonly_fields = ['created_at', 'updated_at']

@admin.register(SocialLink)
class SocialLinkAdmin(admin.ModelAdmin):
    list_display = ['profile', 'platform', 'url', 'is_active', 'order']
    list_filter = ['platform', 'is_active']
    list_editable = ['order', 'is_active']

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ['title', 'category', 'is_featured', 'is_active', 'created_at']
    list_filter = ['category', 'is_featured', 'is_active', 'created_at']
    search_fields = ['title', 'description']
    prepopulated_fields = {'slug': ('title',)}
    filter_horizontal = ['technologies']
    list_editable = ['is_featured', 'is_active']

@admin.register(Skill)
class SkillAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'proficiency', 'is_active', 'order']
    list_filter = ['category', 'is_active']
    list_editable = ['proficiency', 'order', 'is_active']

@admin.register(Education)
class EducationAdmin(admin.ModelAdmin):
    list_display = ['institution', 'degree_type', 'field_of_study', 'start_date', 'end_date']
    list_filter = ['degree_type', 'is_current']
    date_hierarchy = 'start_date'

@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ['name', 'email', 'subject', 'is_read', 'is_replied', 'created_at']
    list_filter = ['is_read', 'is_replied', 'created_at']
    search_fields = ['name', 'email', 'subject']
    readonly_fields = ['ip_address', 'user_agent', 'created_at']
    actions = ['mark_as_read', 'mark_as_replied']
    
    def mark_as_read(self, request, queryset):
        queryset.update(is_read=True)
    mark_as_read.short_description = "Mark selected messages as read"
    
    def mark_as_replied(self, request, queryset):
        queryset.update(is_replied=True)
    mark_as_replied.short_description = "Mark selected messages as replied"

@admin.register(NewsletterSubscriber)
class NewsletterSubscriberAdmin(admin.ModelAdmin):
    list_display = ['email', 'is_active', 'is_confirmed', 'subscribed_at']
    list_filter = ['is_active', 'is_confirmed', 'subscribed_at']
    search_fields = ['email']
    actions = ['activate_subscribers', 'deactivate_subscribers']
    
    def activate_subscribers(self, request, queryset):
        queryset.update(is_active=True)
    activate_subscribers.short_description = "Activate selected subscribers"
    
    def deactivate_subscribers(self, request, queryset):
        queryset.update(is_active=False)
    deactivate_subscribers.short_description = "Deactivate selected subscribers"
```

### 2.7 Settings Configuration

```python
# settings.py additions
import os
from pathlib import Path

# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@example.com')
CONTACT_EMAIL = os.environ.get('CONTACT_EMAIL', 'contact@example.com')

# Media Files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticatedOrReadOnly',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'portfolio.log',
        },
    },
    'loggers': {
        'portfolio': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# CORS Settings (if using separate frontend)
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
```

### 2.8 Required Packages

```python
# requirements.txt
Django==4.2.7
djangorestframework==3.14.0
django-cors-headers==4.3.1
Pillow==10.1.0
python-decouple==3.8
django-extensions==3.2.3
django-debug-toolbar==4.2.0
celery==5.3.4
redis==5.0.1
gunicorn==21.2.0
psycopg2-binary==2.9.9
```

## 3. Database Schema

### Entity Relationship Diagram
```
Profile (1) ←→ (M) SocialLink
Profile (1) ←→ (M) Project
Project (M) ←→ (M) Technology
Project (M) ←→ (1) ProjectCategory
Skill (M) ←→ (1) SkillCategory
ContactMessage (Independent)
NewsletterSubscriber (Independent)
VisitorAnalytics (Independent)
Education (Independent)
```

## 4. API Endpoints

### Public Endpoints
- `GET /api/v1/profile/` - Get profile information
- `GET /api/v1/projects/` - List all projects
- `GET /api/v1/projects/{slug}/` - Get project details
- `GET /api/v1/projects/categories/` - Get project categories
- `GET /api/v1/skills/` - List all skills
- `GET /api/v1/skills/by_category/` - Get skills by category
- `GET /api/v1/education/` - List education history
- `POST /api/v1/contact/` - Submit contact form
- `POST /api/v1/newsletter/subscribe/` - Subscribe to newsletter
- `PUT /api/v1/newsletter/unsubscribe/{token}/` - Unsubscribe from newsletter
- `POST /api/v1/analytics/track/` - Track visitor analytics

### Admin Endpoints (Authentication Required)
- Django Admin interface for content management
- Token-based authentication for API access

## 5. Security Considerations

1. **Input Validation**: All user inputs are validated using Django forms and DRF serializers
2. **Rate Limiting**: API endpoints are rate-limited to prevent abuse
3. **CSRF Protection**: Enabled for form submissions
4. **SQL Injection Prevention**: Using Django ORM prevents SQL injection
5. **XSS Protection**: Template auto-escaping and secure headers
6. **File Upload Security**: Restricted file types and sizes for uploads
7. **Email Security**: Proper email validation and sanitization

## 6. Performance Optimizations

1. **Database Optimization**: 
   - Proper indexing on frequently queried fields
   - Select_related and prefetch_related for reducing queries
2. **Caching**: Redis caching for frequently accessed data
3. **Image Optimization**: Automatic image resizing and compression
4. **API Pagination**: Paginated responses for large datasets
5. **Database Connection Pooling**: For production environments

## 7. Deployment Considerations

1. **Environment Variables**: Sensitive data stored in environment variables
2. **Static Files**: Proper static file handling for production
3. **Database**: PostgreSQL recommended for production
4. **Web Server**: Nginx + Gunicorn configuration
5. **SSL/TLS**: HTTPS enforcement in production
6. **Monitoring**: Logging and error tracking setup

This comprehensive Django backend system provides a robust foundation for the portfolio website with proper separation of concerns, security measures, and scalability considerations.