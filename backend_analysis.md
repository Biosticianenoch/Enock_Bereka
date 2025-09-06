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
5. **User Authentication (Admin)**
6. **Content Management System**
7. **Analytics & Visitor Tracking**
8. **File Upload (CV, Project Images)**

## 2. Django Backend Architecture

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