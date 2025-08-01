"""djangoproj URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from django.conf.urls.static import static
from django.conf import settings
from djangoapp import views
from django.views.generic import TemplateView

urlpatterns = [
    path('about/', TemplateView.as_view(template_name="About.html")),
    path('contact/', TemplateView.as_view(template_name="Contact.html")),
    path('admin/', admin.site.urls),
    path('djangoapp/', include('djangoapp.urls')),
    path('login/', TemplateView.as_view(template_name="index.html")),
    path('logout/', views.logout_request, name='logout'),
    path('', TemplateView.as_view(template_name="Home.html")),
    path('register/', include('djangoapp.urls')),
    path('register/', TemplateView.as_view(template_name="index.html")),
    path('register/', views.registration, name='register'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
