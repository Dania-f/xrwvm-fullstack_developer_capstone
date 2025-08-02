from django.urls import path
from .views import serve_frontend

urlpatterns = [
    path('', serve_frontend),
]
