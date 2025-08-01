# Uncomment the imports before you add the code
from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from . import views
from django.contrib.auth.views import LogoutView
from djangoapp.views import serve_frontend 

app_name = 'djangoapp'
urlpatterns = [
    # path for registration
    path('register/', views.registration, name='register'),
    path(route='get_dealers', view=views.get_dealerships, name='get_dealers'),
    path(route='get_dealers/<str:state>', view=views.get_dealerships, name='get_dealers_by_state'),
    # path for login
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_request, name='logout'),
    path('', serve_frontend),
    path(route='add_review', view=views.add_review, name='add_review'),
    path(route='reviews/dealer/<int:dealer_id>', view=views.get_dealer_reviews, name='dealer_details'),
    path(route='dealer/<int:dealer_id>', view=views.get_dealer_details, name='dealer_details'),
    # other paths...
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
