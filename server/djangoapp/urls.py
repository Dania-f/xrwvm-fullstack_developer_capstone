# Uncomment the imports before you add the code
# from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from django.urls import path
from . import views



app_name = 'djangoapp'
urlpatterns = [
    # # path for registration

    # path for login
    # path(route='login', view=views.login_user, name='login'),

    # path for dealer reviews view
      path(route='get_cars', view=views.get_cars, name='getcars'),
      path('get_dealers/', views.get_dealerships, name='get_dealers'),
      path('get_dealers/<str:state>', views.get_dealerships, name='get_dealers_by_state'),
      path('dealer/<int:dealer_id>', views.get_dealer_details, name='dealer_details'),
      path('reviews/dealer/<int:dealer_id>', views.get_dealer_reviews, name='dealer_reviews'),   
    # path for add a review view
      path('add_review', views.add_review, name='add_review'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
