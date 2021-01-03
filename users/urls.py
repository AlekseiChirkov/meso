from django.conf.urls import url
from django.urls import path, include
from django_rest_passwordreset import views
# Third Party Stuff
from rest_framework.routers import DefaultRouter

# phone_verify
# from .api import VerificationViewSet

from .views import *

default_router = DefaultRouter(trailing_slash=False)
default_router.register("phone", VerificationViewSet, basename="phone")

app_name = 'users'


urlpatterns = [
    list(default_router.urls),

    path('backend/users/', UserRetrieveUpdateAPIView.as_view(), name='users'),
    path('backend/users/me/', CurrentUserView.as_view(), name='me'),
    path('backend/users/update/', UserUpdateAPIView.as_view(), name='update_user'),
    path('backend/users/registration/', RegistrationAPIView.as_view(), name='registration'),
    path('backend/users/login/', LoginAPIView.as_view(), name='login'),
    path('backend/users/password-reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('backend/users/search/', UserListAPIView.as_view(), name='user-search'),

    # email verification
    # url(r'backend/activate/(?P<uid64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
    #     activate, name='activate'),
]

