from django.urls import include, path
from rest_framework import routers

from catalog.views import ProductViewSet, ExcelFileViewSet


router = routers.DefaultRouter()
router.register('products', ProductViewSet)
router.register('excel', ExcelFileViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
