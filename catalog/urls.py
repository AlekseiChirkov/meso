from django.urls import include, path
from rest_framework import routers

from .views import *


router = routers.DefaultRouter()
router.register('product-units', ProductUnitViewSet)
router.register('product-sub-categories', ProductSubCategoryViewSet)
router.register('product-categories', ProductCategoryViewSet)
router.register('products', ProductViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
