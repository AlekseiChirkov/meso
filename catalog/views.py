from django.http import HttpResponse
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated

from catalog.serializers import ProductSerializer, ExcelFileSerializer
from catalog.models import Product, ExcelFile
from catalog.services import excel_data_in_model


class ProductViewSet(ModelViewSet):
    # permission_classes = (IsAuthenticated, )
    queryset = Product.objects.all()
    serializer_class = ProductSerializer


class ExcelFileViewSet(ModelViewSet):
    # permission_classes = (IsAuthenticated, )
    queryset = ExcelFile.objects.all()
    serializer_class = ExcelFileSerializer

    def create(self, request, *args, **kwargs):
        excel_data_in_model(request)
        return HttpResponse('Ok')
