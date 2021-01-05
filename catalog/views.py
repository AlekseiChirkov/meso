from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated

from catalog.serializers import *


class ProductUnitViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated, )
    queryset = ProductUnit.objects.all()
    serializer_class = ProductUnitSerializer


class ProductSubCategoryViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated, )
    queryset = ProductSubCategory.objects.all()
    serializer_class = ProductSubCategorySerializer


class ProductCategoryViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated, )
    queryset = ProductCategory.objects.all()
    serializer_class = ProductCategorySerializer

    def list(self, request, *args, **kwargs):
        product_category = self.queryset.all()
        serializer = ProductCategoryReadableSerializer(product_category, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ProductViewSet(ModelViewSet):
    permission_classes = (IsAuthenticated, )
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    parser_classes = (MultiPartParser, FormParser)

    def list(self, request, *args, **kwargs):
        product = self.queryset.all()
        serializer = ProductReadableSerializer(product, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
