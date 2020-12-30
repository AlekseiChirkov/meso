from rest_framework import serializers

from catalog.models import *


class ProductUnitSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductUnit
        fields = '__all__'


class ProductSubCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductSubCategory
        fields = '__all__'


class ProductCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategory
        fields = '__all__'


class ProductCategoryReadableSerializer(serializers.ModelSerializer):
    sub_category = ProductSubCategorySerializer()

    class Meta:
        model = ProductCategory
        fields = '__all__'


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'


class ProductReadableSerializer(serializers.ModelSerializer):
    category = ProductCategoryReadableSerializer()
    sub_category = ProductSubCategorySerializer()
    unit = ProductUnitSerializer()

    class Meta:
        model = Product
        fields = '__all__'
