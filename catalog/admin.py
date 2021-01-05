from django.contrib import admin

from catalog.models import Product, ProductUnit, ProductCategory, ProductSubCategory


admin.site.register(Product)
admin.site.register(ProductUnit)
admin.site.register(ProductCategory)
admin.site.register(ProductSubCategory)
