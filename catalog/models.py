from django.core.validators import MinLengthValidator
from django.db import models


class ProductUnit(models.Model):
    name = models.CharField(max_length=16)

    def __str__(self):
        return str(self.name)


class ProductSubCategory(models.Model):
    name = models.CharField(max_length=128)

    def __str__(self):
        return str(self.name)


class ProductCategory(models.Model):
    name = models.CharField(max_length=128)
    sub_category = models.ForeignKey(ProductSubCategory, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.name), str(self.sub_category)


class Product(models.Model):
    name = models.CharField(max_length=64)
    image = models.ImageField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    residue = models.FloatField()
    category = models.ForeignKey(ProductCategory, on_delete=models.CASCADE)
    sub_category = models.ForeignKey(ProductSubCategory, on_delete=models.CASCADE)
    unit = models.ForeignKey(ProductUnit, on_delete=models.CASCADE)
    barcode = models.PositiveIntegerField(validators=[MinLengthValidator(6), ])

    def __str__(self):
        return '%s %s %s %s %s %s %s %s' % (
            self.name, self.image, self.price, self.residue,
            self.category, self.sub_category, self.unit, self.barcode
        )
