from django.db import models
from django.core.validators import MinLengthValidator


class ExcelFile(models.Model):
    file = models.FileField()


class Product(models.Model):
    article = models.CharField(max_length=128)
    nomenclature = models.CharField(max_length=256)
    bar_code = models.CharField(max_length=64, validators=[MinLengthValidator(6), ], unique=True)
    unit = models.CharField(max_length=8)
    residue = models.FloatField()
    price = models.FloatField()
    nds = models.FloatField()

    def __str__(self):
        return '%s %s %s %s %s %s %s' % (
            self.article, self.nomenclature, self.bar_code,
            self.unit, self.price, self.residue, self.nds
        )
