# Generated by Django 3.1.4 on 2020-12-29 18:12

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ProductSubCategory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128)),
            ],
        ),
        migrations.CreateModel(
            name='ProductUnit',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=16)),
            ],
        ),
        migrations.CreateModel(
            name='ProductCategory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128)),
                ('sub_category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='catalog.productsubcategory')),
            ],
        ),
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64)),
                ('image', models.ImageField(blank=True, null=True, upload_to='')),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('residue', models.FloatField()),
                ('barcode', models.PositiveIntegerField(validators=[django.core.validators.MinLengthValidator(6)])),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='catalog.productcategory')),
                ('sub_category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='catalog.productsubcategory')),
                ('unit', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='catalog.productunit')),
            ],
        ),
    ]