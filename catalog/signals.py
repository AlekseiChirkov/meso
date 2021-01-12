# from django.dispatch import receiver
# from django.db.models.signals import post_save
# from django.conf import settings
#
# from catalog.models import ExcelFile, Product
#
#
# @receiver(post_save, sender=ExcelFile)
# def excel_to_model(sender, instance, created, **kwargs):
#     media_url = settings.MEDIA_URL
