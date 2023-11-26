from django.db import models


# Create your models here.

class PublicKey(models.Model):
    id= models.AutoField(primary_key=True)
    key_id = models.TextField(max_length=255)
    key_data = models.BinaryField()
    user_id = models.TextField(max_length=255,default="")
    validity = models.TextField(max_length=255,default="")
    cname = models.TextField(max_length=255,default="")
    ounit = models.TextField(max_length=255,default="")
    state= models.TextField(max_length=255,default="")
    country=models.TextField(max_length=255,default="")
    location=models.TextField(max_length=255,default="")
    organ=models.TextField(max_length=255,default="")
    keystore_name=models.TextField(max_length=255,default="")



