from django.db import models


# Create your models here.
class User(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.TextField(max_length=255)
    email = models.TextField(max_length=255)
    password = models.TextField(max_length=255)
    role = models.TextField(max_length=255)

class Policy(models.Model):
    id= models.AutoField(primary_key=True)
    name=models.TextField(max_length=255)
    default=models.BooleanField(default=False)
    data_owner_id = models.TextField(max_length=255)