# Generated by Django 2.1.4 on 2023-10-15 17:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapp', '0002_alter_user_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='Policy',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.TextField(max_length=255)),
                ('data_owner_id', models.TextField(max_length=255)),
            ],
        ),
    ]