# Generated by Django 4.2 on 2023-06-16 20:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('keygen', '0002_publickey_user_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='publickey',
            name='cname',
            field=models.TextField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='publickey',
            name='country',
            field=models.TextField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='publickey',
            name='keystore_name',
            field=models.TextField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='publickey',
            name='location',
            field=models.TextField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='publickey',
            name='organ',
            field=models.TextField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='publickey',
            name='ounit',
            field=models.TextField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='publickey',
            name='state',
            field=models.TextField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='publickey',
            name='validity',
            field=models.TextField(default='', max_length=255),
        ),
        migrations.AlterField(
            model_name='publickey',
            name='id',
            field=models.UUIDField(primary_key=True, serialize=False),
        ),
    ]
