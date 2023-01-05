# Generated by Django 3.2.16 on 2022-12-22 13:02

from django.db import migrations, models
from datetime import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0005_notificationmodel_created_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='vehicle',
            name='reservation_expire_time',
            field=models.DateTimeField(blank=True, null=True, default=datetime.now()),
        ),
    ]
