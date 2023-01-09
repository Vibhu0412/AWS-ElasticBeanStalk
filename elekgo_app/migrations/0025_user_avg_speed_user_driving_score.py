# Generated by Django 4.1.4 on 2023-01-09 05:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0024_alter_vehicle_vehicle_station'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='avg_speed',
            field=models.FloatField(default=0, verbose_name='Average speed'),
        ),
        migrations.AddField(
            model_name='user',
            name='driving_score',
            field=models.FloatField(default=0, verbose_name='Driving score'),
        ),
    ]
