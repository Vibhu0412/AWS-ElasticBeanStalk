# Generated by Django 4.1.4 on 2023-01-19 09:53

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0042_alter_ridetable_vehicle_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ridetable',
            name='riding_user_id',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='ride_user', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='ridetable',
            name='vehicle_id',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='ride_vehicle', to='elekgo_app.vehicle'),
        ),
    ]
