# Generated by Django 4.1.4 on 2022-12-30 08:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0010_user_total_km_alter_user_total_carbon_saved'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='total_km',
            field=models.FloatField(default=0, verbose_name='Total Kilometer travelled'),
        ),
    ]
