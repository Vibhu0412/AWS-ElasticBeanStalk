# Generated by Django 4.1.4 on 2022-12-30 08:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0011_alter_user_total_km'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='total_carbon_saved',
            field=models.FloatField(default=0, verbose_name='Carbon saved in grams'),
        ),
    ]
