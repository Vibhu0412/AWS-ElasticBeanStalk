# Generated by Django 4.1.4 on 2023-02-27 07:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0048_paymentmodel_phone_alter_paymentmodel_payment_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='vehicle',
            name='vehicle_name',
            field=models.CharField(default='default', max_length=50, verbose_name='Vehicle Name'),
        ),
    ]