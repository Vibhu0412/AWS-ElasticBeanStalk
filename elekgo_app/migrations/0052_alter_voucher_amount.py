# Generated by Django 4.1.4 on 2023-03-01 06:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0051_ridetable_last_pause_time_ridetable_last_resume_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='voucher',
            name='amount',
            field=models.PositiveIntegerField(verbose_name='Amount'),
        ),
    ]