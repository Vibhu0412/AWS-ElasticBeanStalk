# Generated by Django 4.1.4 on 2023-01-03 08:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0020_rename_one_pause_time_ridetimehistory_pause_duration'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ridetimehistory',
            name='pause_duration',
            field=models.IntegerField(blank=True, max_length=200, null=True),
        ),
    ]
