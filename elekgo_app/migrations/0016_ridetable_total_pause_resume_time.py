# Generated by Django 4.1.4 on 2023-01-02 12:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0015_vehicle_celery_task_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='ridetable',
            name='total_pause_resume_time',
            field=models.TimeField(blank=True, null=True),
        ),
    ]
