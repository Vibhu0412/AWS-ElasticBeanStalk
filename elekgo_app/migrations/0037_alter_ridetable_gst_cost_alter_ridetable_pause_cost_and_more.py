# Generated by Django 4.1.4 on 2023-01-10 07:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0036_ridetable_gst_cost_ridetable_pause_cost_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ridetable',
            name='gst_cost',
            field=models.FloatField(blank=True, null=True, verbose_name='GST applied'),
        ),
        migrations.AlterField(
            model_name='ridetable',
            name='pause_cost',
            field=models.FloatField(blank=True, null=True, verbose_name='Pause cost'),
        ),
        migrations.AlterField(
            model_name='ridetable',
            name='ride_km',
            field=models.FloatField(blank=True, null=True, verbose_name='Ride distance'),
        ),
        migrations.AlterField(
            model_name='ridetable',
            name='running_cost',
            field=models.FloatField(blank=True, null=True, verbose_name='Running cost'),
        ),
        migrations.AlterField(
            model_name='ridetable',
            name='total_cost',
            field=models.FloatField(blank=True, null=True, verbose_name='Total cost'),
        ),
        migrations.AlterField(
            model_name='ridetable',
            name='total_cost_with_gst',
            field=models.FloatField(blank=True, null=True, verbose_name='Total cost with GST'),
        ),
    ]
