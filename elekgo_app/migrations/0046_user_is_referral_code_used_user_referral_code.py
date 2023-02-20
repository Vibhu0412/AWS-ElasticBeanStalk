# Generated by Django 4.1.4 on 2023-02-20 07:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0045_appversion_desc_appversion_title_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_referral_code_used',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='referral_code',
            field=models.CharField(blank=True, max_length=8, null=True),
        ),
    ]