# Generated by Django 3.2.16 on 2022-12-22 07:27

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('elekgo_app', '0003_alter_user_user_aadhar_identification_num'),
    ]

    operations = [
        migrations.AddField(
            model_name='notificationmodel',
            name='user_id',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='elekgo_app.user'),
            preserve_default=False,
        ),
    ]
