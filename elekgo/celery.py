import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'elekgo.settings')

app = Celery('tasks', backend='redis://localhost:6379/0', broker='amqp://')

#for render
# app = Celery('tasks', backend='redis://red-cep88mh4reb38608up3g:6379', broker='redis://red-cep88mh4reb38608up3g:6379')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()