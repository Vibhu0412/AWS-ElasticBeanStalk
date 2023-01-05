from celery import shared_task
import time
import requests
from elekgo_app.models import Vehicle

@shared_task
def countdown_timer(vid, t=1800):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1
    vehicle_obj = Vehicle.objects.filter(vehicle_unique_identifier=vid).first()
    vehicle_obj.reserverd_user_id = None
    vehicle_obj.is_reserved = False
    vehicle_obj.save()
    print("task complete")
 

@shared_task
def geocoder_reverse(lat, long):
  """lat long must be strings only and for now it is on 6 or 7 decimal points"""
  try:
    url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={long}&format=geocodejson&addressdetails=1"
    response = requests.request("GET", url)
    return response.json()
  except Exception as E:
    print('E: ', str(E))
    return None   