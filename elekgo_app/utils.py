from django.core.mail import EmailMessage
from rest_framework import status, exceptions
import os
import random
import requests
import json

from authy.api import AuthyApiClient 
from elekgo_app.models import NotificationModel, User, Vehicle, Station
from geopy import distance

FCM_CLOUD_API_KEY = os.getenv('FCM_CLOUD_API_KEY')

class Util:
  @staticmethod
  def send_email(data):
    otp = random.randint(1000,9999)
    email = EmailMessage(
      subject=data['subject'],
      body=data['body'],
      
      #from_email=os.environ.get('EMAIL_FROM'),
      from_email='amanpandey.tecbic@gmail.com',
      to=[data['to_email']]
      
    )
    print(email)
    email.send()

def send_twilio_otp_via_phone(phone):
  authy_api = AuthyApiClient("YOUR_AUTHY_API_KEY")

  res = authy_api.phones.verification_start(
      phone_number=phone[3:], 
      country_code=phone[0:3], 
      via='sms')

  if res.ok():
      print(res.content)
  
def send_notification(fcm_token, title, desc, user):
  url = "https://fcm.googleapis.com/fcm/send"
  header = {
        'Content-Type': "application/json",
        'Authorization': FCM_CLOUD_API_KEY
    } 
  data = json.dumps({
      "to": fcm_token,
      "notification": {
          "body": desc,
          "title": title
      }
  })
  response = requests.post(url=url, headers=header, data=data)
  if response.status_code == status.HTTP_200_OK:
    NotificationModel.objects.create(user_id=user, notification_title=title, notification_description=desc)
  return response

def get_vehicle_location(vin, pk):
  user = User.objects.get(id=pk)
  url = 'https://bookings.revos.in/user/vehicles/all'
  headers = {
      'token': os.getenv('bolt_app_token'),
      'authorization': user.bolt_token
  }
  response = requests.request("GET", url, headers=headers)
  if response.status_code == status.HTTP_200_OK:
    data = response.json()
    for key in data.get("vehicles"):
      if key.get("vin") == vin:
        coordinate = str(key.get("location").get("latitude"))[0:9] + "," + str(key.get("location").get("longitude"))[0:9]
        return coordinate
  else:
    raise exceptions.JsonResponse("Bad response from bolt get all vehicle api")

def update_or_create_vehicle_data(pk):
  """Utitlity for getting all vehicles list from bolt api and updating project's database"""
  user = User.objects.get(id=pk)
  url = 'https://bookings.revos.in/user/vehicles/all'
  headers = {
      'token': os.getenv('bolt_app_token'),
      'authorization': user.bolt_token
  }
  response = requests.request("GET", url, headers=headers)
  if response.status_code == status.HTTP_200_OK:
    data = response.json()
    
    vehicles = []
    for i in range(len(data.get('vehicles'))):
      val = 0.0005
      lat = float(str(data.get('vehicles')[i].get('location').get("latitude"))[0:6])
      long = float(str(data.get('vehicles')[i].get('location').get("longitude"))[0:6])
      station_obj = Station.objects.filter(lat__gte=lat-val, lat__lte=lat+val, long__gte=long-val, long__lte=long+val).first()
      vehicles.append(Vehicle(vehicle_unique_identifier=data.get('vehicles')[i].get('vin'), vehicle_station=station_obj))
    Vehicle.objects.bulk_update_or_create(vehicles, ["vehicle_unique_identifier"], match_field='vehicle_unique_identifier')
  else:
    return response

def get_vehicle_detials(vin, user):
  url = f"https://bookings.revos.in/user/vehicles/{vin}"
  headers = {
        'token': os.getenv('bolt_app_token'),
        'authorization': user.bolt_token
    }
  response = requests.request("GET", url, headers=headers)
  return response

def geocoder_reverse(lat, long):
  """lat long must be strings only and for now it is on 6 or 7 decimal points"""
  try:
    # url = "https://cakemls.p.rapidapi.com/api/geocode/"
    # querystring = {"location":f"{lat},{long}"}
    # print('querystring: ', querystring)
    # headers = {
    #   "X-RapidAPI-Key": "1cf327bc29mshd09010ba819fe26p1774bfjsn3227d85c4481",
    #   "X-RapidAPI-Host": "cakemls.p.rapidapi.com"
    # }
    # response = requests.request("GET", url, headers=headers, params=querystring)
    # print("ping>>>>>>>>>>>>>>>>>>", response.json().get("data"))#.get("address"))
    url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={long}&format=geocodejson&addressdetails=1"
    response = requests.request("GET", url)
    return response.json()
  except Exception as E:
    print('E: ', str(E))
    return None

def restructuring_all_vehicles(pk):
  #user instance
  user = User.objects.filter(pk=pk).first()
  
  
  #calling bolt api
  url = 'https://bookings.revos.in/user/vehicles/all'
  headers = {
      'token': os.getenv('bolt_app_token'),
      'authorization': user.bolt_token
  }
  response = requests.request("GET", url, headers=headers)
  
  
  # validating response
  if response.status_code == status.HTTP_200_OK:
    data = response.json()
    lat_long_vehicle = []
    locations = []
    coordinate = []
    vehicle_data = {}
    for i in range(len(data.get("vehicles"))):
      if data.get('vehicles')[i].get("rentalStatus") == "AVAILABLE":
        lat = str(data.get('vehicles')[i].get('location').get('latitude'))[0:9]
        long = str(data.get('vehicles')[i].get('location').get('longitude'))[0:9]
        vin = data.get('vehicles')[i].get('location').get('vin')
        lat_long_vehicle.append((lat, long, vin))
        coordinate.append((lat[0:5], long[0:5]))
        
        
        #restructuring vehicle according to station name
        vehicle_obj = Vehicle.objects.filter(vehicle_unique_identifier=vin).first()
        is_reserved = vehicle_obj.is_reserved
        reserved_user = vehicle_obj.reserverd_user_id.pk if vehicle_obj.reserverd_user_id else ""
        if lat == "None" or long == "None":
                continue
        # address = geocoder_reverse(lat, long).get('features')[0].get("properties").get("geocoding").get("label")
        if coordinate[i] in locations:
          new_dict = str(vehicle_data.get(coordinate[i])) + "," + str({ #str(vehicle_data.get(address)) + "," + 
            # "num": rec,
            # "km": round(total_km, 2),
            "latitude": lat,
            "longtitude": long,
            'vehicle': vin,
            "is_reserved": is_reserved,
            "reserved_user": reserved_user,
            "per_min_charge": vehicle_obj.per_min_charge,
            "battery_percentage": 50,
            "max_km_capacity": "25/Km"
          })
          vehicle_data.update({coordinate[i]: new_dict })
        else:
          locations.append(coordinate[i])
          vehicle_data.update({
            coordinate[i] : {
              # "num": rec,
              # "km": round(total_km, 2),
              "latitude": lat,
              "longtitude": long,
              'vehicle': vin,
              "is_reserved": is_reserved,
              "reserved_user": reserved_user,
              "per_min_charge": vehicle_obj.per_min_charge,
              "battery_percentage": 50,
              "max_km_capacity": "25/Km"
            }
          })
        i += 1
    return vehicle_data
  else:
    return response      

def calculate_ride_distance(start, end):
  """start and end are start and end coordinates respectively"""
  start = start.split(",")
  lat = (start[0], start[1])
  end = end.split(",")
  long = (end[0], end[1])
  ride_distance = round(distance.distance(lat, long).kilometers, 2)
  return ride_distance

def carbon_calculation(ride_km):
  carbon_emmision_per_km = 90
  ride_carbon_footprint = round(ride_km * carbon_emmision_per_km, 2)
  return ride_carbon_footprint





# {'type': 'FeatureCollection', 'geocoding': 
#   {'version': '0.1.0', 'attribution': 'Data © OpenStreetMap contributors, ODbL 1.0. https://osm.org/copyright', 'licence': 'ODbL', 'query': '23.25248,72.63383'}, 
#   'features': [
#     {'type': 'Feature', 'properties': 
#       {'geocoding': 
#         {'place_id': 186684879, 'osm_type': 'way', 'osm_id': 338367080, 'type': 'street', 'accuracy': 0, 'label': 'Sector 25, Gandhinagar, Gandhinagar Taluka, Gandhinagar District, Gujarat, 382027, India', 'country': 'India', 'postcode': '382027', 'state': 'Gujarat', 'county': 'Gandhinagar Taluka', 'city': 'Gandhinagar', 'locality': 'Sector 25', 'admin': 
#           {'level4': 'Gujarat', 'level5': 'Gandhinagar District', 'level6': 'Gandhinagar Taluka'
#            }}}, 'geometry': 
#              {'type': 'Point', 'coordinates': [72.63370126178594, 23.252559020731493]}}]}