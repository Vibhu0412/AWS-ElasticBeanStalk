from rest_framework import serializers
from elekgo_app.models import User, VehicleReportModel, CustomerSatisfaction, PaymentModel, UserPaymentAccount, \
  NotificationModel, RideTable
from time import strftime, gmtime
import datetime
from elekgo_app.models import Vehicle



class TripInfoSerializer(serializers.ModelSerializer):
  vehicle_id = serializers.SerializerMethodField()
  trip_id = serializers.SerializerMethodField()
  distance_traveled = serializers.SerializerMethodField()
  driver_score = serializers.SerializerMethodField()
  ride_date = serializers.SerializerMethodField()
  ride_start_time = serializers.SerializerMethodField()
  
  class Meta:
    model = RideTable
    fields = ['trip_id','vehicle_id','distance_traveled','driver_score','ride_date','ride_start_time']

  def get_vehicle_id(self,obj):
    vehicle_id = RideTable.objects.get(pk=obj.id)
    return str(vehicle_id)

  def get_trip_id(self,obj):
    trip_id = obj.id
    return trip_id

  def get_distance_traveled(self,obj):
    distance_traveled = f'{13}km'
    return distance_traveled

  def get_driver_score(self,obj):
      driver_score = f'{99}km'
      return driver_score

  def get_ride_date(self,obj):
    ride_date = obj.ride_date.strftime('%d %b %Y')
    return ride_date

  def get_ride_start_time(self,obj):
    ride_start_time = obj.start_time
    return ride_start_time


class VehicleSerializer(serializers.ModelSerializer):
  class Meta:
    model = Vehicle
    fields = '__all__'


class AllRideSerialzer(serializers.ModelSerializer):
    vin = serializers.SerializerMethodField()
    ride_start_time = serializers.SerializerMethodField()
    total_running_time = serializers.SerializerMethodField()
    ride_end_time = serializers.SerializerMethodField()
    max_speed = serializers.SerializerMethodField()
    avg_speed = serializers.SerializerMethodField()
    distance = serializers.SerializerMethodField()
    driver_score = serializers.SerializerMethodField()
    trip_info = TripInfoSerializer(required=False, read_only=True, source='*')

    class Meta:
        model = RideTable
        fields = ['id','end_time','riding_user_id','vin','ride_start_time','total_running_time','ride_end_time','max_speed','avg_speed','distance','driver_score','trip_info']

    def get_vin(self,obj):
        vin = RideTable.objects.get(id=obj.id)
        return str(vin)

    def get_ride_start_time(self,obj):
      start_date = obj.ride_date.strftime('%d/%m/%y')
      start_time = obj.start_time.strftime('%H:%M')
      ride_start_time = f'{start_date} {start_time}'
      return ride_start_time

    def get_total_running_time(self,obj):
      total_running_time = int(obj.total_running_time)
      if total_running_time < 60:
        return f'{total_running_time} Sec'
      else:
        if total_running_time < 3600:
          return f'{strftime("%M:%S", gmtime(total_running_time))}'
        return f'{str(datetime.timedelta(seconds=total_running_time))}'
      
    def get_ride_end_time(self,obj):
      end_date = obj.end_date.strftime('%d/%m/%y')
      ride_end_time = obj.end_time.strftime('%H:%M')
      ride_end_time = f'{end_date} {ride_end_time}'
      return ride_end_time

    def get_max_speed(self,obj):
      max_speed = f'{5}km/h'
      return max_speed

    def get_avg_speed(self,obj):
      avg_speed = f'{10}km/h'
      return avg_speed
    
    def get_distance(self,obj):
      distance = f'{13}km'
      return distance

    def get_driver_score(self,obj):
      driver_score = f'{99}km'
      return driver_score


class UserPermissionSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    user_role = serializers.IntegerField()


class ReportDataSerializer(serializers.Serializer):
    range = serializers.CharField()
    vehicle = serializers.CharField()
    start_date_range = serializers.CharField(allow_blank=True, allow_null=True)
    end_date_range = serializers.CharField(allow_blank=True, allow_null=True)
    report = serializers.CharField(default="summary")

    def validate_range(self, data):
        range_lst = ['1M', '7D', '3M', '1Y', 'YTD', 'date_range']
        if data not in range_lst:
            raise serializers.ValidationError({
                'range': f'Range should only be {range_lst}'
            })
        return data

    def validate_report(self, data):
        lst_of_report_types = ['summary', 'overspeed', 'geofence', 'trips']
        if data not in lst_of_report_types:
            raise serializers.ValidationError({
                'range': f'Report type should only be {lst_of_report_types}'
            })
        return data


class AdminProfiileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'user_name', 'phone', 'user_role']

        def create(self, validate_data):
            return User.objects.create(**validate_data)

        def update(self, instance, validated_data):
            instance.email = validated_data.get("email", instance.email)
            instance.phone = validated_data.get("phone", instance.phone)
            instance.user_name = validated_data.get("user_name", instance.user_name)
            instance.user_role = validated_data.get("user_role", instance.user_role)
            instance.save()
            return instance


class AdminDashboardOverview(serializers.ModelSerializer):
    # vehicles = serializers.SerializerMethodField()
    booked_vehicles = serializers.CharField()
    avilable_vehicles = serializers.CharField()
    total_vehicles = serializers.CharField()
    total_users = serializers.CharField()
    total_earnings = serializers.CharField()
    # total_users = serializers.CharField()
    total_distance = serializers.CharField()
    active = serializers.CharField()
    moderate = serializers.CharField()
    critical = serializers.CharField()
    inactive = serializers.CharField()

    class Meta:
        model = Vehicle
        fields = ['booked_vehicles', 'avilable_vehicles', 'total_vehicles', 'total_users', 'total_earnings',
                  'total_users', 'total_distance', 'active', 'moderate', 'critical', 'inactive']


class AssetsViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle
        fields = ['vehicle_unique_identifier', 'is_unlocked']