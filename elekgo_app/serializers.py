from rest_framework import serializers
from .models import User, VehicleReportModel, CustomerSatisfaction, PaymentModel, UserPaymentAccount, \
  NotificationModel, RideTable, Vehicle, Station, Voucher
from time import strftime, gmtime
import datetime
from django.db.models import Sum


class UserRegistrationSerializer(serializers.ModelSerializer):
  # We are writing this becoz we need confirm password field in our Registratin Request

  class Meta:
    model = User
    fields=['email', 'user_name', 'password', 'phone', 'otp', 'is_email_verified', 'fcm_token']
    extra_kwargs= {
      'password': {'write_only': True}
    }

  def validate(self, attrs):
    return attrs

  def create(self, validate_data):
    return User.all_users.create_user(**validate_data)


class VerifyAccountSerializer(serializers.Serializer):
  otp = serializers.CharField()
  # fcm_token = serializers.CharField()


class VerifyAccountSerializerLogin(serializers.Serializer):
  otp = serializers.CharField()
  fcm_token = serializers.CharField()

class UserLoginSerializer(serializers.Serializer):
  email = serializers.EmailField()
  password = serializers.CharField()
  fcm_token = serializers.CharField()


class PhoneOtpSerializer(serializers.Serializer):
  phone = serializers.IntegerField()


class ResendOtpSerializer(serializers.Serializer):
  user_id = serializers.IntegerField()
  email = serializers.EmailField(allow_null=True)
  phone = serializers.IntegerField(allow_null=True)

  def validate(self, attrs):
    if attrs['email'] is None and attrs['phone'] is None:
      raise serializers.ValidationError({
        'data': 'Mobile or Phone is required'
      })
    return attrs

  def create(self, validate_data):
    return User.objects.create_user(**validate_data)


class FrequentlyAskedQuestionSerializer(serializers.Serializer):
  question = serializers.CharField(max_length=500)
  answer = serializers.CharField(max_length=1000)


class UserKycVerificationSerializer(serializers.Serializer):
  user_id = serializers.IntegerField()
  user_image = serializers.ImageField()
  user_aadhar_identification_num = serializers.IntegerField()
  user_aadhar_image = serializers.ImageField()
  user_aadhar_image_back = serializers.ImageField()

  def validate(self, attrs):
    if len(str(attrs['user_aadhar_identification_num'])) != 12:
      raise serializers.ValidationError({
        'user_aadhar_identification_num': 'Aadhar number should be 12 digits only.'
      })
    return attrs


class VehicleReportSerializer(serializers.ModelSerializer):
  class Meta:
    model = VehicleReportModel
    fields = '__all__'


class ChangePasswordSerializer(serializers.Serializer):
  user_id = serializers.IntegerField()
  old_password = serializers.CharField()
  new_password = serializers.CharField()
  re_enter_password = serializers.CharField()

  def validate(self, attrs):
    if attrs['new_password'] != attrs['re_enter_password']:
      raise serializers.ValidationError({
        'password_validate': 'New password and confirm password should be match'
      })
    return attrs


class CustomerSatisfactionSerializer(serializers.ModelSerializer):
  class Meta:
    model = CustomerSatisfaction
    fields = '__all__'

    def validate_email(self, data):
      return data

    def create(self, validate_data):
      return CustomerSatisfaction.objects.create(**validate_data)

    def update(self, instance, validated_data):
      instance.email = validated_data.get("email", instance.email)
      instance.user_phone = validated_data.get("user_phone", instance.user_phone)
      instance.user_is_satisfied = validated_data.get("user_is_satisfied", instance.user_is_satisfied)
      instance.save()
      return instance


class PaymentModelSerializer(serializers.ModelSerializer):
  class Meta:
    model = PaymentModel
    fields = '__all__'

    def validate(self, attrs):
      return attrs

    def create(self, validate_data):
      return PaymentModel.objects.create_user(**validate_data)


class UserPaymentAccountSerializer(serializers.ModelSerializer):
  class Meta:
    model = UserPaymentAccount
    fields = '__all__'

    def validate(self, attrs):
      return attrs

    def create(self, validate_data):
      return UserPaymentAccount.objects.create_user(**validate_data)


class RideStartStopSerializer(serializers.Serializer):
  user_id = serializers.IntegerField()
  scooter_chassis_no = serializers.CharField()
  action = serializers.CharField()

  def validate(self, attrs):
    if attrs['action'] not in ['start', 'pause', 'resume', 'end']:
      raise serializers.ValidationError({
        'action': 'action have only four valid value : start, pause, resume, end'
      })
    return attrs


class NotificationSerializer(serializers.ModelSerializer):
  class Meta:
    model = NotificationModel
    fields = '__all__'

    def validate(self, attrs):
      return attrs

    def create(self, validate_data):
      return NotificationModel.objects.create_user(**validate_data)


#Admin User

class AdminUserRegistrationSerializer(serializers.ModelSerializer):
  # We are writing this becoz we need confirm password field in our Registratin Request

  class Meta:
    model = User
    fields=['email', 'user_name', 'password', 'phone', 'otp', 'is_email_verified', 'fcm_token','user_role']
    extra_kwargs= {
      'password': {'write_only': True}
    }

  def validate(self, attrs):
    return attrs

  def create(self, validate_data):
    return User.objects.create_user(**validate_data)


class AdminUserLoginSerializer(serializers.Serializer):
  email = serializers.EmailField()
  password = serializers.CharField()
  fcm_token = serializers.CharField()


class GetAllUserSerializer(serializers.ModelSerializer):

  class Meta:
    model = User
    fields = ['id', 'email', 'user_name', 'phone', 'user_role']


class RideRunningTimeGet(serializers.Serializer):
  scooter_chassis_no = serializers.CharField()
  user_id = serializers.IntegerField()
  ride_id = serializers.IntegerField()


class GetAllKycUserSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ['id', 'email', 'user_name', 'phone', 'is_user_kyc_verified', 'user_image', 'user_aadhar_image', 'user_aadhar_image_back', 'user_aadhar_identification_num']


class UserRideSerializer(serializers.ModelSerializer):
  ride_date = serializers.SerializerMethodField()
  total_running_time = serializers.SerializerMethodField()
  start_time = serializers.SerializerMethodField()
  total_charge = serializers.SerializerMethodField()

  class Meta:
    model = RideTable
    fields = ['id', 'ride_date', 'start_time', 'total_running_time', 'total_charge']

  def get_ride_date(self, obj):
    date = obj.ride_date.strftime('%d %b %Y')
    return date

  def get_start_time(self, obj):
    start_time = obj.start_time.strftime("%H:%M")
    return start_time

  def get_total_running_time(self, obj):
    running_time = int(obj.total_running_time)
    if running_time < 60:
      return f'{running_time} Sec'
    else:
      if running_time < 3600:
        return f'{strftime("%M:%S", gmtime(running_time))} Min'
      return f'{str(datetime.timedelta(seconds=running_time))} Min'

  def get_total_charge(self, obj):
    ride = RideTable.objects.get(id=obj.id)
    total_charge = str(ride.payment_id.payment_amount) if ride.payment_id else 0
    return total_charge


def get_sec(time_str):
  h, m, s = time_str.split(':')
  return int(h) + 3600 + int(m) * 60 + int(s)


class UserRideDetailsSerializer(serializers.ModelSerializer):
  ride_date = serializers.SerializerMethodField()
  # total_running_time = serializers.SerializerMethodField()
  # total_pause_time = serializers.SerializerMethodField()
  # running_charge_per_minute = serializers.SerializerMethodField()
  # pause_charge_per_minute = serializers.SerializerMethodField()
  # total_running_time_cost = serializers.SerializerMethodField()
  # total_pause_time_cost = serializers.SerializerMethodField()
  # gst = serializers.SerializerMethodField()
  # total_amount_paid = serializers.SerializerMethodField()
  start_time = serializers.SerializerMethodField()
  end_time = serializers.SerializerMethodField()
  vehicle_id = serializers.SerializerMethodField()


  class Meta:
    model = RideTable
    fields = ['id', 'ride_date', 'start_time', 'end_time', "start_location", "end_location", 'vehicle_id']

  def get_ride_date(self, obj):
    date = obj.ride_date.strftime('%A, %d %b %Y')
    return date

  def get_vehicle_id(self, obj):
    vehicle = Vehicle.objects.get(id=obj.vehicle_id.id)
    return str(vehicle.vehicle_unique_identifier)

  def get_start_time(self, obj):
    start_time = obj.start_time.strftime("%H:%M")
    return start_time

  def get_end_time(self, obj):
    end_time = obj.end_time.strftime("%H:%M")
    return end_time

class GetAllUsersTripsSerializer(serializers.ModelSerializer):
  ride_date = serializers.SerializerMethodField()
  vehicle_id = serializers.SerializerMethodField()
  start_time = serializers.SerializerMethodField()
  total_duration = serializers.SerializerMethodField()
  total_payment = serializers.SerializerMethodField()
  distance_km = serializers.SerializerMethodField()
  class Meta:
    model = RideTable
    fields = ['id', 'vehicle_id', 'ride_date', 'start_time', 'total_duration', 'total_payment', 'distance_km']

  def get_vehicle_id(self, obj):
    vehicle = Vehicle.objects.get(id=obj.vehicle_id.id)
    return str(vehicle.vehicle_unique_identifier)

  def get_ride_date(self, obj):
    date = obj.ride_date.strftime('%d/%m/%y')
    return date

  def get_start_time(self, obj):
    start_time = obj.start_time.strftime("%H:%M")
    return start_time

  def get_total_duration(self, obj):
    ride = RideTable.objects.get(id=obj.id)
    time = int(ride.total_running_time) + int(ride.total_pause_time) if ride.total_pause_time else 0
    if time < 60:
      return f'{time} Sec'
    else:
      if time < 3600:
        return f'{strftime("%M:%S", gmtime(time))} Min'
      return f'{str(datetime.timedelta(seconds=time))} Min'

  def get_total_payment(self, obj):
    ride = RideTable.objects.get(id=obj.id)
    total = ride.payment_id.payment_amount if ride.payment_id else 0
    return abs(total)

  def get_distance_km(self, obj):
    total_km = f'0 Km'
    return total_km

class GetAllUsersSerializer(serializers.ModelSerializer):
  # id = serializers.SerializerMethodField()
  status = serializers.SerializerMethodField()
  ridedetails = serializers.SerializerMethodField()
  total_bookings = serializers.SerializerMethodField()
  # total_booking_duration = serializers.SerializerMethodField()
  total_distance = serializers.SerializerMethodField()
  class Meta:
    model = User
    fields = ['id', 'user_name', 'phone', 'email', 'status', 'ridedetails', 'total_bookings', 'total_distance']#'total_booking_duration',

  def get_status(self, obj):
    user = User.objects.get(id=obj.id)
    status = ''
    if user.is_user_kyc_verified == 'Pending':
      status = 'Pending Approval'
    elif user.is_active == True:
      status = 'Active'
    elif user.is_active == False:
      status = 'Inactive'
    return status

  def get_ridedetails(self, obj):
    rides = RideTable.objects.filter(riding_user_id=obj.id)
    serialize = GetAllUsersTripsSerializer(rides, many=True)
    return serialize.data
  
  def get_total_bookings(self, obj):
    rides = RideTable.objects.filter(riding_user_id=obj.id)
    return len(rides)

  def get_total_booking_duration(self, obj):
    rides = RideTable.objects.filter(riding_user_id=obj.id)
    total_running_time = rides.aggregate(Sum('total_running_time')) if len(rides) > 0 else 0
    total_pause_time = rides.aggregate(Sum('total_pause_time')) if len(rides) > 0 else 0
    if len(rides) > 0:
      time = total_pause_time.get('total_pause_time__sum') if total_pause_time.get('total_pause_time__sum') else 0 + total_running_time.get('total_running_time__sum')
      if time < 60:
        total = f'{time} Sec'
      else:
        if time < 3600:
          total = f'{strftime("%M:%S", gmtime(time))} Min'
        else:
          total = f'{str(datetime.timedelta(seconds=time))} Min'
    else:
      total = 0
    return total

  def get_total_distance(self, obj):
    total_distance = f'{0} Km'
    return total_distance


class ReserveSerializer(serializers.ModelSerializer):
  class Meta:
    model = Vehicle
    fields = ["battery_percentage", "scooter_number", "number_of_km_used", "per_min_charge", "is_reserved", "reserverd_user_id"]

class StationSerializer(serializers.ModelSerializer):
  class Meta:
    model = Station
    fields = "__all__"

class UserSerializer(serializers.ModelSerializer):
  total_carbon_saved = serializers.SerializerMethodField()
  class Meta:
    model = User
    exclude = ["password", "is_email_verified", "otp", "bolt_id", "bolt_token", "fcm_token"]
    
  def get_total_carbon_saved(self, obj):
    total_carbon_saved = round(obj.total_carbon_saved, 2)
    if total_carbon_saved >= 1000:
      total_carbon_saved = round(total_carbon_saved/1000, 2)
      total_carbon_saved = f"{total_carbon_saved} Kg"
    else:
      total_carbon_saved = f"{total_carbon_saved} g"
    return total_carbon_saved

class StationVehicleSerializer(serializers.ModelSerializer):
  class Meta:
    model = Vehicle
    exclude = ["vehicle_station", "id", "celery_task_id", "qr_image", "iot_device_number", "battery_number", "current_location"]
    
class VoucherSerializer(serializers.ModelSerializer):
  class Meta:
    model = Voucher
    fields = "__all__"