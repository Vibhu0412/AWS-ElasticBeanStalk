import json

from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet, ModelViewSet
from .renderers import UserRenderer
from .serializers import PhoneOtpSerializer, UserLoginSerializer, UserRegistrationSerializer, UserRfCodeSerializer, VerifyAccountSerializer, \
    ResendOtpSerializer, VerifyAccountSerializerLogin, FrequentlyAskedQuestionSerializer, UserKycVerificationSerializer,\
    VehicleReportSerializer, ChangePasswordSerializer, CustomerSatisfactionSerializer, PaymentModelSerializer, \
    UserPaymentAccountSerializer, RideStartStopSerializer, NotificationSerializer, AdminUserLoginSerializer, AdminUserRegistrationSerializer,\
    GetAllUserSerializer, RideRunningTimeGet, GetAllKycUserSerializer, UserRideSerializer, UserRideDetailsSerializer, \
    GetAllUsersSerializer, ReserveSerializer, StationSerializer, UserSerializer, StationVehicleSerializer, VoucherSerializer, RedeemVoucherSerializer, AppVersionSerializer,OrderSerializer
import requests
import ast
from geopy.geocoders import Nominatim
from geopy.distance import geodesic
from django.db.models import Sum
from rest_framework.response import Response
from rest_framework import status
from .emails import *
from .models import FrequentlyAskedQuestions, CustomerSatisfaction, UserPaymentAccount, PaymentModel, Vehicle, \
    RideTable, NotificationModel, RideTimeHistory, Station, Voucher, AppVersion
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from decouple import config
from django.contrib.auth.hashers import check_password, make_password
import datetime
import requests
import time
from elekgo_app.authentication import JWTAuthentication, create_access_token, create_refresh_token, decode_access_token, decode_refresh_token, get_verification_token, decode_verification_token
from elekgo_app.user_permissions import IsAdminUser
from rest_framework.permissions import IsAuthenticated
from django.contrib.sessions.backends.db import SessionStore
from elekgo_app.utils import send_notification, update_or_create_vehicle_data, restructuring_all_vehicles, get_vehicle_location, calculate_ride_distance, carbon_calculation, geocoder_reverse, get_vehicle_detials, geocode_reverse_coordinate
import environ
from rest_framework.decorators import action
from elekgo_app.pagination import CustomPagination
from elekgo_app.filters import SearchFilter
from elekgo_app.tasks import countdown_timer, geocoder_reverse
from elekgo.celery import app
from rest_framework import filters
import math
from dotenv import load_dotenv
from .viewset import CustomViewSet
from django.forms.models import model_to_dict
load_dotenv()

env = environ.Env()
environ.Env.read_env()

# Using Nominatim Api
geolocator = Nominatim(user_agent="coordinateconverter")
def get_sec(time_str):
    try:
        h, m, s = 0, 0, 0
        if len(time_str.split(", ")) > 1:
            h, m, s = time_str.split(", ")[1].split(':')
        else:
            h, m, s = time_str.split(':')
        return int(h) * 3600 + int(m) * 60 + int(s)
    except Exception as e:
        print('e: ', e)
        return 0


def get_tokens_for_user(user):
  # refresh = RefreshToken.for_user(user)
  access_token = create_access_token(user.id)
  refresh_token = create_refresh_token(user.id)
  id = decode_refresh_token(refresh_token)
  refresh_access_token = create_access_token(id)

  return {
      'refresh': refresh_token,
      'access': refresh_access_token,
  }


def unlock_scooter(name):
    url = f"https://trackgaddi.com/api/v1/TokenizedVehicle/Controlling/IgnitionOn/{name}"

    headers = {
        'TGToken': os.getenv('TGToken')
    }
    response = requests.request("GET", url, headers=headers)
    print('unlock response: ', response.json(), response.status_code)
    return response


def lock_scooter(name):
    url = f"https://trackgaddi.com/api/v1/TokenizedVehicle/Controlling/IgnitionOff/{name}"
    headers = {
        'TGToken': os.getenv('TGToken')
    }
    response = requests.request("GET", url, headers=headers)
    print('lock response: ', response.json(), response.status_code)
    return response


class RegisterUserView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        if request.data:
            try:
                serializer = UserRegistrationSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    email = serializer.validated_data['email']
                    phone = serializer.validated_data['phone']
                    send_otp_via_email(email)
                    # send_twilio_otp_via_phone(phone)
                    user = User.objects.get(email=email)
                    token = get_tokens_for_user(user)

                    response = {
                        "success": True,
                        "message": "User Registration Successfull, Please check your email and verify using OTP",
                        "status": status.HTTP_201_CREATED,
                        'user_id': user.id,
                        "user_name": user.user_name,
                        "user_phone": str(user.phone),
                        "user_email": user.email,
                        "is_kyc_verified": user.is_user_kyc_verified,
                        "token": token,
                        "referral_code": user.referral_code, 
                        "is_referral_code_used":user.is_referral_code_used,
                    }
                    return Response(response, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({
                    "message":str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                "message": "Data not found"
            }, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTP(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, pk, *args, **kwargs):
        try:
            serializer = VerifyAccountSerializer(data=request.data)
            if serializer.is_valid():
                otp = serializer.validated_data['otp']
                user = User.objects.filter(id=pk, otp=otp).first()
                if user:
                    user.is_email_verified = True
                    user.save()
                    token = get_tokens_for_user(user)
                    send_notification(fcm_token=user.fcm_token, title="Registration succesfull", desc="Email is verified succesfully", user=user)
                    return Response({
                        "success": True,
                        "message": "your email is verified and logged in successfully",
                        'user_id': user.id,
                        "user_name": user.user_name,
                        "user_phone": str(user.phone),
                        "user_email": user.email,
                        "is_kyc_verified": user.is_user_kyc_verified,
                        "token": token,
                    }, status=status.HTTP_200_OK)
                # return Response({
                #     "status": 400,
                #     "message": "Please enter valid otp"
                # })
                return Response({
                    "message": "Your username and otp is doesn't match!! please enter valid OTP or username"
                }, status=status.HTTP_400_BAD_REQUEST)
                # except:
            return Response({
                "message":"Something went wrong"
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as E:
            print('E: ', E)
            return Response({
                "message":"Please Enter Valid OTP"
            }, status=status.HTTP_400_BAD_REQUEST)


class UserLoginWithEmail(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, *ags, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            fcm_token = serializer.validated_data['fcm_token']
            user = User.objects.filter(email=email)
            if user:
                user_validate = authenticate(email=email, password=password)
                user = User.objects.get(email=email)
                if user.is_email_verified:
                    if user_validate:
                        token = get_tokens_for_user(user)
                        response={
                            "success": True,
                            "message": "User logged in Successfully",
                            "status": status.HTTP_201_CREATED,
                            'user_id': user.id,
                            "user_name": user.user_name,
                            "user_phone": str(user.phone),
                            "user_email": user.email,
                            "is_kyc_verified": user.is_user_kyc_verified,
                            "token": token,
                            "referral_code": user.referral_code, 
                            "is_referral_code_used":user.is_referral_code_used,
                        }
                        user.fcm_token=fcm_token
                        user.save()
                        return Response(response, status=status.HTTP_201_CREATED)
                    return Response({
                        'message': "username or password does not match!! please enter correct credentials"
                    }, status=status.HTTP_400_BAD_REQUEST)
                send_otp_via_email(user.email)
                return Response({
                    'message': "user has not verified the email, please check your email and verify it using OTP sent to your email address",
                    'user_id': user.id
                }, status.HTTP_400_BAD_REQUEST)
            return Response({
                'message': "username or password does not match!! please enter correct credentials"
            }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOtpLogin(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, pk, *args, **kwargs):
        serializer = VerifyAccountSerializerLogin(data=request.data)
        if serializer.is_valid():
            otp = serializer.validated_data['otp']
            try:
                user = User.objects.get(id=pk, otp=str(otp))
            except:
                return Response({
                    "message":"Please enter valid otp"
                }, status=status.HTTP_400_BAD_REQUEST)
            if not user:
                return Response({
                    "message": "Please enter valid otp"
                }, status=status.HTTP_400_BAD_REQUEST)

            user.fcm_token = serializer.validated_data['fcm_token']
            user.is_email_verified = True
            user.save()
            access_token = create_access_token(user.id)
            refresh_token=create_refresh_token(user.id)
            id = decode_refresh_token(refresh_token)
            refresh_access_token = create_access_token(id)
            return Response({
                "success": True,
                "status": status.HTTP_201_CREATED,
                'user_id': user.id,
                "user_name": user.user_name,
                "user_phone": str(user.phone),
                "user_email": user.email,
                "message": "logged in successfully",
                "is_kyc_verified": user.is_user_kyc_verified,
                "token": get_tokens_for_user(user),
            }, status=status.HTTP_200_OK)
            
        return Response({
            "message":"Something wents wrong"
        }, status=status.HTTP_400_BAD_REQUEST)


class SendMobileOtp(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        serializer = PhoneOtpSerializer(data=request.data)
        if serializer.is_valid():
            phone = "+" + str(serializer.validated_data['phone'])
            try:
                user = User.objects.get(phone=phone)
                if user:
                    send_otp_via_phone(phone=phone)
                return Response({
                    "user_id": user.id,
                    "message": "Your otp sent successfully",
                    "is_kyc_verified": user.is_user_kyc_verified,
                }, status=status.HTTP_200_OK)
            except Exception as e:
                print("e====================", str(e))
                return Response({
                    "message": str(e)
                }, status=status.HTTP_400_BAD_REQUEST)

                # phone_number = phone
                # my_otp = random.randint(1111, 9999)
                # message = client.messages.create(
                #                         body=f"Hi,Welcome to ElekGo ,{my_otp} is your one time password to proceed on ElekGo. Do not share your OTP with anyone.",
                #                         from_='+14245678409',
                #                         to=f'{phone}'
                # )
                # User.objects.filter(phone=phone).update(otp=my_otp)

            # return Response({
            #     "status":400,
            #     "message":"Something wents wrong"
            # })
        return Response({
            "message":"Something wents wrong"
        }, status=status.HTTP_400_BAD_REQUEST)


class ResendOtpSerializerView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = ResendOtpSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            email = serializer.validated_data['email']
            phone = "+" + str(serializer.validated_data['phone'])
            if email is None and phone is None:
                return Response(serializer.validated_data, status=status.HTTP_400_BAD_REQUEST)
            if email:
                try:
                    user = User.objects.get(id=user_id, email=email)
                    send_otp_via_email(user.email)
                    return Response({
                        "user_id": user.id,
                        "message": "Your otp sent successfully",
                        "email": user.email,
                        "is_kyc_verified": user.is_user_kyc_verified,
                    }, status=status.HTTP_200_OK)
                except:
                    return Response({
                        'message': 'user not found with the email and id'
                    }, status=status.HTTP_400_BAD_REQUEST)
            if phone:
                try:
                    user = User.objects.get(id=user_id, phone=phone)
                    send_otp_via_phone(user.phone)
                    return Response({
                        "user_id": user.id,
                        "message": "Your otp sent successfully",
                        "phone": str(user.phone),
                        "is_kyc_verified": user.is_user_kyc_verified,
                    }, status=status.HTTP_200_OK)
                except:
                    return Response({
                        'message': 'user not found with the phone and id'
                    }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FAQSerializerView(APIView):
    renderer_classes = [UserRenderer]
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        faq = FrequentlyAskedQuestions.objects.all()
        serializer = FrequentlyAskedQuestionSerializer(faq, many=True)
        return Response({'faq': serializer.data})


class UserKycVerificationSerializerView(APIView):
    renderer_classes = [UserRenderer]
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UserKycVerificationSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            user_image = serializer.validated_data['user_image']
            user_aadhar_identification_num = serializer.validated_data['user_aadhar_identification_num']
            user_aadhar_image = serializer.validated_data['user_aadhar_image']
            user_aadhar_image_back = serializer.validated_data['user_aadhar_image_back']
            try:
                user = User.objects.get(id=user_id)
                if user:
                    if user.is_user_kyc_verified == "NA" or user.is_user_kyc_verified == "Rejected":
                        user.user_image = user_image
                        user.user_aadhar_image = user_aadhar_image
                        user.user_aadhar_identification_num = user_aadhar_identification_num
                        user.user_aadhar_image_back = user_aadhar_image_back
                        user.is_user_kyc_verified = 'Pending'
                        user.save()
                        send_notification(fcm_token=request.user.fcm_token, title="Uploaded KYC details successfully", desc="Your KYC details is send to admin", user=request.user)
                        return Response({
                            'message': 'Uploaded kyc details successfully',
                            'user_id': user_id,
                            'user_aadhar_identification_num': user.user_aadhar_identification_num,
                            'is_kyc_verified': user.is_user_kyc_verified
                        })
                    return Response({
                        'message': f'KYC status {user.is_user_kyc_verified}',
                        'user_id': user_id,
                        'user_aadhar_identification_num': user.user_aadhar_identification_num,
                        'is_kyc_verified': user.is_user_kyc_verified
                    })
            except Exception as e:
                return Response({
                    'message': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
            # return Response(serializer.data, )
        return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


class VehicleReportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = VehicleReportSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message":"your vehicle report saved successfully.please wait for an action",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        return Response({
            "message":"something wents wrong",
            "error": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    # authentication_classes = [JWTAuthentication]
    # permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logout Successfully"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            try:
                user = User.objects.get(id=user_id)
                if check_password(serializer.validated_data['old_password'], user.password):
                    user.password = make_password(serializer.validated_data['new_password'])
                    user.save()
                    return Response({"message": "password updated successfully"},
                                    status=status.HTTP_200_OK)
                return Response({"message": "old password doesn't match with your password"}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({
                    'message': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = User.objects.get(id=request.data.get('user_id'))
            if user:
                user.user_name = request.data.get('user_name')
                user.save()
                return Response({
                    "success": True,
                    "status": status.HTTP_200_OK,
                    'user_id': user.id,
                    "user_name": user.user_name,
                    "user_phone": str(user.phone),
                    "user_email": user.email,
                    "message": "Profile updated successfully",
                    "is_kyc_verified": user.is_user_kyc_verified,
                    "token": get_tokens_for_user(user),
                }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_200_OK)


class CustomerSatisfactionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            user_id = request.data['user_id']
            user_details = CustomerSatisfaction.objects.get(user_id=user_id)
            serializer = CustomerSatisfactionSerializer(user_details, data=request.data)
            if serializer.is_valid():
                serializer.save()
                if str(request.data['user_is_satisfied']) == "False":
                    return Response({
                        "message": "Thank You,Your response saved successfully,Our team will connect you soon"
                    }, status=status.HTTP_200_OK)
                return Response({
                    "message": "Thank You,Your response saved successfully"
                    }, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except:
            serializer = CustomerSatisfactionSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                if str(request.data['user_is_satisfied']) == "False":
                    return Response({
                        "message": "Thank You,Your response saved successfully,Our team will connect you soon"
                    }, status=status.HTTP_200_OK)
                return Response({
                    "message": "Thank You,Your response saved successfully"
                    }, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PaymentView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request.data['payment_amount'] = request.data['payment_amount'].replace(',', '')
        request.data['payment_user_id'] = request.user.id
        serializer = PaymentModelSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            # user_id = serializer.validated_data['payment_user_id']
            pay_user_id = request.data['payment_user_id']
            received_amount = request.data['payment_amount']
            data = {
                "account_user_id": pay_user_id,
                "account_amount": received_amount
            }
            try:
                pay_user = UserPaymentAccount.objects.get(account_user_id=pay_user_id)
                amount = pay_user.account_amount
                final_amount = float(amount) + float(received_amount)
                UserPaymentAccount.objects.filter(account_user_id=pay_user_id).update(account_amount=final_amount)
                send_notification(fcm_token=request.user.fcm_token, title="Payment succesfull", desc="Payment Details Saved Successfully, Your wallet has been updated", user=request.user)
                return Response({
                    "message": "Payment Details Saved Successfully, Your wallet has been updated"
                }, status=status.HTTP_201_CREATED)
            except Exception as E:
                serializer = UserPaymentAccountSerializer(data=data)
                if serializer.is_valid():
                    serializer.save()
                    send_notification(fcm_token=request.user.fcm_token, title="Payment Created", desc="Your wallet has been updated", user=request.user)
                    return Response({"message": "Your wallet has been updated"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserAccountBalanceView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kargs):
        user = User.objects.filter(pk=pk).first()
        if user is None:
            return Response({
            "message": "User does not exist"
            }, status=status.HTTP_400_BAD_REQUEST)
        user_account,_ = UserPaymentAccount.objects.get_or_create(account_user_id=user)
        user_payment = PaymentModel.objects.filter(payment_user_id=pk)
        if user_account:
            serializer = UserPaymentAccountSerializer(user_account)
            serializer1 = PaymentModelSerializer(user_payment, many=True)
            return Response({
                "data": serializer.data,
                "payment": serializer1.data
            })
        return Response({
            "message": "User account does not exist"
        }, status=status.HTTP_400_BAD_REQUEST)


class RideStartStopSerializerView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    """
    Ride start pause resume end use cases
    start:
        on start vehicle unlocks and ride cannot be started if end date and time is empty
        and ride should be end before current day
    pause:
        if ride is paused then cannot be paused
    resume:
        if ride is running then cannot be resumed
    end:
        ride can be end when start pause and resume
    """

    def post(self, request, *args, **kwargs):
        serializer = RideStartStopSerializer(data=request.data)
        if serializer.is_valid():
            action = request.data.get('action')
            user_id = request.data.get('user_id')
            scooter_id = request.data.get('scooter_chassis_no')
            current_time = datetime.datetime.now().strftime("%H:%M:%S")
            current_date = datetime.date.today()
            try:
                user = User.objects.get(id=user_id)
                scooter = Vehicle.objects.filter(vehicle_unique_identifier=scooter_id).first()
                # if (scooter.reserverd_user_id is not None) or (scooter.reserverd_user_id != user.id):
                #     return Response({'message': 'ride is reserved'}, status=status.HTTP_400_BAD_REQUEST)
                
                ride_obj = RideTable.objects.filter(vehicle_id=scooter).last()
                
                if action == "start":
                    if ride_obj is not None:
                        if ride_obj.is_ride_end == False:
                            return Response({
                                            'message': 'ride cannot be started vehicle is running',
                                        }, status=status.HTTP_400_BAD_REQUEST)
                            
                    unlock_data = unlock_scooter(scooter.vehicle_name)
                    scooter_coordinate = get_vehicle_location(scooter.vehicle_unique_identifier)
                    scooter_address = scooter.vehicle_station.address if scooter.vehicle_station else geocode_reverse_coordinate(scooter_coordinate)
                    if unlock_data.status_code == 200:
                        if unlock_data.json().get("IsError") == True:
                            return Response({
                                        'message': str(unlock_data.json().get("Message")),
                                    }, status=status.HTTP_400_BAD_REQUEST)
                        scooter.vehicle_station = None
                        scooter.is_reserved = False
                        scooter.is_unlocked = True
                        ride = RideTable(riding_user_id=user, vehicle_id=scooter, start_time=current_time, start_date=current_date, is_ride_running=True, start_location=scooter_address)
                        ride.save()
                        scooter.save()
                        
                        send_notification(fcm_token=request.user.fcm_token, title="Ride Started", desc="You can start your ride now.", user=request.user)
                        return Response({
                                "data": [{
                                    'message': 'ride started',
                                    'ride_id': ride.id
                                }]
                        }, status=status.HTTP_200_OK)
                    else:
                        return Response({
                                        'message': f'{scooter_coordinate} {unlock_data}',
                                    }, status=status.HTTP_400_BAD_REQUEST)

                if ride_obj.is_ride_end == True:
                    return Response({'message': 'ride already ended'}, status=status.HTTP_400_BAD_REQUEST)

                if action == "pause":
                    if ride_obj.is_paused == False:
                        ride_pause_obj = RideTimeHistory.objects.create(ride_table_id=ride_obj, pause_time=current_time)
                        lock_data = lock_scooter(scooter.vehicle_name)
                        if lock_data.status_code == 200:
                            if lock_data.json().get("IsError") == True:
                                return Response({
                                        'message': str(lock_data.json().get("Message")),
                                    }, status=status.HTTP_400_BAD_REQUEST)
                            start = datetime.datetime.strptime(str(ride_obj.start_time), "%H:%M:%S")
                            pause = datetime.datetime.strptime(str(current_time), "%H:%M:%S")
                            delta = pause-start
                            if ride_obj.total_running_time == None:
                                ride_obj.total_running_time = get_sec(str(delta))
                            else:
                                ride_obj.total_running_time = get_sec(str(delta)) + int(ride_obj.total_running_time)
                            ride_obj.is_paused = True
                            ride_obj.save()
                            
                            send_notification(fcm_token=request.user.fcm_token, title="Ride Paused", desc="Your ride is paused.", user=request.user)
                            return Response({
                                "data": [{
                                    'message': 'ride paused',
                                    'ride_id': ride_obj.id
                                }]
                            }, status=status.HTTP_200_OK)
                    else:
                        return Response({
                                        'message': 'ride cannot be paused, it is already paused',
                                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if action == "resume":
                    ride_pause_obj = RideTimeHistory.objects.filter(ride_table_id=ride_obj).last()
                    if ride_obj.is_paused == True:
                        unlock_data = unlock_scooter(scooter.vehicle_name)
                        if unlock_data.status_code == 200:
                            if unlock_data.json().get("IsError") == True:
                                return Response({
                                        'message': str(unlock_data.json().get("Message")),
                                    }, status=status.HTTP_400_BAD_REQUEST)
                            ride_pause_obj.resume_time = str(current_time)
                            ride_obj.is_paused = False
                            pause = datetime.datetime.strptime(str(ride_pause_obj.pause_time), "%H:%M:%S")
                            resume = datetime.datetime.strptime(str(current_time), "%H:%M:%S")
                            delta = resume-pause
                            ride_pause_obj.pause_duration = get_sec(str(delta))
                            if ride_obj.total_pause_time == None:
                                ride_obj.total_pause_time = get_sec(str(delta))
                            else:
                                ride_obj.total_pause_time = get_sec(str(delta)) + int(ride_obj.total_pause_time)
                            ride_obj.save()
                            ride_pause_obj.save()
                            
                            send_notification(fcm_token=request.user.fcm_token, title="Ride Resumed", desc="Your ride is resumed.", user=request.user)
                            return Response({
                                "data": [{
                                    'message': 'ride resume',
                                    'ride_id': ride_obj.id
                                }]
                            }, status=status.HTTP_200_OK)
                    else:
                        return Response({
                                        'message': 'ride cannot be resumed, it is already running',
                                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if action == 'end':
                    ride_pause_queryset = RideTimeHistory.objects.filter(ride_table_id=ride_obj)
                    if ride_obj.is_ride_end == False:
                        update_or_create_vehicle_data()
                        # val = 0.0010
                        # lat = float(scooter.lat)
                        # long = float(scooter.long)
                        # station_obj = Station.objects.filter(lat__gte=lat-val, lat__lte=lat+val, long__gte=long-val, long__lte=long+val).first()
                        # if station_obj is None:
                        #     return Response({'message': 'You cannot end ride here, ride can only be ended at a station'}, status=status.HTTP_400_BAD_REQUEST)
                        lock_data = lock_scooter(scooter.vehicle_name)
                        if lock_data.status_code == 200:
                            if lock_data.json().get("IsError") == True:
                                return Response({
                                        'message': str(lock_data.json().get("Message")),
                                    }, status=status.HTTP_400_BAD_REQUEST)
                            # scooter.vehicle_station = station_obj
                            scooter.is_unlocked = False
                            scooter.booked_user_id = None
                            scooter.is_booked = False
                            scooter.save()
                            
                            delta = 0
                            end = datetime.datetime.strptime(str(current_time), "%H:%M:%S")
                            if len(ride_pause_queryset) == 0:
                                start = datetime.datetime.strptime(str(ride_obj.start_time), "%H:%M:%S")
                                delta = end - start
                                ride_obj.total_pause_time = 0
                                ride_obj.total_running_time = get_sec(str(delta))
                                
                            else:
                                ride_pause_queryset_obj = ride_pause_queryset.last()
                                if ride_obj.is_paused == True:
                                    pause = datetime.datetime.strptime(str(ride_pause_queryset_obj.pause_time), "%H:%M:%S")
                                    end = datetime.datetime.strptime(str(current_time), "%H:%M:%S")
                                    ride_pause_queryset_obj.resume_time = end
                                    delta = end - pause
                                    ride_pause_queryset_obj.pause_duration = get_sec(str(delta))
                                    ride_pause_queryset_obj.save()
                                    delta = "0:0:0"
                                    
                                else:
                                    resume = datetime.datetime.strptime(str(ride_pause_queryset_obj.resume_time), "%H:%M:%S")
                                    delta = end - resume
                                    
                                total_pause_time = ride_pause_queryset.aggregate(Sum('pause_duration'))["pause_duration__sum"]
                                ride_obj.total_pause_time = total_pause_time
                                ride_obj.total_running_time = get_sec(str(delta)) + int(ride_obj.total_running_time)
                            
                            ride_obj.end_time = end
                            ride_obj.end_date = datetime.date.today()
                            ride_obj.is_ride_running = False
                            ride_obj.is_ride_end = True
                            ride_obj.is_paused = False
                            scooter_coordinate = get_vehicle_location(scooter.vehicle_unique_identifier)
                            ride_obj.end_location = scooter.vehicle_station.address if scooter.vehicle_station else geocode_reverse_coordinate(scooter_coordinate)
                            ride_obj.save()

                            km_list = [1.3, 0.5, 1.21, 0.73, 1.91, 1.68, 2.43, 1.76]
                            ride_distance = random.choice(km_list)#calculate_ride_distance(ride_obj.start_location, ride_obj.end_location)
                            user.total_km += ride_distance
                            user.save()
                            
                            carbon_footprint = carbon_calculation(ride_distance)
                            user.total_carbon_saved += carbon_footprint
                            user.save()
                            
                            """
                            for every 30 minutes only 10 minutes pause time is available to user
                            for 60 minutes 20 minutes pause time is available
                            i.e. ratio of 1:3
                            
                            e.g. running time is 50 minutes and pause time is 20 minutes ratio is 
                                0.4 and it is greater than 0.3 i.e. user can take 10 min pause time
                                
                            e.g. running time is 70 min and pause time is 20 min ratio is 
                                0.28 and it is less than 0.3 i.e. user can take 20 min pause
                                
                            e.g. running time is 60 min and pause time is 15 min ratio is .25 then
                                user can take 15 min pause time
                                
                            e.g. running time is 60 min and pause time is 25 min then ratio is .4 then 
                                user can take 20 minutes of break
                            """
                            
                            per_min_running_charge = float(ride_obj.vehicle_id.per_min_charge)
                            per_min_pause_charge = float(ride_obj.vehicle_id.per_pause_charge)
                            total_pause_time = float(ride_obj.total_pause_time) / 60
                            total_running_time = float(ride_obj.total_running_time) / 60
                            total_time = total_pause_time + total_running_time
                            ratio = total_pause_time / total_time
                            
                            total_cost = None
                            pause_cost = None
                            running_cost = None
                            if ratio <= (1/3):
                                running_cost = (total_running_time) * per_min_running_charge
                                pause_cost = (total_pause_time) * per_min_pause_charge
                                total_cost = running_cost + pause_cost
                            else:
                                available_pause_min = math.floor(total_time/30) * 10
                                pause_cost = available_pause_min * per_min_pause_charge
                                considered_running_min = total_time - available_pause_min
                                running_cost = considered_running_min * per_min_running_charge
                                total_cost = running_cost + pause_cost
                                
                            gst_cost = total_cost * (18 / 100)
                            total_cost_with_gst = round(total_cost + gst_cost, 2)
                            ride_obj.running_cost = running_cost
                            ride_obj.pause_cost = pause_cost
                            ride_obj.total_cost = total_cost
                            ride_obj.gst_cost = gst_cost
                            ride_obj.total_cost_with_gst = total_cost_with_gst
                            ride_obj.ride_km = ride_distance
                            ride_obj.save()
                            
                            trip_statistics = {
                                "per_minute_charges_on_running": per_min_running_charge,
                                "total_running_mins": f'{time.strftime("%M:%S", time.gmtime(float(total_running_time)*60))} Min',
                                "per_minute_charges_on_pause": per_min_pause_charge,
                                "total_pause_mins": f'{time.strftime("%M:%S", time.gmtime(float(total_pause_time)*60))} Min' if total_pause_time else '00:00 Min',
                                "total_min_cost": round(total_cost, 2),
                                "total_pause_cost": round(pause_cost, 2),
                                "total_km": ride_distance,
                                "gst": '18%',
                                "gst_cost": round(gst_cost, 2),
                                "total_cost": total_cost_with_gst,
                                "total_ride_min": f'{time.strftime("%M:%S", time.gmtime(float(total_time)*60))} Min' if total_time else '00:00 Min'
                            }
                            
                            payment = PaymentModel(payment_user_id=user, payment_amount=-total_cost_with_gst, payment_date=datetime.date.today(), payment_note='Book Ride')
                            payment.save()
                            user_payment,_ = UserPaymentAccount.objects.get_or_create(account_user_id=payment.payment_user_id)
                            user_payment.account_amount = float(user_payment.account_amount) if user_payment else 0 - float(total_cost_with_gst)
                            user_payment.save()
                            ride_obj.payment_id = payment
                            ride_obj.save()
                            
                            send_notification(fcm_token=request.user.fcm_token, title="Ride ended", desc="Your ride is ended.", user=request.user)
                            return Response({
                                "data": [{
                                    'message': 'ride end',
                                    'ride_id': ride_obj.id,
                                    'trip_statistics': trip_statistics
                                }]
                            }, status=status.HTTP_200_OK)
                        return Response({'message': 'something went wrong'}, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({'message': 'ride already ended'}, status=status.HTTP_401_UNAUTHORIZED)
                
            except Exception as e:
                print('e: ', e.__traceback__())
                return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanBarcodeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, pk, *args, **kwargs):
        data = request.data
        vin = data.get("scooter_chassis_no")
        if data and data.get("scooter_chassis_no"):
            try:
                scooter = Vehicle.objects.get(vehicle_unique_identifier=vin)
                if scooter.is_under_maintenance:
                    return Response(
                        {
                            'message': "This scooter is under maintenance!! please try some other scooter"
                        }, status=status.HTTP_400_BAD_REQUEST)
                if scooter.is_reserved:
                    if scooter.reserverd_user_id and scooter.reserverd_user_id.id == pk:
                        scooter.is_booked = True
                        scooter.reserverd_user_id = None
                        scooter.is_reserved = False
                        scooter.booked_user_id = scooter.reserverd_user_id
                        scooter.save()
                        return Response(
                            {"data": [{
                                'scooter_chassis_num': scooter.vehicle_unique_identifier,
                                'battery_percentage': scooter.battery_percentage,
                                'iot_device_number': scooter.iot_device_number,
                                'scooter_number': scooter.scooter_number,
                                'battery_number': scooter.battery_number,
                                'current_location': scooter.current_location,
                                'total_km_capacity': scooter.total_km_capacity,
                                'per_min_charge': scooter.per_min_charge}]
                            }, status=status.HTTP_200_OK)
                    return Response(
                        {
                            'message': "Already Reserved, you cannot book this scooter!! please try some other scooter"
                        }, status=status.HTTP_400_BAD_REQUEST)
                else:
                    user = User.objects.get(id=pk)
                    if user.reserved_Vehicle_User.filter(vehicle_unique_identifier=vin):
                        return Response(
                        {
                            'message': "You cannot book this scooter, try scanning the scooter that you reserved"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    scooter.is_booked = True
                    scooter.reserverd_user_id = None
                    scooter.is_reserved = False
                    scooter.booked_user_id = user
                    scooter.save()
                    return Response(
                        {"data":[{
                            'scooter_chassis_num': scooter.vehicle_unique_identifier,
                            'battery_percentage': scooter.battery_percentage,
                            'iot_device_number': scooter.iot_device_number,
                            'scooter_number': scooter.scooter_number,
                            'battery_number': scooter.battery_number,
                            'current_location': scooter.current_location,
                            'total_km_capacity': scooter.total_km_capacity,
                            'per_min_charge': scooter.per_min_charge}]
                        }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({
                    'message': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'scooter_chassis_no': 'This field is required'
        }, status=status.HTTP_400_BAD_REQUEST)


class AllNotifications(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self,request,*args,**kwargs):
        all_notifations = NotificationModel.objects.filter(user_id=request.user).order_by("-created_at")
        serializer = NotificationSerializer(all_notifations,many=True)
        return Response({
            "data":serializer.data
        },status=status.HTTP_200_OK)
        
    def post(self, request):
        fcm_token = request.user.fcm_token
        title = request.data.get("title")
        desc = request.data.get("desc")
        response = send_notification(fcm_token=fcm_token, title=title, desc=desc, user=request.user)
        if response.status_code == status.HTTP_200_OK:
            serializer = NotificationSerializer(data = request.data)
            if serializer.is_valid():
                serializer.save()
                final_response = {
                    "data":serializer.data
                }
                return Response(final_response, status=response.status_code)
        final_response = {
            "data": response
        }
        return Response(final_response, status=response.status_code)
      
            
class AdminUserRegisterUserView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        if request.data:
            try:
                serializer = AdminUserRegistrationSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    # send_otp_via_email(serializer.validated_data['email'])
                    email = serializer.validated_data['email']
                    user = User.objects.get(email=email)
                    token = get_verification_token(user)
                    user.save()
                    response = {
                        "status_code": status.HTTP_201_CREATED,
                        'user_id': user.id,
                        "user_name": user.user_name,
                        "user_phone": str(user.phone),
                        "user_email": str(user.email),
                    }
                    link = f"http://{request.get_host()}/verify_admin_user/?token={token}"
                    send_verification_link(email, link)
                    return Response(response, status=status.HTTP_201_CREATED)
                response = {
                    "status_code": status.HTTP_400_BAD_REQUEST,
                    "errors": serializer.errors
                }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                print('e: ', e.__traceback__())
                return Response({
                    "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "message": "Something went wrong"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": "Data not found"
            }, status=status.HTTP_400_BAD_REQUEST)
        

class AdminVerificationLink(APIView):
    
    def get(self, request):
        token = request.query_params["token"]
        user_id = decode_verification_token(token)
        try:
            user_obj = User.objects.get(pk=user_id)
        except:
            return Response({
                "status_code": status.HTTP_400_BAD_REQUEST,
                "message": "User not found"
            }, status=status.HTTP_400_BAD_REQUEST)
        user_obj.is_email_verified = True
        user_obj.save()
        response = {"message": "Email verified successfuly"}
        return Response(response, status=status.HTTP_200_OK)


class AdminUserLogin(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        serializer = AdminUserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            fcm_token = serializer.validated_data['fcm_token']
            user = User.objects.filter(email=email)
            if user:
                user_validate = authenticate(email=email, password=password)
                user = User.objects.get(email=email)
                # if user.is_email_verified:
                if user_validate:
                    token = get_tokens_for_user(user)
                    response = {
                        "status_code": 200,
                        "message": "User logged in Successfully",
                        'user_id': user.id,
                        "user_name": user.user_name,
                        "user_phone": str(user.phone),
                        "user_email": user.email,
                        "user_role": user.user_role,
                        "token": token
                    }
                    user.fcm_token = fcm_token
                    user.save()
                    return Response(response, status=status.HTTP_200_OK)
                # send_otp_via_email(user.email)
                return Response({
                    "status_code": 400,
                    'message': "user has not verified the email, please check your email and verify it using OTP sent to your email address",
                    'user_id': user.id
                }, status.HTTP_400_BAD_REQUEST)
            return Response({
                "status_code": 400,
                'message': "username or password does not match!! please enter correct credentials"
            }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllAdminUsers(APIView, CustomPagination, SearchFilter):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]
    search_fields = ["user_name", "phone", "email"]
    
    def get(self,request,*args,**kwargs):
        user = self.filter_queryset(request=request, model=User, view=self.__class__).exclude(user_role=5)
        page = request.query_params.get("page") if request.query_params.get("page") else 1
        limit = request.query_params.get("limit") if request.query_params.get("limit") else 10
        results = self.paginate(page=page, request=request, limit=limit, queryset=user, view=self)
        data = GetAllUserSerializer(results,many=True)
        return Response({
            "data":data.data
        },status=status.HTTP_200_OK)


class GetCurrentRideTime(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = RideRunningTimeGet(data=request.data)
        if serializer.is_valid():
            try:
                ride = serializer.validated_data['ride_id']
                user = serializer.validated_data['user_id']
                scooter_chassis_no = serializer.validated_data['scooter_chassis_no']
                current_time = datetime.datetime.now().strftime("%H:%M:%S")
                ride_id = RideTable.objects.filter(id=ride).last()
                vehicle_obj = Vehicle.objects.filter(pk = ride_id.vehicle_id.pk).first()

                if ride_id.is_ride_end == True:
                    return Response({
                        'message': 'Ride already ended.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if ride_id is None:
                    return Response({
                        'message': 'User Data or Vehicle Data does not match with ride data.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if ride_id.is_paused == True:
                    running_time = str(datetime.timedelta(seconds=ride_id.total_running_time))
                    min, sec = divmod(get_sec(str(running_time)), 60)
                    hour, min = divmod(min, 60)
                    time = '%d:%02d:%02d' % (hour, min, sec)
                    data = {
                        'ride_running_time': time,
                        'battery_percentage': vehicle_obj.battery_percentage
                    }
                    return Response(data=data, status=status.HTTP_200_OK)
                                    
                current = datetime.datetime.strptime(str(current_time), "%H:%M:%S")
                start = datetime.datetime.strptime(str(ride_id.start_time), "%H:%M:%S")
                pause_time = str(datetime.timedelta(minutes=ride_id.total_pause_time))
                delta = current - start - pause_time
                min, sec = divmod(get_sec(str(delta)), 60)
                hour, min = divmod(min, 60)
                time = '%d:%02d:%02d' % (hour, min, sec)
                data = {
                    'ride_running_time': time,
                    'battery_percentage': vehicle_obj.battery_percentage
                }
                return Response(data=data, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({
                    'message': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllKycUsers(APIView, CustomPagination, SearchFilter):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    search_fields = ["user_name", "phone", "email"]

    def get(self, request, *args, **kwargs):
        kyc_status = request.query_params.get("status") if request.query_params.get("status") else None
        user = super().filter_queryset(request=request, model=User, view=self.__class__, status=kyc_status).exclude(is_user_kyc_verified='NA').filter(user_role=5)
        get_pending_user_count = user.filter(is_user_kyc_verified='Pending').count()
        get_rejected_user_count = user.filter(is_user_kyc_verified='Rejected').count()
        get_approved_user_count = user.filter(is_user_kyc_verified='Approved').count()
        page = request.query_params.get("page") if request.query_params.get("page") else 1
        limit = request.query_params.get("limit") if request.query_params.get("limit") else 10
        results = self.paginate(page=page, request=request, limit=limit, queryset=user, view=self)
        data = GetAllKycUserSerializer(results, many=True)
        return Response({
            'total_user_count': user.count(),
            'pending_user_count': get_pending_user_count,
            'rejected_user_count': get_rejected_user_count,
            'approved_user_count': get_approved_user_count,
            "data": data.data
        }, status=status.HTTP_200_OK)


class AcceptRejectKycDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            data = request.data
            user_id = data.get('user_id')
            kyc_status = data.get('is_kyc_verified')
            user = User.objects.get(id=user_id)
            if kyc_status in ['Approved', 'Rejected']:
                user.is_user_kyc_verified = kyc_status
                user.save()
                response = {
                    'message': f'Kyc Details Updated Successfully'
                }
                send_notification(fcm_token=user.fcm_token, title="KYC Verification", desc=f"Your KYC status is {kyc_status}", user=user)
                return Response(response, status=status.HTTP_200_OK)
            response = {
                'message': f"Kyc status should be \'Approved', 'Rejected'"
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            response = {
                'message': str(e)
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class GetUserKycUpdate(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            user = User.objects.get(id=pk)
            response = {
                'message': f'User Kyc has been {user.is_user_kyc_verified}'
            }
            if user.is_user_kyc_verified == 'Approved':
                return Response(response, status=status.HTTP_200_OK)
            if user.is_user_kyc_verified == 'Rejected':
                return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            response = {
                'message': str(e)
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class CompleteRideDetail(APIView):
    def post(self, request, pk, *args, **kwargs):
        data = request.data
        ride_id = data.get('ride_id')
        try:
            ride = RideTable.objects.get(riding_user_id=pk, id=ride_id)
            ride_pause_time_in_secondes = str(ride.total_pause_time)
            final_time = str(ride.total_running_time)
            total_km = 3
            per_min_cost_on_running = round(float(ride.vehicle_id.per_min_charge) / 60, 4)
            per_min_pause_cost = round(float(ride.vehicle_id.per_pause_charge)/60, 4)
            ride_pause_time_cost = float(ride_pause_time_in_secondes) * float(per_min_pause_cost)
            total_cost = float(per_min_cost_on_running) * float(final_time) + (ride_pause_time_cost)
            gst_cost = total_cost * 5 / 100
            response = {
                "total_cost": round(total_cost + gst_cost, 2),
                "pause_cost": round(ride_pause_time_cost, 2),
                "total_km": total_km,
                "gst": '5%',
                "gst_cost": round(gst_cost, 2),
                "per_minute_charges_on_running": 2.5,
                "per_minute_charges_on_pause": 0.5,                
            }
            return Response(response, status=status.HTTP_200_OK)
        except Exception as e:
            response = {
                "message": str(e)
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class UnlockScooter(APIView):

    def post(self, request, pk):
        user = User.objects.get(id=pk)
        vin = Vehicle.objects.get(vehicle_unique_identifier=request.data.get('scooter_chassis_number'))
        unlock_data = unlock_scooter(vin.vehicle_unique_identifier)
        if unlock_data.status_code == 200:
            vin.is_unlocked = True
            vin.save()
            return Response(unlock_data.json(), status=status.HTTP_200_OK)
        return Response(unlock_data.json(), status=status.HTTP_400_BAD_REQUEST)


class UserRideHistory(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        ride = RideTable.objects.filter(riding_user_id=pk, is_ride_end=True)
        serializer = UserRideSerializer(ride, many=True)
        return Response({
            "data": serializer.data,
        }, status=status.HTTP_200_OK)


class UserRideDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, ride_id, *args, **kwargs):
        try:
            ride = RideTable.objects.get(id=ride_id, is_ride_end=True)
            ride_data = RideTable.objects.filter(id=ride_id, is_ride_end=True)
            serializer = UserRideDetailsSerializer(ride_data, many=True)
            trip_statistics = {
                "per_minute_charges_on_running": 2.5,
                "total_running_mins": f'{time.strftime("%M:%S", time.gmtime(int(ride.total_running_time)))} Min',
                "per_minute_charges_on_pause": 0.5,
                "total_pause_mins": f'{time.strftime("%M:%S", time.gmtime(int(ride.total_pause_time)))} Min' if ride.total_pause_time else '00:00 Min',
                "total_min_cost": round(ride.running_cost, 2),
                "total_pause_cost": round(ride.pause_cost, 2),
                "total_km": ride.ride_km,
                "gst": '18%',
                "gst_cost": round(ride.gst_cost, 2),
                "total_cost": round(ride.total_cost_with_gst, 2),
            }
            return Response({
                "data": serializer.data[0],
                'invoice_details': trip_statistics
            })
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class GetAvailableVehicles(ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        all_data = []
        pk = request.user.id
        user_lat = str(request.data.get("user_lat"))
        user_long = str(request.data.get("user_long"))
        update_or_create_vehicle_data()
        station = Station.objects.all()
        try:
        # "scooter_data": [
        #         {
        #             "latitude": "23.25248",
        #             "longtitude": "72.63383",
        #             "vehicle": "WCM202100002",
        #             "is_reserved": false,
        #             "reserved_user": "",
        #             "per_min_charge": "2.5",
        #             "battery_percentage": 50,
        #             "max_km_capacity": "25/Km"
        #         },
            for key in station:
                scooter = list(key.station_object.all().values("lat", "long", "vehicle_unique_identifier", "is_reserved", "reserverd_user_id", "per_min_charge", "battery_percentage", "total_km_capacity"))
                station_dict = model_to_dict(key)
                station_dict["scooter_data"] = scooter
                all_data.append(station_dict)
                # all_data.append({
                #     "location_stand": "Sector 25, Gandhinagar, Gandhinagar Taluka, Gandhinagar District, Gujarat, 382027, India",
                #     "latitude": scooter[0].get('latitude'),
                #     "longitude": scooter[0].get('longtitude'),
                #     "scooter_data": scooter,
                # })
            return Response({'vehicle_data': all_data }, status=status.HTTP_200_OK)
        except Exception as E:
            print('E: ', str(E))
            return Response({"message":"Something went wrong", 'Exception': str(E)}, status=status.HTTP_400_BAD_REQUEST)
        all_data = {
            "vehicle_data": [
                {
                    "location_stand": "Ghatlodiya, Ahmedabad, Ahmedabad City Taluka, Ahmedabad District, Gujarat, 380001, India",
                    "latitude": "23.07608",
                    "longitude": "72.52638",
                    "scooter_data": [
                        {
                            "latitude": "23.07608",
                            "longtitude": "72.52638",
                            "vehicle": "WCM202100002",
                            "is_reserved": True,
                            "reserved_user": 1,
                            "per_min_charge": 2.5,
                            "battery_percentage": 50,
                            "max_km_capacity": "25/Km"
                        },
                        {
                            "latitude": "23.07608",
                            "longtitude": "72.52638",
                            "vehicle": "WCM202100002",
                            "is_reserved": True,
                            "reserved_user": 1,
                            "per_min_charge": 2.5,
                            "battery_percentage": 20,
                            "max_km_capacity": "25/Km"
                        },
                        {
                            "latitude": "23.07608",
                            "longtitude": "72.52638",
                            "vehicle": "WCM202100002",
                            "is_reserved": False,
                            "reserved_user": 1,
                            "per_min_charge": 2.5,
                            "battery_percentage": 50,
                            "max_km_capacity": "25/Km"
                        },
                        {
                            "latitude": "23.07608",
                            "longtitude": "72.52638",
                            "vehicle": "WCM202100002",
                            "is_reserved": False,
                            "reserved_user": 1,
                            "per_min_charge": 2.5,
                            "battery_percentage": 30,
                            "max_km_capacity": "25/Km"
                        }
                    ]
                },
                {
                    "location_stand": "Gandhinagar-Sarkhej Highway, Gandhinagar, Gandhinagar Taluka, Gandhinagar District, Gujarat, 382423, India",
                    "latitude": "23.18250",
                    "longitude": "72.59683",
                    "scooter_data": []
                },
                {
                    "location_stand": "Iscon, Gandhinagar-Sarkhej Highway, Gujarat, 382423, India",
                    "latitude": "23.0202434",
                    "longitude": "72.5797426",
                    "scooter_data": []
                },
                {
                    "location_stand": "Panjrapol, Ahmedabad, Ahmedabad City Taluka, Ahmedabad District, Gujarat, 380001, India",
                    "latitude": "23.07685",
                    "longitude": "72.52658",
                    "scooter_data": [
                        {
                            "latitude": "23.07608",
                            "longtitude": "72.52638",
                            "vehicle": "WCM202100002",
                            "is_reserved": True,
                            "reserved_user": 1,
                            "per_min_charge": 2.5,
                            "battery_percentage": 50,
                            "max_km_capacity": "25/Km"
                        },
                        {
                            "latitude": "23.07608",
                            "longtitude": "72.52638",
                            "vehicle": "WCM202100002",
                            "is_reserved": True,
                            "reserved_user": 1,
                            "per_min_charge": 2.5,
                            "battery_percentage": 20,
                            "max_km_capacity": "25/Km"
                        },
                        {
                            "latitude": "23.07608",
                            "longtitude": "72.52638",
                            "vehicle": "WCM202100002",
                            "is_reserved": False,
                            "reserved_user": 1,
                            "per_min_charge": 2.5,
                            "battery_percentage": 50,
                            "max_km_capacity": "25/Km"
                        },
                    ]
                },
            ]
        }
        return Response(all_data, status=status.HTTP_200_OK)


    @action(methods=['GET'], detail=False)
    def station_list(self, request):
        try:
            all_data = []
            pk = request.user.id
            update_or_create_vehicle_data()
            
            station_queryset = Station.objects.all()
            for key in station_queryset:
                scooter = key.station_object.filter(vehicle_station=key.id)
                serializer = StationVehicleSerializer(scooter, many=True)
                all_data.append({
                    "station_id": key.id,
                    "location_stand": key.address,
                    "latitude": key.lat,
                    "longitude": key.long,
                })
            return Response({'station_data': all_data }, status=status.HTTP_200_OK)
        except Exception as E:
            print('E: ', str(E))
            return Response({"message":"Something went wrong", 'Exception': str(E)}, status=status.HTTP_400_BAD_REQUEST)
    
    def retrieve(self, request, pk=None):
        try:
            user_id = request.user.id
            update_or_create_vehicle_data()
            station_obj = Station.objects.filter(pk=pk).first()
            scooter = station_obj.station_object.filter(vehicle_station=station_obj.id)
            serializer = StationVehicleSerializer(scooter, many=True)
            return Response({'vehicle_data': serializer.data }, status=status.HTTP_200_OK)
        except Exception as E:
            print('E: ', str(E))
            return Response({"message":"Something went wrong", 'Exception': str(E)}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['POST'], detail=False)
    def vehicle_list(self, request):
        try:
            station_id = request.data.get("station_id")
            user_id = request.user.id
            update_or_create_vehicle_data()
            station_obj = Station.objects.filter(pk=station_id).first()
            scooter = station_obj.station_object.filter(vehicle_station=station_obj.id)
            serializer = StationVehicleSerializer(scooter, many=True)
            return Response({'vehicle_data': serializer.data }, status=status.HTTP_200_OK)
        except Exception as E:
            print('E: ', str(E))
            return Response({"message":"Something went wrong", 'Exception': str(E)}, status=status.HTTP_400_BAD_REQUEST)

    # @action(methods=['POST'], detail=True)
    # def retrieve(self, request, pk):
    #     """
    #     api for see a vehicle details
    #     """
    #     response = get_vehicle_detials(vin=pk, user=request.user)
    #     vehicle_data = response.json().get("data").get("vehicle")[0]
    #     vehicle_unique_identifier = vehicle_data.get("vin")
    #     vehicle_obj = Vehicle.objects.get_or_create(vehicle_unique_identifier=vehicle_unique_identifier)
    #     serializer = ReserveSerializer(vehicle_obj)
    #     response_data = {"data": serializer.data}
    #     return Response(response_data, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False)
    def reserve(self, request):
        """api for reserve vehicle, reservation will be only available for 10 minutes,
        after 30 minutes it will be released to reserve
        request data is vehicle id
        """
        try:
            vid = request.data.get("vid")
            vehicle_obj = Vehicle.objects.filter(vehicle_unique_identifier=vid).first()
            user_obj = User.objects.filter(pk=request.user.id).first()
            serializer = ReserveSerializer(vehicle_obj)
            # if vehicle_obj.booked_user_id is not None:
            #         return Response({'message': 'ride is booked'}, status=status.HTTP_400_BAD_REQUEST)
            if vehicle_obj.is_reserved == True:
                response_data = {"data": serializer.data, "message": "Vehicle is already reserved"}
                return Response(response_data, status=status.HTTP_200_OK)
            vehicle_obj.reserverd_user_id = user_obj
            vehicle_obj.is_reserved = True
            vehicle_obj.save()
            timer = countdown_timer.delay(vid)
            Vehicle.objects.filter(vehicle_unique_identifier=vid).update(celery_task_id=timer.id)
            serializer = ReserveSerializer(vehicle_obj)
            response_data = {"data": serializer.data, "message": "Vehicle reserved for 10 minutes"}
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as E:
            response_data = {"data": E, "message": "Something went wrong"}
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    @action(methods=['POST'], detail=False)
    def cancel(self, request):
        """api for cancel reserved vehicle,
        request data is vehicle id
        """
        try:
            vehicle_obj = Vehicle.objects.filter(vehicle_unique_identifier=request.data.get("vid")).first()
            user_obj = User.objects.filter(pk=request.user.id).first()
            if vehicle_obj.reserverd_user_id == user_obj:
                vehicle_obj.reserverd_user_id = None
                vehicle_obj.is_reserved = False
                vehicle_obj.save()
                app.control.revoke(vehicle_obj.celery_task_id, terminate=True, signal='SIGKILL')
                serializer = ReserveSerializer(vehicle_obj)
                response_data = {"data": serializer.data, "message": "Vehicle reservation cancelled"}
            else:
                serializer = ReserveSerializer(vehicle_obj)
                response_data = {"data": serializer.data, "message": "User cannot cancel this reservation"}
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as E:
            response_data = {"error":E, "message": "Something went wrong"}
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAllUsersData(APIView, CustomPagination, SearchFilter):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    page_size = 10
    page_size_query_param = 'count'
    search_fields = ["user_name", "phone", "email"]

    def get(self, request):
        user = User.objects.filter(user_role=5).count()
        try:
            user_status = bool(int(request.query_params.get("status"))) if request.query_params.get("status") else None
        except:
            user_status = None
        users_list = self.filter_queryset(request=request, model=User, view=self.__class__, status=user_status).filter(user_role=5)
        page = request.query_params.get("page") if request.query_params.get("page") else 1
        limit = request.query_params.get("limit") if request.query_params.get("limit") else 10
        results = self.paginate(page=page, request=request, limit=limit, queryset=users_list, view=self)
        serializer = GetAllUsersSerializer(results, many=True)
        return Response({
            'Total_Users': user,
            'Users_details': serializer.data
        })


class ResetPasswordView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        user = User.objects.filter(email=email)
        if user:
            generated_otp = send_otp_session_via_email(email)
            session_data = SessionStore()
            session_data['otp'] = generated_otp
            session_data['email'] = email
            session_data.create()
            return Response({
                "msg": "successfull",
                "session_key": session_data.session_key
            })
        return Response({
            "msg": "You are not a registered user,please register"
        })


class VeifyOtpForPasswordReset(APIView):
    def post(self, request, *args, **kwargs):
        received_otp = request.data.get('otp')
        session_id = request.data.get('session_id')
        session_stored_data = SessionStore(session_key=session_id)
        try:
            data = session_stored_data['otp']
        except:
            return Response({
                "msg": "Your OTP has been expired,Please generate otp once again"
            }, status=status.HTTP_403_FORBIDDEN)
        if int(received_otp) == int(data):
            return Response({
                "msg": "Your email verified successfully,Please Create a new password"
            }, status=status.HTTP_200_OK)
        return Response({
            "msg": "Please Enter a valid otp"
        }, status=status.HTTP_400_BAD_REQUEST)


class CreateNewPassword(APIView):

    def post(self, request):
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        session_id = request.data.get('session_id')
        session_stored_data = SessionStore(session_key=session_id)
        try:
            data = session_stored_data['email']
        except:
            return Response({
                "msg": "User not found or session expired"
            }, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.get(email=data)
        if user and new_password == confirm_password:
            user.set_password(new_password)
            user.save()
            return Response({
                "msg": "password updated successfully"
            }, status=status.HTTP_200_OK)
        return Response({
            "msg": "something went wrong"
        }, status=status.HTTP_400_BAD_REQUEST)


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]


class StationApi(ModelViewSet):
    queryset = Station.objects.all()
    serializer_class = StationSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]


class VoucherApi(CustomViewSet, CustomPagination):
    queryset = Voucher.objects.all()
    serializer_class = VoucherSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter]
    search_fields = ["code", "amount"]
    
    def list(self, request, *args, **kwargs):
        self.voucher = Voucher.objects.all().count()
        try:
            voucher_status = bool(int(request.query_params.get("status"))) if request.query_params.get("status") else None
        except:
            voucher_status = None
        try:
            used_status = bool(int(request.query_params.get("is_used"))) if request.query_params.get("is_used") else None
        except:
            used_status = None
        queryset = Voucher.objects.all()
        voucher_list = self.filter_queryset(queryset=queryset)
        if voucher_status:
            voucher_list = voucher_list.filter(is_active=voucher_status)
        if used_status:
            voucher_list = voucher_list.filter(is_used=used_status)
        page = request.query_params.get("page") if request.query_params.get("page") else 1
        limit = request.query_params.get("limit") if request.query_params.get("limit") else 10
        results = super().paginate(page=page, request=request, limit=limit, queryset=voucher_list, view=self)
        serializer = VoucherSerializer(results, many=True)
        # return Response({
        #     'total_vouchers': voucher,
        #     'results': serializer.data,
        #     "status": status.HTTP_200_OK,
        # }, status=status.HTTP_200_OK)
        return super().list(serializer.data, *args, **kwargs)

    def retrieve(self, request, pk=None, *args, **kwargs):
        try:
            voucher = Voucher.objects.get(pk=pk)
        except:
            return Response({'message': "Voucher not found"}, status=status.HTTP_400_BAD_REQUEST)
        serializer = VoucherSerializer(voucher)
        # return Response({
        #     'data': serializer.data,
        #     "status": status.HTTP_200_OK,
        # }, status=status.HTTP_200_OK)
        return super().retrieve(serializer.data, *args, **kwargs)


class RedeemVoucherApi(ViewSet):
    authentication_classes = [JWTAuthentication]
    
    def create(self, request):
        code = request.data.get("code")
        
        try: 
            voucher_obj = Voucher.objects.get(code=code, is_active=True, is_used=False)
        except: 
            return Response({'message': "Voucher not found"}, status=status.HTTP_400_BAD_REQUEST)
        
        voucher_obj.is_used = True
        voucher_obj.used_by = request.user
        voucher_obj.save()
        
        serializer = RedeemVoucherSerializer(voucher_obj)
        response = {"message":f"{voucher_obj.amount} amount will be transferred to your wallet", "data":serializer.data}
        return Response(response, status=status.HTTP_200_OK )

class AppVersionApi(ViewSet):
    def list(self, request):
        queryset = AppVersion.objects.all()
        serializer = AppVersionSerializer(queryset, many=True)
        return Response({"data":serializer.data}, status=status.HTTP_200_OK)
    
    def retrieve(self, request, pk):
        try:
            version_obj = AppVersion.objects.get(pk=pk)
        except:
            return Response({"data":"version does not exists"}, status=status.HTTP_400_BAD_REQUEST)
        serializer = AppVersionSerializer(version_obj)
        return Response({"data":serializer.data}, status=status.HTTP_200_OK)
        


class BattryNotification(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            send_notification(fcm_token=request.user.fcm_token, title="Low battery", desc=f"Low battery", user=request.user)

            response = {
                        'message': f'success'
                    }
            return Response (response, status=status.HTTP_200_OK)
        except Exception as e: 

            return Response({'message': "something went wrong"}, status=status.HTTP_400_BAD_REQUEST)


class BalanceNotification(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            send_notification(fcm_token=request.user.fcm_token, title="Insufficient Balance", desc=f"Add Amount in Your elekgo app", user=request.user)

            response = {
                        'message': f'success'
                    }
            return Response (response, status=status.HTTP_200_OK)
        except Exception as e: 

            return Response({'message': "something went wrong"}, status=status.HTTP_400_BAD_REQUEST)




class ReferralCodeView(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
        
    def post(self, request, *args, **kwargs):
        Serializer = UserRfCodeSerializer(request.data)
        rf_user = None
        user = User.objects.filter(id=request.user.id).first()
        print('user: ', user)
        if user.is_referral_code_used == True:
            response = {
                "message": "referral code is already used",
                "status": status.HTTP_400_BAD_REQUEST,
        
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

        rf = Serializer.data.get("referral_code")
        if rf != "":
            rf_user = User.objects.get(referral_code=rf)
            user.is_referral_code_used = True
            user.save()
            rf_user.rf_used_count += 1
            rf_user.save()
            print('rf_user.count: ', rf_user.rf_used_count)
        else:
            response = {
                "message": "referral code can not be empty",
                "status": status.HTTP_400_BAD_REQUEST,
        
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
            
        response = {
            "message": "referral code is used",
            "status": status.HTTP_201_CREATED,
            'user_id': user.id,
            "referral_code": user.referral_code,
            "rf_user_id":rf_user.id,
            "is_referral_code_used":user.is_referral_code_used,

        }
        return Response(response, status=status.HTTP_201_CREATED)







# class VerifyOtpLogin(APIView):
#     renderer_classes = [UserRenderer]
#
#     def post(self, request, pk, *args, **kwargs):
#         serializer = VerifyAccountSerializerLogin(data=request.data)
#         if serializer.is_valid():
#             otp = serializer.validated_data['otp']
#             try:
#                 user = User.objects.get(id=pk, otp=str(otp))
#             except:
#                 return Response({
#                     "message":"Please enter valid otp"
#                 }, status=status.HTTP_400_BAD_REQUEST)
#             if not user:
#                 return Response({
#                     "message": "Please enter valid otp"
#                 }, status=status.HTTP_400_BAD_REQUEST)
#             
#                 user.fcm_token = serializer.validated_data['fcm_token']
#                 user.is_email_verified = True
#                 user.save()
#                 access_token = create_access_token(user.id)
#                 refresh_token = create_refresh_token(user.id)
#                 id = decode_refresh_token(refresh_token)
#                 refresh_access_token = create_access_token(id)
#                 return Response({
#                     "success": True,
#                     "status": status.HTTP_201_CREATED,
#                     'user_id': user.id,
#                     "user_name": user.user_name,
#                     "user_phone": str(user.phone),
#                     "user_email": user.email,
#                     "message": "logged in successfully",
#                     "is_kyc_verified": user.is_user_kyc_verified,
#                     "access": access_token,
#                     "refresh": refresh_access_token,
#                 }, status=status.HTTP_200_OK)
#         return Response({
#             "message":"Something wents wrong"
#         }, status=status.HTTP_400_BAD_REQUEST)

class OrderAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        orderSerializer = OrderSerializer(data = request.data)
        if orderSerializer.is_valid():
            email = orderSerializer.data.get("email")
            phone = orderSerializer.data.get("phone")
            amount = orderSerializer.data.get("amount")

            print("amount---------------__>",orderSerializer.data,amount,email,phone)         
            payment = PaymentModel.objects.create(payment_amount=amount,phone=phone,payment_user_id = request.user)
            url = "https://sandbox.cashfree.com/pg/orders"

            payload = {
                "customer_details": {
                    "customer_id": str(payment.payment_user_id.id),
                    "customer_email": email,
                    "customer_phone": phone,
                },
                "order_meta": {"payment_methods": "cc"},
                "order_id": payment.order_id,
                "order_amount": amount,
                "order_currency": "INR"
            }
            headers = {
                "accept": "application/json",
                "x-client-id": "325613a9d1a0b3774c6512e194316523",
                "x-client-secret": "de28de047cef87a23c979b986329d9b1e16b0bd4",
                "x-api-version": "2022-01-01",
                "content-type": "application/json"
            }

            response = requests.post(url, json=payload, headers=headers)

            print(response.text)

            return Response(response.json(),status=status.HTTP_200_OK)
        return Response({"error":orderSerializer.errors},status=status.HTTP_400_BAD_REQUEST)

    # @action(methods=["POST"],detail=False)
    # def payment_api(self,request):
    #     pass