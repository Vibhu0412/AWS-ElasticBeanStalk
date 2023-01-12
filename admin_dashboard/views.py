import datetime

from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import AllRideSerialzer, UserPermissionSerializer, ReportDataSerializer, AdminDashboardOverview,\
    AdminProfiileUpdateSerializer, AssetsViewSerializer, VehicleSerializer
from elekgo_app.models import RideTable, User, Vehicle, PaymentModel
from rest_framework import status
from elekgo_app.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from elekgo_app.user_permissions import IsAdminUser, IsCustomeSupport, IsMaintenanceUser, IsStaffUser
from rest_framework.pagination import LimitOffsetPagination
from elekgo_app.views import unlock_scooter, lock_scooter
from django.db.models import Sum
from rest_framework.viewsets import ViewSet, ModelViewSet
from django.db.models.functions import Abs
from elekgo_app.pagination import CustomPagination


class UserRideHistory(APIView, CustomPagination):
    authentication_classes = [JWTAuthentication]
    permission_classes= [IsAdminUser]
    page_size = 20
    page_size_query_param = 'count'

    def get(self, request, *args, **kwargs):
        ride_details = RideTable.objects.all()
        page = request.query_params.get("page") if request.query_params.get("page") else 1
        results = self.paginate(page=page, request=request, queryset=ride_details, view=self)
        serializer = AllRideSerialzer(results,many=True)
        return Response({
            'next_limit': self.limit + 20,
            'next_offset': self.offset + 20,
            'previous_limit': self.limit - 20,
            'previous_offset': self.offset - 20,
            "total_rides": ride_details.count(),
            "status": status.HTTP_200_OK,
            "data": serializer.data
        },status=status.HTTP_200_OK)


class SetUserPermission(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request, *args, **kwargs):
        serializer = UserPermissionSerializer(data=request.data)

        if serializer.is_valid():
            data = serializer.validated_data
            try:
                user_id = serializer.validated_data['id']
                user_permission = serializer.validated_data['user_role']
                user = User.objects.get(id=user_id)
                if user:
                    user.user_role = user_permission
                    user.save()
                response = {
                    'status': 200,
                    'message': 'Permissions updated succesfully'
                }
                return Response(response, status=status.HTTP_200_OK)
            except Exception as e:
                response = {
                    'status': 400,
                    'message': str(e)
                }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'status': 404,
            'data': serializer.errors
        })


class AssetUnlock(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request, pk, *args, **kwargs):
        try:
            vin = request.data.get('vin')
            user = User.objects.get(id=pk)
            scooter = Vehicle.objects.get(vehicle_unique_identifier=vin)
            unlock_data = unlock_scooter(user.bolt_token, vin)
            if unlock_data.status_code == 200:
                scooter.is_unlocked = True
                scooter.save()
                return Response({
                    'status': unlock_data.status_code,
                    'data': unlock_data.json()
                })
            return Response({
                'status': unlock_data.status_code,
                'data': unlock_data.json()
            })
        except Exception as e:
            return Response({
                'status': 400,
                'data': str(e)
            })


class GetAllAssets(APIView, CustomPagination):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request, *args, **kwargs):
        try:
            vehicle = Vehicle.objects.all()
            page = request.query_params.get("page")
            results = self.paginate(page=page, request=request, queryset=vehicle, view=self)
            serializer = AssetsViewSerializer(results, many=True)
            return Response({
                'total_assets': vehicle.count(),
                'status': 200,
                'data': serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'status': 400,
                'data': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class VehicleAdminApi(ModelViewSet):
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]


class AssetLock(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request, pk, *args, **kwargs):
        try:
            vin = request.data.get('vin')
            user = User.objects.get(id=pk)
            scooter = Vehicle.objects.get(vehicle_unique_identifier=vin)
            lock_data = lock_scooter(user.bolt_token, vin)
            if lock_data.status_code == 200:
                scooter.is_unlocked = False
                scooter.save()
                return Response({
                    'status': lock_data.status_code,
                    'data': lock_data.json()
                })
            return Response({
                'status': lock_data.status_code,
                'data': lock_data.json()
            })
        except Exception as e:
            return Response({
                'status': 400,
                'data': str(e)
            })


class GetReportingDataView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request, *args, **kwargs):
        serializer = ReportDataSerializer(data=request.data)
        if serializer.is_valid():
            try:
                range = serializer.validated_data['range']
                vehicle = serializer.validated_data['vehicle']
                report = serializer.validated_data['report']
                start_date = datetime.date.today() + datetime.timedelta(days=-30)
                end_date = datetime.date.today()
                if range == '7D':
                    start_date = datetime.date.today() + datetime.timedelta(days=-7)
                    end_date = datetime.date.today()
                if range == '1M':
                    start_date = datetime.date.today() + datetime.timedelta(days=-30)
                    end_date = datetime.date.today()
                if range == '3M':
                    start_date = datetime.date.today() + datetime.timedelta(days=-90)
                    end_date = datetime.date.today()
                if range == '1Y':
                    start_date = datetime.date.today() + datetime.timedelta(days=-365)
                    end_date = datetime.date.today()
                if range == 'YTD':
                    start_date = datetime.date(year=datetime.date.today().year, month=1, day=1)
                    end_date = datetime.date.today()
                if range != 'date_range':
                    print('start_date: ', start_date)
                    print('end_date: ', end_date)
                    fstart_date = start_date.strftime('%d/%m/%Y')
                    fend_date = end_date.strftime('%d/%m/%Y')
                if range == 'date_range':
                    start_date = serializer.validated_data['start_date_range']
                    fstart_date = datetime.datetime.strptime(start_date, '%d/%m/%Y').date()
                    start_date = fstart_date.strftime("%Y-%m-%d")
                    end_date = serializer.validated_data['end_date_range']
                    fend_date = datetime.datetime.strptime(end_date, '%d/%m/%Y').date()
                    end_date = fend_date.strftime("%Y-%m-%d")
                    
                if vehicle == 'all' and start_date and end_date and report == 'summary':
                    vehicle_data = Vehicle.objects.all()
                    summary = []
                    count = 1
                    for record in vehicle_data:
                        ride = RideTable.objects.filter(vehicle_id=record, start_date__gte=start_date, start_date__lte=end_date)
                        total_running_time = ride.aggregate(Sum('total_running_time'))
                        total_pause_time = ride.aggregate(Sum('total_pause_time'))
                        total_time = total_pause_time.get('total_pause_time__sum') if total_pause_time.get('total_pause_time__sum') else 0 + total_running_time.get('total_running_time__sum') if total_running_time.get('total_running_time__sum') else 0
                        delta = datetime.timedelta(seconds=total_time)
                        h, m, s = str(delta).split(':')
                        vehicle_record = {
                            'sr.no': count,
                            'vin': record.vehicle_unique_identifier,
                            'start_date': fstart_date,
                            'end_date': fend_date,
                            'total_distance': 0.00,
                            'moving_duration': f'{h}h {m}m {s}s',
                            'idle_duration': '0h 0m 00s',
                            'max_speed': 0.00,
                            'average_speed': 0.00,
                            'trips_count': ride.count(),
                            'overspeed_count': 0,
                            'geo_fence_breach_count': 0,
                            'stop_count':0
                        }
                        summary.append(vehicle_record)
                        count += 1
                    return Response({
                        'status': 200,
                        'data': summary if len(summary) >= 1 else 'No Vehicles found'
                    }, status=status.HTTP_200_OK)
                if vehicle and start_date and end_date:
                    vehicle_data = Vehicle.objects.filter(vehicle_unique_identifier=vehicle)
                    if report == 'summary':
                        summary = []
                        count = 1
                        for record in vehicle_data:
                            ride = RideTable.objects.filter(vehicle_id=record, start_date__gte=start_date, start_date__lte=end_date)
                            total_running_time = ride.aggregate(Sum('total_running_time'))
                            total_pause_time = ride.aggregate(Sum('total_pause_time'))
                            total_time = total_pause_time.get('total_pause_time__sum') if total_pause_time.get(
                                'total_pause_time__sum') else 0 + total_running_time.get('total_running_time__sum') if total_running_time.get('total_running_time__sum') else 0
                            delta = datetime.timedelta(seconds=total_time)
                            h, m, s = str(delta).split(':')
                            vehicle_record = {
                                'sr.no': count,
                                'vin': record.vehicle_unique_identifier,
                                'start_date': start_date,
                                'end_date': end_date,
                                'total_distance': 0.00,
                                'moving_duration': f'{h}h {m}m {s}s',
                                'idle_duration': '0h 0m 00s',
                                'max_speed': 0.00,
                                'average_speed': 0.00,
                                'trips_count': ride.count(),
                                'overspeed_count': 0,
                                'geo_fence_breach_count': 0,
                                'stop_count': 0
                            }
                            summary.append(vehicle_record)
                            count += 1
                        return Response({
                            'status': 200,
                            'data': summary if len(summary) >= 1 else 'No Vehicle found'
                        }, status=status.HTTP_200_OK)
                    if report == 'trips':
                        if not vehicle_data:
                            return Response({
                            'status': 200,
                            'data': 'No Trips found for this vehicle'
                        }, status=status.HTTP_200_OK)
                        trips_data = RideTable.objects.filter(vehicle_id=vehicle_data.values()[0].get('id'))
                        rides = []
                        count = 1
                        for record in trips_data:
                            total_running_time = record.total_running_time
                            total_pause_time = record.total_pause_time
                            total_time = int(total_pause_time) if total_pause_time else 0 + int(total_running_time) if total_running_time.get('total_running_time__sum') else 0
                            delta = datetime.timedelta(seconds=total_time)
                            h, m, s = str(delta).split(':')
                            rides.append({
                                'sr_no': count,
                                'trip_id': record.id,
                                'start_date_time': f'{record.start_date.strftime("%d/%m/%Y")}, {record.start_time}',
                                'end_date_time': f'{record.end_date.strftime("%d/%m/%Y")}, {record.end_time}',
                                'duration': f'{h}h {m}m {s}s',
                                'max_speed': 0.00,
                                'avg_speed': 0.00,
                                'total_distance': 0.00
                            })
                            count += 1
                        return Response({
                            'status': 200,
                            'data': rides if len(rides) >= 1 else 'No Trips found for this vehicle'
                        }, status=status.HTTP_200_OK)
                    if report == 'overspeed':
                        overspeed = []
                        return Response({
                            'status': 200,
                            'data': overspeed if len(overspeed) >= 1 else 'No overspeed records found'
                        }, status=status.HTTP_200_OK)
                    if report == 'geofence':
                        geofence = []
                        return Response({
                            'status': 200,
                            'data': geofence if len(geofence) >= 1 else 'No geofence records found'
                        }, status=status.HTTP_200_OK)
                    return Response({
                        'status': 400,
                        'data': 'something went wrong'
                    }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({
                    'status': 400,
                    'data': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'status': 400,
            'data': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class AdminProfileUpdateView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def patch(self,request,pk,*args,**kwargs):
        user = User.objects.get(id=pk)
        serializer = AdminProfiileUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "msg":"Profile Updated Successfully",
                "status":status.HTTP_200_OK
            }, status=status.HTTP_200_OK)
        return Response({
            "status": status.HTTP_400_BAD_REQUEST,
            "msg":"something wents wrong",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class AdminDashboardOverView(ViewSet):
    serializer_class = AdminDashboardOverview
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def list(self, request, *args, **kwargs):
        total_amount = PaymentModel.objects.filter(payment_note='Book Ride').aggregate(
            total_amount=Sum(Abs("payment_amount")))
        options = [
            {
                "booked_vehicles": Vehicle.objects.filter(is_booked=True).count(),
                "avilable_vehicles": Vehicle.objects.filter(is_booked=False, is_reserved=False).count(),
                "total_vehicles": Vehicle.objects.all().count(),
                # "total_users": User.objects.all().count(),
                "total_earnings": float(total_amount.get('total_amount')),
                "total_users": User.objects.filter(user_role=5).count(),
                "total_distance": "100KM",
                "active": 5,
                "moderate": 2,
                "critical": 1,
                "inactive": 3

            }
        ]
        result = AdminDashboardOverview(data=options, many=True)
        result.is_valid()
        return Response({
            "status": status.HTTP_200_OK,
            "vehicle": result.data
        }, status=status.HTTP_200_OK)