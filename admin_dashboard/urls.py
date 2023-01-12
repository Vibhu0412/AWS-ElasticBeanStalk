
from django.contrib import admin
from django.urls import path
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r"overview",views.AdminDashboardOverView , basename="users")
router.register("vehicle",views.VehicleAdminApi , basename="vehicle")


urlpatterns = [
   
    path('all_ride_history/', views.UserRideHistory.as_view(), name='all-ride-history'),
    path('set_user_permission/', views.SetUserPermission.as_view(), name='set-user-permission'),
    path('asset_unlock/<int:pk>/', views.AssetUnlock.as_view(), name='asset-unlock'),
    path('asset_lock/<int:pk>/', views.AssetLock.as_view(), name='asset-lock'),
    path('get_report_data/', views.GetReportingDataView.as_view(), name='get-report-data'),
    path('update_admin_profile/<int:pk>/', views.AdminProfileUpdateView.as_view(), name='update-admin-profile'),
    path('get_all_assets/', views.GetAllAssets.as_view(), name='get-all-assets'),
    *router.urls,

]
   
