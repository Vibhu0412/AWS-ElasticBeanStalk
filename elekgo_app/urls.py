from django.urls import path
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register("get_available_vehicles", views.GetAvailableVehicles, basename="vehicle")
router.register("station", views.StationApi, basename="station")
router.register("user", views.UserViewSet , basename="user")
router.register("voucher", views.VoucherApi , basename="voucher")
router.register("redeem_voucher", views.RedeemVoucherApi , basename="redeem_voucher")
router.register("app_version", views.AppVersionApi , basename="app_version")

urlpatterns = [
    path('register/', views.RegisterUserView.as_view(), name='register'),
    path('verify_otp/<int:pk>/', views.VerifyOTP.as_view(), name='verify-otp'),
    path('user_login/', views.UserLoginWithEmail.as_view(), name='user-login'),
    # path('user_login_otp_verify/<int:pk>/', views.VerifyOtpLogin.as_view(), name='user-login-otp-verify'),
    path('otp_verification/<int:pk>/', views.VerifyOtpLogin.as_view(), name="otp-verification"),
    path('send_otp_mobile/', views.SendMobileOtp.as_view(), name='send-otp-mobile'),
    path('resend_otp/', views.ResendOtpSerializerView.as_view(), name='resend_otp'),
    path('list_faq/', views.FAQSerializerView.as_view(), name='list_faq'),
    path('user_kyc_verification/', views.UserKycVerificationSerializerView.as_view(), name='user_kyc_verification'),
    path('vehicle_report/', views.VehicleReportView.as_view(), name='vehicle-report'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('change_password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('update_profile/', views.UpdateProfileView.as_view(), name='update_profile'),
    path('customer_satisfaction_response/',views.CustomerSatisfactionView.as_view(),name='customer-satisfaction-response'),
    path('payment/', views.PaymentView.as_view(), name='payment'),
    path('user_account_balance/<int:pk>/', views.UserAccountBalanceView.as_view(), name='user-account-balance'),
    path('scan_barcode/<int:pk>/', views.ScanBarcodeView.as_view(), name='scan-barcode'),
    path('ride_start_stop/', views.RideStartStopSerializerView.as_view(), name='ride-start-stop'),
    path('all_notifications/', views.AllNotifications.as_view(),name="all-notifications"),
    path('create_admin_user/', views.AdminUserRegisterUserView.as_view(),name="create-admin-user"),
    path('verify_admin_user/', views.AdminVerificationLink.as_view(),name="verify-admin-user"),
    path('admin_user_login/', views.AdminUserLogin.as_view(),name="admin-user-login"),
    path('all_admin_user/',views.GetAllAdminUsers.as_view(),name='all-admin-user'),
    path('get_user_ride_time/', views.GetCurrentRideTime.as_view(), name='user-ride-time'),
    path('get_all_kyc_users/', views.GetAllKycUsers.as_view(), name='get-all-kyc-users'), #Kyc-User Details
    path('accept_reject_kyc/', views.AcceptRejectKycDetails.as_view(), name='accept-reject-kyc'), #Kyc-User Details
    path('get_user_kyc_update/<int:pk>/', views.GetUserKycUpdate.as_view(), name='get-user-kyc-update'), #Kyc-User Details
    # path('get_ride_statistics/<int:pk>/',views.CompleteRideDetail.as_view(),name='get-complete-ride-detal'),
    path('unlock_scooter/<int:pk>/', views.UnlockScooter.as_view(), name='unlock-scooter'),
    path('user_ride_history/<int:pk>/', views.UserRideHistory.as_view(), name='user-ride-histoty'),
    path('user_ride_details/<int:ride_id>/', views.UserRideDetails.as_view(), name="user-ride-details"),
    # path('get_available_vehicles/<int:pk>/', views.GetAvailableVehicles.as_view(), name="get_available_vehicles"),
    # path('get_vehicle_details/<int:pk>/', views.GetAvailableVehicles.get_vehicle_details.as_view(), name="get_available_vehicles"),
    path('get_all_users/', views.GetAllUsersData.as_view(), name="get_all_users"),
    path('reset_password/', views.ResetPasswordView.as_view(),name='reset-password'),
    path('verify_otp_password_reset/', views.VeifyOtpForPasswordReset.as_view(),name='verify-otp-password-reset'),
    path('create_new_password/', views.CreateNewPassword.as_view(), name='create_new_password'),
    path('battery_notification/', views.BattryNotification.as_view(), name='battery_notification'),
    path('low_balance_notification/', views.BalanceNotification.as_view(), name='low_balance_notification'),

] + router.urls

