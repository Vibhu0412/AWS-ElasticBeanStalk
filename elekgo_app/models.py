import datetime

import django.utils.timezone
from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser
from phonenumber_field.modelfields import PhoneNumberField
import qrcode
from PIL import Image, ImageDraw
from io import BytesIO
from django.core.files import File
from bulk_update_or_create import BulkUpdateOrCreateQuerySet
from django.utils.translation import gettext_lazy as _


# Create your models here.
class AllUserManager(BaseUserManager):
    def create_user(self, email, user_name, phone, user_role=5, password=None, fcm_token=None):
        if not email:
            raise ValueError('User must have an email address')
        user = self.model(
            email=self.normalize_email(email),
            password=password,
            user_name=user_name,
            phone=phone,
            fcm_token=fcm_token,
            user_role=user_role

        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, user_name, phone, password=None, fcm_token=None):
        user = self.create_user(
            email,
            password=password,
            user_name=user_name,
            phone=phone,
            fcm_token=fcm_token
        )
        user.is_active = True
        user.is_admin = True
        # user.is_staff = True
        user.save(using=self._db)
        return user
    
    def get_queryset(self):
        return super().get_queryset().exclude(is_user_kyc_verified = "Rejected")

class UserManager(BaseUserManager):
    def create_user(self, email, user_name, phone, user_role=5, password=None, fcm_token=None):
        if not email:
            raise ValueError('User must have an email address')
        user = self.model(
            email=self.normalize_email(email),
            password=password,
            user_name=user_name,
            phone=phone,
            fcm_token=fcm_token,
            user_role=user_role

        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, user_name, phone, password=None, fcm_token=None):
        user = self.create_user(
            email,
            password=password,
            user_name=user_name,
            phone=phone,
            fcm_token=fcm_token
        )
        user.is_active = True
        user.is_admin = True
        # user.is_staff = True
        user.save(using=self._db)
        return user
    
    def get_queryset(self):
        return super().get_queryset()


#  Custom  User Model
class User(AbstractBaseUser):
    USER_TYPE_CHOICES = (
        (1, 'admin'),
        (2, 'staff_user'),
        (3, 'customer_support'),
        (4, 'maintenance_user'),
        (5, 'normal_user')
    )

    kyc_choices = (
        ('NA', 'NA'),
        ('Approved', 'Approved'),
        ('Pending', 'Pending'),
        ('Rejected', 'Rejected')
    )
    email = models.EmailField(
        verbose_name='Email',
        max_length=255,
        unique=True,
    )
    user_name = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    phone = PhoneNumberField(unique=True)
    is_email_verified = models.BooleanField(default=False)
    otp = models.IntegerField(null=True, blank=True)
    fcm_token = models.CharField(max_length=500, null=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_user_kyc_verified = models.CharField(max_length=20, choices=kyc_choices, default='NA')
    user_image = models.ImageField(null=True, blank=True, upload_to='static/images')
    user_aadhar_image = models.ImageField(null=True, blank=True, upload_to='static/images', verbose_name='Aadhar Front Image')
    user_aadhar_image_back = models.ImageField(null=True, blank=True, upload_to='static/images', verbose_name='Aadhar Back Image')
    user_aadhar_identification_num = models.BigIntegerField(null=True, blank=True, unique=True)
    total_carbon_saved = models.FloatField(_("Carbon saved in grams"), default=0)
    total_km = models.FloatField(_("Total Kilometer travelled"), default=0)

    # admin User Fields
    user_role = models.PositiveSmallIntegerField(choices=USER_TYPE_CHOICES, default=5)

    #bolt data
    bolt_id = models.CharField(max_length=200, null=True, blank=True)
    bolt_token = models.CharField(max_length=1000, null=True, blank=True)

    objects = UserManager()
    all_users = AllUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_name', 'phone', 'password', 'fcm_token']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


class FrequentlyAskedQuestions(models.Model):
    question = models.CharField(max_length=500)
    answer = models.CharField(max_length=1000)
    def __str__(self):
        return self.question


class VehicleReportModel(models.Model):
    report_status = [
        ('pending','Pending'),
        ('in progress','In Progress'),
        ('Resolved','Resolved')
    ]
    reported_user = models.ForeignKey(User,on_delete=models.CASCADE)
    report_vehicle_image = models.ImageField(null=True, blank=True, upload_to='static/repoted_vehicle_images')
    remark = models.CharField(max_length=400,null=True,blank=True)
    report_status = models.CharField(choices=report_status,max_length=20,default='Pending')

    def __str__(self):
        return str(self.reported_user)


class CustomerSatisfaction(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    email = models.EmailField(
        verbose_name='User Email',
        max_length=255

    )
    user_phone = PhoneNumberField()
    user_is_satisfied = models.BooleanField()

    def __str__(self):
        return str(self.user_id)


class PaymentModel(models.Model):
    payment_user_id = models.ForeignKey(User,on_delete=models.CASCADE)
    payment_id = models.CharField(max_length=100)
    order_id = models.CharField(max_length=100,null=True,blank=True)
    payment_signature = models.CharField(max_length=200, null=True, blank=True)
    payment_amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateField(auto_now_add=True)
    payment_note = models.CharField(max_length=100)

    def __str__(self):
        return str(self.payment_user_id)


class UserPaymentAccount(models.Model):
    account_user_id = models.ForeignKey(User,on_delete=models.CASCADE)
    account_amount = models.DecimalField(max_digits=10,decimal_places=2, null=True, blank=True)

    def __str__(self):
        return str(self.account_user_id)


class Vehicle(models.Model):
    vehicle_unique_identifier = models.CharField(max_length=100, unique=True, verbose_name="Scooter Chassis Number/VIN Number", null=True)
    qr_image = models.ImageField(blank=True, null=True, upload_to='static/QRCode')
    battery_percentage = models.IntegerField(null=True)
    iot_device_number = models.CharField(max_length=100, null=True)
    scooter_number = models.CharField(max_length=100, null=True)
    battery_number = models.CharField(max_length=100, null=True)
    is_under_maintenance = models.BooleanField(null=True, default=False)
    number_of_km_used = models.CharField(max_length=100, null=True, blank=True)
    no_of_time_battery_used = models.IntegerField(null=True, blank=True)
    no_of_person_used = models.IntegerField(null=True, blank=True)
    no_of_hours_used = models.CharField(max_length=50, null=True, blank=True)
    reserverd_user_id = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='reserved_Vehicle_User')
    is_reserved = models.BooleanField(null=True, default=False)
    is_booked = models.BooleanField(null=True, blank=True, default=False)
    booked_user_id = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='booked_Vehicle_User')
    current_location = models.CharField(max_length=500, null=True, blank=True)
    total_km_capacity = models.CharField(max_length=20, default="25/Km")
    per_min_charge = models.CharField(max_length=10, default="2.5", verbose_name='Per Minute Running Charge')
    per_pause_charge = models.CharField(max_length=10, default="0.5", verbose_name='Per Minute Pause Charge')
    is_unlocked = models.BooleanField(default=False)
    celery_task_id = models.CharField(_("Celery running task id"), max_length=50, null=True, blank=True)
    
    objects = BulkUpdateOrCreateQuerySet.as_manager()

    def __str__(self):
        return str(self.vehicle_unique_identifier)

    def save(self, *args, **kwargs):
        qr_image = qrcode.make(self.vehicle_unique_identifier)
        qr_offset = Image.new('RGB', (310, 310), 'white')
        draw_img = ImageDraw.Draw(qr_offset)
        qr_offset.paste(qr_image)
        file_name = f'{self.vehicle_unique_identifier}.png'
        stream = BytesIO()
        qr_offset.save(stream, 'PNG')
        self.qr_image.save(file_name, File(stream), save=False)
        qr_offset.close()
        super().save(*args, **kwargs)


class RideTable(models.Model):
    ride_date = models.DateField(auto_now=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    start_date = models.DateField(default=django.utils.timezone.now)
    total_running_time = models.CharField(max_length=200, null=True, blank=True)
    total_pause_time = models.CharField(max_length=200, null=True, blank=True)
    riding_user_id = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vehicle_id = models.ForeignKey(Vehicle, on_delete=models.CASCADE, null=True)
    is_ride_running = models.BooleanField(default=False)
    is_ride_end = models.BooleanField(default=False)
    is_paused = models.BooleanField(default=False)
    payment_id = models.ForeignKey(PaymentModel, on_delete=models.CASCADE, null=True, blank=True)
    start_location = models.CharField(max_length=500, null=True, blank=True)
    end_location = models.CharField(max_length=500, null=True, blank=True)

    def __str__(self):
        return str(self.vehicle_id)


class RideTimeHistory(models.Model):
    ride_table_id = models.ForeignKey(RideTable, on_delete=models.CASCADE)
    pause_time = models.TimeField(null=True, blank=True)
    resume_time = models.TimeField(null=True, blank=True)
    pause_duration = models.IntegerField(null=True, blank=True)


class NotificationModel(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    notification_title = models.CharField(max_length=100)
    notification_description = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now=False, auto_now_add=True)

    def __str__(self):
        return str(self.notification_title)