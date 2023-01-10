from django.contrib import admin
from .models import User, FrequentlyAskedQuestions, VehicleReportModel, CustomerSatisfaction, PaymentModel, \
    UserPaymentAccount, RideTable, Vehicle, NotificationModel, RideTimeHistory, Station, Voucher
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

class UserModelAdmin(BaseUserAdmin):
  # The fields to be used in displaying the User model.
  # These override the definitions on the base UserModelAdmin
  # that reference specific fields on auth.User.
  list_display = ('id', 'email', 'user_name','phone' 'is_admin')
  list_filter = ('is_admin',)
  fieldsets = (
      ('User Credentials', {'fields': ('email', 'password')}),
      ('Personal info', {'fields': ('user_name','email','password','phone')}),
      ('Permissions', {'fields': ('is_admin',)}),
  )
  # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
  # overrides get_fieldsets to use this attribute when creating a user.
  add_fieldsets = (
      (None, {
          'classes': ('wide',),
          'fields': ('user_name','email','password','phone','is_email_verified'),
      }),
  )
  search_fields = ('email',)
  ordering = ('email', 'id')
  filter_horizontal = ()


admin.site.register(User)
admin.site.register(FrequentlyAskedQuestions)
admin.site.register(VehicleReportModel)
admin.site.register(CustomerSatisfaction)
admin.site.register(PaymentModel)
admin.site.register(UserPaymentAccount)
admin.site.register(Vehicle)
admin.site.register(RideTable)
admin.site.register(NotificationModel)
admin.site.register(RideTimeHistory)
admin.site.register(Station)
admin.site.register(Voucher)

