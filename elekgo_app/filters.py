from rest_framework import filters
from rest_framework.settings import api_settings

class SearchFilter(filters.SearchFilter):
    def filter_queryset(self, request, view, model, status):
        queryset = model.objects.all()
        if status is not None:
            if type(status) == bool:
                return super().filter_queryset(request, queryset, view).filter(is_active=status)
            return super().filter_queryset(request, queryset, view).filter(is_user_kyc_verified=status)
        else:
            return super().filter_queryset(request, queryset, view)