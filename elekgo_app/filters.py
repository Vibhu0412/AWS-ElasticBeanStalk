from rest_framework import filters
from rest_framework.settings import api_settings

class SearchFilter(filters.SearchFilter):
    def filter_queryset(self, request, view, model):
        queryset = model.objects.all()
        return super().filter_queryset(request, queryset, view)
    
class StatusFilter(filters.BaseFilterBackend):
    def filter_queryset(self, request, queryset, view, status):
        if status:
            return super(StatusFilter, self).filter_queryset(request, queryset, view).filter(is_user_kyc_verified=status)
        else:
            return super(StatusFilter, self).filter_queryset(request, queryset, view)