from rest_framework.pagination import LimitOffsetPagination

class CustomPagination(LimitOffsetPagination):
    
        def paginate(self, limit=10, page=1, request=None, queryset=None, view=None):
            try:
                queryset = queryset.order_by("-created_at")
            except Exception as E:
                print('E: ', E)
            self.limit = int(limit) * int(page)
            if self.limit is None:
                return None

            self.count = self.get_count(queryset)
            self.offset = self.limit - int(limit)
            self.request = request
            if self.count > self.limit and self.template is not None:
                self.display_page_controls = True

            if self.count == 0 or self.offset > self.count:
                return []
            return list(queryset[self.offset:self.limit])