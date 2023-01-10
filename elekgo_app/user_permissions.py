from rest_framework.permissions import BasePermission


class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        print(request.user)
        if request.user.user_role == 1:
            return True
        return False


class IsStaffUser(BasePermission):
    def has_permission(self, request, view):
        if request.user.user_role == 2:
            print(request.user.user_role)
            return True
        return False


class IsCustomeSupport(BasePermission):
    def has_permission(self, request, view):
        if request.user.user_role == 3:
            print(request.user.user_role)
            return True
        return False


class IsMaintenanceUser(BasePermission):
    def has_permission(self, request, view):
        if request.user.user_role == 4:
            print(request.user.user_role)
            return True
        return False


class IsNomalUser(BasePermission):
    def has_permission(self, request, view):
        if request.user.user_role == 5:
            print(request.user.user_role)
            return True
        return False
