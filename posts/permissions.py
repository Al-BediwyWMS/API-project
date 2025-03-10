from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsPostAuthor(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        return obj.author == request.user

class IsCommentAuthor(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.author == request.user
    
class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_staff

class IsModeratorUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.groups.filter(name='Moderator').exists()