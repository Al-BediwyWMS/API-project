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
    
class CanViewPrivatePost(BasePermission):
    def has_object_permission(self, request, view, obj):
        # Admin and moderators can see all posts
        if request.user.is_staff or request.user.groups.filter(name='Moderator').exists():
            return True
        # The author can see their own private posts
        if obj.author == request.user:
            return True
        # For private posts, only allow author access
        if obj.privacy == 'private':
            return False
        # Public posts are visible to everyone
        return True