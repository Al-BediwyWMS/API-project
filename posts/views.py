# Imports
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.models import User as AuthUser, Group
from django.contrib.auth import authenticate, logout
from django.contrib.auth.decorators import login_required
from rest_framework.authtoken.models import Token
from connectly_project import settings
from .permissions import IsPostAuthor, IsAdminUser, IsModeratorUser
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from django.db import transaction
from django.http import Http404
from .models import Like, Post, Comment, Task, UserFollow
from .serializers import PostSerializer, CommentSerializer
from singletons.logger_singleton import LoggerSingleton
from singletons.config_manager import ConfigManager
from factories.task_factory import TaskFactory
from django.contrib.auth.models import User
from rest_framework.pagination import PageNumberPagination
from django.db.models import Count,Q, Case, When, BooleanField
from django.utils import timezone
from datetime import timedelta
from django.core.cache import cache
from django.conf import settings
from .cache_utils import get_feed_cache_key, invalidate_post_caches


logger = LoggerSingleton().get_logger()
config = ConfigManager()

# Serializers (moved to top)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthUser
        fields = ('id', 'username', 'email', 'groups')
        read_only_fields = ('groups',)

# Helper functions
def create_user_groups():
    Group.objects.get_or_create(name='Admin')
    Group.objects.get_or_create(name='Moderator')
    Group.objects.get_or_create(name='Regular')

def validate_username(username):
    if not username or len(username) < 3:
        raise ValidationError("Username must be at least 3 characters long")
    if AuthUser.objects.filter(username=username).exists():
        raise ValidationError("Username already exists")

def validate_user_input(data):
    required_fields = ['username', 'email']
    for field in required_fields:
        if field not in data:
            raise ValidationError(f"{field} is required")
    
    validate_username(data['username'])
    validate_email(data['email'])

def validate_post_input(data):
    if 'content' not in data:
        raise ValidationError("Content is required")
    if 'author' not in data:
        raise ValidationError("Author ID is required")
    if not data['content'].strip():
        raise ValidationError("Content cannot be empty")
    if not str(data['author']).isdigit():
        raise ValidationError("Author ID must be a number")

# API Views
def get_users(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        users = list(AuthUser.objects.values('id', 'username', 'email'))
        return JsonResponse(users, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def create_user(request):
    try:
            data = json.loads(request.body.decode('utf-8'))
            
            required_fields = ['username', 'email', 'password']
            for field in required_fields:
                if field not in data:
                    return Response({'error': f"{field} is required"}, status=400)
            
            validate_username(data['username'])
            validate_email(data['email'])
            
            if len(data['password']) < 8:
                return Response({'error': 'Password must be at least 8 characters long'}, status=400)
            
            user = AuthUser.objects.create_user(
                username=data['username'],
                email=data['email'],
                password=data['password']
            )
            
            regular_group = Group.objects.get(name='Regular')
            user.groups.add(regular_group)
            
            token, created = Token.objects.get_or_create(user=user)
            
            return Response({
                'token': token.key,
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'message': 'User created successfully'
            }, status=201)
            
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON format'}, status=400)
    except ValidationError as e:
        return Response({'error': str(e)}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@csrf_exempt
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAdminUser])
def assign_role(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
        if 'user_id' not in data or 'role' not in data:
            return JsonResponse({'error': 'user_id and role are required'}, status=400)

        user = AuthUser.objects.get(id=data['user_id'])
        role = data['role']

        user.groups.clear()

        if role in ['Admin', 'Moderator', 'Regular']:
            group = Group.objects.get(name=role)
            user.groups.add(group)
            return JsonResponse({'message': f'User assigned to {role} role successfully'})
        else:
            return JsonResponse({'error': 'Invalid role'}, status=400)

    except AuthUser.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def update_user(request, id):
    if request.method != 'PUT':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        user = AuthUser.objects.filter(id=id).first()
        if not user:
            return JsonResponse({'error': 'User not found'}, status=404)

        data = json.loads(request.body)
        if 'email' not in data:
            return JsonResponse({'error': 'Email is required'}, status=400)
        
        validate_email(data['email'])
        user.email = data['email']
        user.save()
        
        return JsonResponse({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'message': 'User updated successfully'
        }, status=200)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format'}, status=400)
    except ValidationError as e:
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def delete_user(request, id):
    if request.method != 'DELETE':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        user = AuthUser.objects.filter(id=id).first()
        if not user:
            return JsonResponse({'error': 'User not found'}, status=404)
            
        user.delete()
        return JsonResponse({'message': 'User deleted successfully'}, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    try:
        data = json.loads(request.body)
        
        if 'username' not in data or 'password' not in data:
            return Response({'error': 'Username and password are required'}, status=400)
        
        user = authenticate(username=data['username'], password=data['password'])
        
        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'is_staff': user.is_staff,
                'groups': list(user.groups.values_list('name', flat=True))
            })
        else:
            return Response({'error': 'Invalid credentials'}, status=401)
            
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON format'}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
def logout_user(request):
    try:
        request.user.auth_token.delete()
        logout(request)
        return Response({'message': 'Successfully logged out'})
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAdminUser])
def update_staff_status(request):
    user_id = request.data.get('user_id')
    staff_status = request.data.get('is_staff', True)
    
    try:
        user = AuthUser.objects.get(id=user_id)
        user.is_staff = staff_status
        user.save()
        return Response({
            'message': f'Staff status updated for user {user.username}',
            'is_staff': user.is_staff
        })
    except AuthUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

@api_view(['POST'])
@permission_classes([IsAdminUser])
def make_user_admin(request):
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        
        if not user_id:
            return Response({'error': 'user_id is required'}, status=400)
            
        user = AuthUser.objects.get(id=user_id)
        
        # Make user a staff member
        user.is_staff = True
        
        # Make user a superuser (optional)
        user.is_superuser = True
        
        # Add to Admin group
        admin_group = Group.objects.get(name='Admin')
        user.groups.clear()  # Remove from other groups
        user.groups.add(admin_group)
        
        user.save()
        
        return Response({
            'message': f'User {user.username} is now an admin',
            'user_id': user.id,
            'username': user.username,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
            'groups': list(user.groups.values_list('name', flat=True))
        })
        
    except AuthUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

class UserListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = AuthUser.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PostListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # For admin users and moderators, show all posts
        if request.user.is_staff or request.user.groups.filter(name='Moderator').exists():
            posts = Post.objects.prefetch_related('comments', 'likes').all()
        else:
            # For regular users, show only public posts and their own private posts
            posts = Post.objects.prefetch_related('comments', 'likes').filter(
                Q(privacy='public') | Q(privacy='private', author=request.user)
            )
        
        serializer = PostSerializer(posts, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        serializer = PostSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PostDetail(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get_object(self, pk, user):
        try:
            # Try to get from cache first
            cache_key = f"post_detail:{pk}"
            cached_post = cache.get(cache_key)
            
            if cached_post:
                # Check privacy even for cached posts
                if cached_post.privacy == 'private' and cached_post.author != user:
                    is_admin_or_mod = (
                        user.is_staff or 
                        user.groups.filter(name__in=['Admin', 'Moderator']).exists()
                    )
                    if not is_admin_or_mod:
                        raise Http404("Post not found")
                return cached_post
            
            # If not in cache, get from DB with optimized query
            post = Post.objects.select_related('author').prefetch_related(
                'comments', 
                'likes', 
                'comments__author'
            ).get(pk=pk)
            
            # Cache the post object
            cache.set(cache_key, post, timeout=settings.CACHE_TTL)
            
            # Strict privacy check
            if post.privacy == 'private' and post.author != user:
                is_admin_or_mod = (
                    user.is_staff or 
                    user.groups.filter(name__in=['Admin', 'Moderator']).exists()
                )
                
                if not is_admin_or_mod:
                    print(f"PRIVACY VIOLATION: User {user.username} (ID: {user.id}) attempted to access private post {pk}")
                    raise Http404("Post not found")
                    
            return post
        except Post.DoesNotExist:
            raise Http404("Post not found")
    
    def get(self, request, pk, format=None):
        # Pass both PK and user to get_object
        post = self.get_object(pk, request.user)
        
        # Try to get serialized post from cache
        cache_key = f"post_detail_serialized:{pk}:{request.user.id}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return Response(cached_data)
        
        # If not in cache, serialize and cache
        serializer = PostSerializer(post, context={'request': request})
        data = serializer.data
        
        # Cache the serialized data
        cache.set(cache_key, data, timeout=settings.CACHE_TTL)
        
        return Response(data)
    
    def put(self, request, pk, format=None):
        post = self.get_object(pk, request.user)
        
        # Additional check for edit permissions
        if post.author != request.user and not (
            request.user.is_staff or 
            request.user.groups.filter(name__in=['Admin', 'Moderator']).exists()
        ):
            return Response(
                {"error": "You don't have permission to edit this post"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = PostSerializer(post, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            
            # Invalidate cache on update
            from .cache_utils import invalidate_post_caches
            invalidate_post_caches(pk)
            
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk, format=None):
        post = self.get_object(pk, request.user)
        
        # Additional check for delete permissions
        if post.author != request.user and not request.user.is_staff:
            return Response(
                {"error": "You don't have permission to delete this post"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Invalidate cache before deletion
        from .cache_utils import invalidate_post_caches
        invalidate_post_caches(pk)
        
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CommentListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CommentSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CommentDetail(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Comment.objects.get(pk=pk)
        except Comment.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        comment = self.get_object(pk)
        serializer = CommentSerializer(comment)
        return Response(serializer.data)

    def put(self, request, pk):
        comment = self.get_object(pk)
        # Check if the user is the author of the comment
        if comment.author != request.user and not request.user.is_staff:
            return Response({
                "error": "You don't have permission to update this comment"
            }, status=status.HTTP_403_FORBIDDEN)
            
        serializer = CommentSerializer(comment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        try:
            comment = Comment.objects.get(pk=pk)
            
            # Check permissions
            if comment.author != request.user and not request.user.is_staff:
                return Response({
                    "error": "You don't have permission to delete this comment"
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Only delete the comment
            comment.delete()
            
            # Return a success message instead of blank response
            return Response({
                "message": "Comment successfully deleted"
            }, status=status.HTTP_200_OK)
            
        except Comment.DoesNotExist:
            return Response({
                "error": "Comment not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CreateTaskView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logger.info("Received task creation request")
        data = request.data
        
        try:
            # Get the user instance
            assigned_to = AuthUser.objects.get(id=data.get('assigned_to', request.user.id))
            
            task = TaskFactory.create_task(
                task_type=data.get('task_type', 'regular'),
                title=data['title'],
                description=data.get('description', ''),
                assigned_to=assigned_to,
                metadata=data.get('metadata', {})
            )
            
            logger.info(f"Task created successfully with ID: {task.id}")
            return Response({
                'message': 'Task created successfully!',
                'task_id': task.id
            }, status=status.HTTP_201_CREATED)
            
        except User.DoesNotExist:
            logger.error("Assigned user not found")
            return Response({
                'error': 'Assigned user not found'
            }, status=status.HTTP_404_NOT_FOUND)
            
        except ValueError as e:
            logger.error(f"Task creation failed: {str(e)}")
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Unexpected error during task creation: {str(e)}")
            return Response({
                'error': 'An unexpected error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TaskListView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logger.info("Retrieving task list")
        try:
            # Get tasks assigned to the user
            tasks = Task.objects.filter(assigned_to=request.user)
            return Response({
                'tasks': [{
                    'id': task.id,
                    'title': task.title,
                    'description': task.description,
                    'task_type': task.task_type,
                    'metadata': task.metadata,
                    'created_at': task.created_at
                } for task in tasks]
            })
        except Exception as e:
            logger.error(f"Error retrieving tasks: {str(e)}")
            return Response({
                'error': 'Error retrieving tasks'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class LikePost(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            
            # Check if user already liked the post
            existing_like = Like.objects.filter(post=post, user=request.user).first()
            
            if existing_like:
                # If user already liked the post, unlike it
                existing_like.delete()
                logger.info(f"User {request.user.username} unliked post {pk}")
                
                # Invalidate caches
                cache.delete(f"post_{pk}_likes_count")
                cache.delete(f"post_detail_serialized:{pk}:{request.user.id}")
                
                # Clear feed caches for this user
                for page in range(1, 5):
                    for size in [10, 20]:
                        key = get_feed_cache_key(request.user.id, {
                            'page': str(page), 
                            'page_size': str(size)
                        })
                        cache.delete(key)
                
                return Response({
                    'message': 'Post unliked successfully',
                    'is_liked': False
                })
            else:
                # If user hasn't liked the post, like it
                Like.objects.create(post=post, user=request.user)
                logger.info(f"User {request.user.username} liked post {pk}")
                
                # Invalidate caches
                cache.delete(f"post_{pk}_likes_count")
                cache.delete(f"post_detail_serialized:{pk}:{request.user.id}")
                
                # Clear feed caches for this user
                for page in range(1, 5):
                    for size in [10, 20]:
                        key = get_feed_cache_key(request.user.id, {
                            'page': str(page), 
                            'page_size': str(size)
                        })
                        cache.delete(key)
                
                return Response({
                    'message': 'Post liked successfully',
                    'is_liked': True
                })
                
        except Post.DoesNotExist:
            logger.error(f"Post {pk} not found when attempting to like")
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            logger.error(f"Error liking post: {str(e)}")
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CommentPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

class PostComments(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = CommentPagination
    
    def get(self, request, pk):
        try:
            # Check if post exists
            post = Post.objects.get(pk=pk)
            
            # Create cache key
            page = request.query_params.get('page', '1')
            page_size = request.query_params.get('page_size', '10')
            cache_key = f"post_comments:{pk}:{page}:{page_size}"
            
            # Try to get from cache
            cached_data = cache.get(cache_key)
            if cached_data:
                logger.info(f"Cache hit for comments on post {pk}")
                return Response(cached_data)
                
            logger.info(f"Cache miss for comments on post {pk}")
        
            # Get comments with optimization
            comments = Comment.objects.select_related('author').filter(post=post).order_by('-created_at')
            
            paginator = self.pagination_class()
            paginated_comments = paginator.paginate_queryset(comments, request)
            
            serializer = CommentSerializer(paginated_comments, many=True)
            
            # Get paginated response
            response_data = paginator.get_paginated_response(serializer.data).data
            
            # Cache the result
            cache.set(cache_key, response_data, timeout=60*10)  # Cache for 10 minutes
            
            return Response(response_data)
            
        except Post.DoesNotExist:
            logger.error(f"Post {pk} not found when fetching comments")
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error fetching comments: {str(e)}")
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request, pk):
        try:
            # Check if post exists
            post = Post.objects.get(pk=pk)
            
            # Create comment data with the post ID
            comment_data = request.data.copy()
            comment_data['post'] = pk
            
            # Serialize and validate
            serializer = CommentSerializer(data=comment_data, context={'request': request})
            
            if serializer.is_valid():
                # Save the comment
                comment = serializer.save(author=request.user, post=post)
                
                # Invalidate caches related to this post's comments
                cache.delete_pattern(f"post_comments:{pk}:*")
                cache.delete_pattern(f"post_detail_serialized:{pk}:*")
                
                logger.info(f"User {request.user.username} created comment on post {pk}")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                logger.error(f"Invalid comment data: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        except Post.DoesNotExist:
            logger.error(f"Post {pk} not found when creating comment")
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error creating comment: {str(e)}")
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class FeedPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 50

class NewsFeedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = FeedPagination
    
    def get(self, request):
        """
        Retrieve personalized news feed for the current user.
        
        Parameters:
        - sort_by: Field to sort by (default: 'recent', options: 'recent', 'popular', 'relevant')
        - filter_by: Filter criteria (options: 'following', 'liked', 'all')
        - time_range: Time range for posts (options: 'day', 'week', 'month', 'all')
        """
        user_id = request.user.id
        logger.info(f"Retrieving news feed for user: {request.user.username}")
        
        # Generate cache key
        cache_key = get_feed_cache_key(user_id, request.query_params)
        
        # Try to get data from cache
        cached_response = cache.get(cache_key)
        if cached_response:
            logger.info(f"Cache hit for user {request.user.username}'s feed")
            return Response(cached_response)
        
        logger.info(f"Cache miss for user {request.user.username}'s feed")
        
        try:
            # Get query parameters with defaults
            sort_by = request.query_params.get('sort_by', 'recent').lower()
            filter_by = request.query_params.get('filter_by', 'all').lower()
            time_range = request.query_params.get('time_range', 'all').lower()
            
            # Base query respecting privacy settings
            if request.user.is_staff or request.user.groups.filter(name='Moderator').exists():
                # Admins and moderators can see all posts
                base_query = Post.objects.all()
            else:
                # Regular users can only see public posts and their own private posts
                base_query = Post.objects.filter(
                    Q(privacy='public') | Q(privacy='private', author=request.user)
                )
            
            # Apply time range filter
            queryset = base_query
            if time_range == 'day':
                queryset = queryset.filter(created_at__gte=timezone.now() - timedelta(days=1))
            elif time_range == 'week':
                queryset = queryset.filter(created_at__gte=timezone.now() - timedelta(weeks=1))
            elif time_range == 'month':
                queryset = queryset.filter(created_at__gte=timezone.now() - timedelta(days=30))
            
            # Apply user-specific filters
            if filter_by == 'following':
                followed_users = UserFollow.objects.filter(follower=request.user).values_list('followed', flat=True)
                queryset = queryset.filter(author__in=followed_users)
            elif filter_by == 'liked':
                liked_posts = Like.objects.filter(user=request.user).values_list('post', flat=True)
                queryset = queryset.filter(id__in=liked_posts)
            
            # Use select_related and prefetch_related to optimize queries
            queryset = queryset.select_related('author').prefetch_related(
                'comments', 
                'likes', 
                'comments__author'
            )
            
            # Annotate with additional data for sorting and display
            queryset = queryset.annotate(
                likes_count=Count('likes', distinct=True),
                comments_count=Count('comments', distinct=True),
                is_liked_by_user=Case(
                    When(likes__user=request.user, then=True),
                    default=False,
                    output_field=BooleanField()
                )
            )
            
            # Apply sorting
            if sort_by == 'recent':
                queryset = queryset.order_by('-created_at')
            elif sort_by == 'popular':
                queryset = queryset.order_by('-likes_count', '-comments_count', '-created_at')
            elif sort_by == 'relevant':
                # Relevance could be a combination of factors
                queryset = queryset.order_by('-is_liked_by_user', '-created_at')
            else:
                queryset = queryset.order_by('-created_at')  # Default sorting
            
            # Apply pagination
            paginator = self.pagination_class()
            paginated_posts = paginator.paginate_queryset(queryset, request)
            
            # Serialize data
            serializer = PostSerializer(paginated_posts, many=True, context={'request': request})
            
            # Get the paginated response
            response_data = paginator.get_paginated_response(serializer.data).data
            
            # Cache the result
            cache.set(cache_key, response_data, timeout=settings.CACHE_TTL)
            
            # Return response
            logger.info(f"Successfully retrieved news feed for user: {request.user.username}")
            return Response(response_data)
            
        except Exception as e:
            logger.error(f"Error retrieving news feed: {str(e)}")
            return Response({
                'error': 'An error occurred while retrieving the news feed.',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAdminUser])
def get_roles(request):
    """
    Get all roles and their permissions (admin only)
    """
    roles = {
        'Admin': {
            'can_create_post': True,
            'can_edit_any_post': True,
            'can_delete_any_post': True,
            'can_view_private_posts': True,
            'can_assign_roles': True,
            'can_manage_users': True,
        },
        'Moderator': {
            'can_create_post': True,
            'can_edit_any_post': True,
            'can_delete_any_post': False,
            'can_view_private_posts': True,
            'can_assign_roles': False,
            'can_manage_users': False,
        },
        'Regular': {
            'can_create_post': True,
            'can_edit_any_post': False,
            'can_delete_any_post': False,
            'can_view_private_posts': False,
            'can_assign_roles': False,
            'can_manage_users': False,
        },
    }
    
    return Response(roles)

@api_view(['PUT'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def update_post_privacy(request, pk):
    """
    Update privacy settings for a post
    """
    try:
        post = Post.objects.get(pk=pk)
        
        # Only allow the post author to change privacy settings
        if post.author != request.user and not request.user.is_staff:
            return Response({
                'error': 'You do not have permission to update this post\'s privacy settings'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get the new privacy setting
        privacy = request.data.get('privacy')
        if privacy not in ['public', 'private']:
            return Response({
                'error': 'Invalid privacy setting. Must be "public" or "private".'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Update the post
        post.privacy = privacy
        post.save()
        
        return Response({
            'message': f'Post privacy updated to {privacy}',
            'post_id': post.id,
            'privacy': post.privacy
        })
        
    except Post.DoesNotExist:
        return Response({
            'error': 'Post not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
