from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from google.oauth2 import id_token
from google.auth.transport import requests
from singletons.logger_singleton import LoggerSingleton

logger = LoggerSingleton().get_logger()
User = get_user_model()

@api_view(['POST'])
@permission_classes([AllowAny])
def google_login(request):
    """
    Endpoint for handling Google OAuth login
    """
    try:
        # Get the Google token from the request
        id_token_jwt = request.data.get('token')
        
        if not id_token_jwt:
            logger.error("No token provided in request")
            return Response({'error': 'Google token is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"Received token: {id_token_jwt[:20]}...")
        
        # Verify the Google token
        try:
            # Specify the CLIENT_ID of your app
            CLIENT_ID = '136645110972-8kdg4idi5atnojnjsaon74oa7ibpr42o.apps.googleusercontent.com'
            logger.info(f"Attempting to verify token with CLIENT_ID: {CLIENT_ID[:20]}...")
            
            idinfo = id_token.verify_oauth2_token(id_token_jwt, requests.Request(), CLIENT_ID)
            
            # Log token verification success
            logger.info(f"Token verified successfully for email: {idinfo.get('email')}")
            
            # Get user info from the verified token
            google_user_id = idinfo['sub']
            email = idinfo['email']
            name = idinfo.get('name', '')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')
            picture_url = idinfo.get('picture', None)  # Define picture_url here, outside of any conditional blocks
            
            # Check if the email is verified by Google
            if not idinfo.get('email_verified', False):
                logger.warning(f"Email not verified by Google: {email}")
                return Response({'error': 'Email not verified by Google'}, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                # Check if the user already exists
                try:
                    user = User.objects.get(email=email)
                    logger.info(f"Existing user logged in with Google: {email}")
                    
                    # Update user information from Google if needed
                    if not user.first_name and first_name:
                        user.first_name = first_name
                    if not user.last_name and last_name:
                        user.last_name = last_name
                    user.save()
                    
                    is_new_user = False
                    
                except User.DoesNotExist:
                    # Create a new user with information from Google
                    username = email.split('@')[0]  # Use part of email as username
                    
                    # Ensure username is unique
                    base_username = username
                    counter = 1
                    while User.objects.filter(username=username).exists():
                        username = f"{base_username}{counter}"
                        counter += 1
                    
                    # Create the user
                    logger.info(f"Creating new user with email: {email}, username: {username}")
                    user = User.objects.create_user(
                        username=username,
                        email=email,
                        first_name=first_name,
                        last_name=last_name
                    )
                    
                    # Add to Regular group
                    try:
                        regular_group = Group.objects.get(name='Regular')
                        user.groups.add(regular_group)
                        logger.info(f"Added user {email} to Regular group")
                    except Group.DoesNotExist:
                        logger.error("Regular group does not exist")
                        # Create the group if it doesn't exist
                        regular_group = Group.objects.create(name='Regular')
                        user.groups.add(regular_group)
                    
                    is_new_user = True
                    
                # Generate or get the token for authentication
                token, created = Token.objects.get_or_create(user=user)
                
                return Response({
                    'token': token.key,
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_staff': user.is_staff,
                    'is_new_user': is_new_user,
                    'profile_picture': picture_url,  # Now this variable is always defined
                    'groups': list(user.groups.values_list('name', flat=True)),
                    'message': 'Login with Google successful',
                })
                
        except ValueError as e:
            # Invalid token
            logger.error(f"Invalid Google token: {str(e)}")
            return Response({'error': 'Invalid Google token'}, status=status.HTTP_401_UNAUTHORIZED)
            
    except Exception as e:
        logger.error(f"Error during Google login: {str(e)}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)