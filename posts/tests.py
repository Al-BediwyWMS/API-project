from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User, Group
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from .models import Post
import json

class SecurityTestCase(TestCase):
    def setUp(self):
        # Create test groups
        self.admin_group = Group.objects.create(name='Admin')
        self.moderator_group = Group.objects.create(name='Moderator')
        self.regular_group = Group.objects.create(name='Regular')

        # Create test users
        self.admin_user = User.objects.create_user(
            username='admin_test',
            password='Admin123!',
            email='admin@test.com',
            is_staff=True
        )
        self.admin_user.groups.add(self.admin_group)
        
        self.regular_user = User.objects.create_user(
            username='regular_test',
            password='Regular123!',
            email='regular@test.com'
        )
        self.regular_user.groups.add(self.regular_group)

        # Create tokens
        self.admin_token = Token.objects.create(user=self.admin_user)
        self.regular_token = Token.objects.create(user=self.regular_user)

        # Initialize API client
        self.client = APIClient()

    def test_user_registration(self):
        """Test user registration with password encryption"""
        registration_data = {
            'username': 'newuser',
            'email': 'newuser@test.com',
            'password': 'NewUser123!'
        }
        
        response = self.client.post(
            reverse('create_user'),
            json.dumps(registration_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        self.assertIn('token', response.data)
        
        # Verify password is encrypted
        user = User.objects.get(username='newuser')
        self.assertNotEqual(user.password, 'NewUser123!')

    def test_user_authentication(self):
        """Test login and token generation"""
        login_data = {
            'username': 'regular_test',
            'password': 'Regular123!'
        }
        
        response = self.client.post(
            reverse('login_user'),
            json.dumps(login_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.data)

    def test_unauthorized_access(self):
        """Test protected endpoints without authentication"""
        response = self.client.get(reverse('get_posts'))
        self.assertEqual(response.status_code, 401)

    def test_authorized_access(self):
        """Test protected endpoints with authentication"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.regular_token.key}')
        response = self.client.get(reverse('get_posts'))
        self.assertEqual(response.status_code, 200)

    def test_role_based_access(self):
        """Test role-based permissions"""
        # Create a post as regular user
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.regular_token.key}')
        post_data = {
            'content': 'Test post content'
        }
        response = self.client.post(
            reverse('create_post'),
            post_data,
            format='json'
        )
        post_id = response.data['id']

        # Try to delete post as regular user
        response = self.client.delete(f'/posts/posts/{post_id}/')
        self.assertEqual(response.status_code, 403)

        # Delete post as admin
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.admin_token.key}')
        response = self.client.delete(f'/posts/posts/{post_id}/')
        self.assertEqual(response.status_code, 204)

    def test_https_redirect(self):
        """Test HTTPS redirect"""
        client = Client()
        response = client.get('/posts/', secure=False)
        self.assertEqual(response.status_code, 301)  # Redirects to HTTPS

    def test_password_validation(self):
        """Test password validation rules"""
        weak_password_data = {
            'username': 'weakpass',
            'email': 'weak@test.com',
            'password': '123'  # Too short
        }
        
        response = self.client.post(
            reverse('create_user'),
            json.dumps(weak_password_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        self.assertIn('password', str(response.content))

    def test_token_invalidation(self):
        """Test logout and token invalidation"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.regular_token.key}')
        response = self.client.post(reverse('logout_user'))
        self.assertEqual(response.status_code, 200)
        
        # Try to access protected endpoint with invalidated token
        response = self.client.get(reverse('get_posts'))
        self.assertEqual(response.status_code, 401)