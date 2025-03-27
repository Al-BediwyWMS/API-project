import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'connectly_project.settings')
django.setup()

from django.contrib.auth.models import User, Group
from posts.models import Post
from rest_framework.authtoken.models import Token

def main():
    print("Testing privacy functionality...")
    
    # Step 1: Check if privacy field exists
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA table_info(posts_post);")
            columns = cursor.fetchall()
            privacy_column = None
            for column in columns:
                if column[1] == 'privacy':
                    privacy_column = column
                    break
        
        if privacy_column:
            print(f"✅ Privacy column exists: {privacy_column}")
        else:
            print("❌ Privacy column doesn't exist in posts_post table!")
            print("Run migrations or add the column manually")
            return
    except Exception as e:
        print(f"Error checking schema: {e}")
    
    # Step 2: Create test users
    print("\nCreating test users...")
    # Ensure groups exist
    admin_group, _ = Group.objects.get_or_create(name='Admin')
    regular_group, _ = Group.objects.get_or_create(name='Regular')
    
    # Create test users
    user1, created1 = User.objects.get_or_create(
        username='test_privacy_user1',
        defaults={'email': 'test_privacy1@example.com'}
    )
    if created1:
        user1.set_password('TestPass123!')
        user1.save()
        user1.groups.clear()
        user1.groups.add(regular_group)
        print(f"Created user1: {user1.username}")
    else:
        print(f"User1 already exists: {user1.username}")
    
    user2, created2 = User.objects.get_or_create(
        username='test_privacy_user2',
        defaults={'email': 'test_privacy2@example.com'}
    )
    if created2:
        user2.set_password('TestPass123!')
        user2.save()
        user2.groups.clear()
        user2.groups.add(regular_group)
        print(f"Created user2: {user2.username}")
    else:
        print(f"User2 already exists: {user2.username}")
    
    # Get or create tokens
    token1, _ = Token.objects.get_or_create(user=user1)
    token2, _ = Token.objects.get_or_create(user=user2)
    
    print(f"User1 token: {token1.key}")
    print(f"User2 token: {token2.key}")
    
    # Step 3: Create a private post
    print("\nCreating a private post...")
    try:
        private_post = Post.objects.create(
            content="This is a private post created by the test script",
            author=user1,
            privacy="private"
        )
        print(f"Created private post ID: {private_post.id}")
        
        # Directly verify the privacy in the database
        refreshed_post = Post.objects.get(id=private_post.id)
        print(f"Post privacy in DB: {refreshed_post.privacy}")
        
        if refreshed_post.privacy != "private":
            print("❌ Privacy was not saved correctly!")
            return
        else:
            print("✅ Privacy saved correctly as 'private'")
    except Exception as e:
        print(f"Error creating post: {e}")
        return
    
    # Step 4: Test accessing the post using Django's permission logic
    print("\nTesting post access...")
    
    def can_access_post(user, post):
        # This is the logic that should be in your view
        if post.privacy == 'public':
            return True
        if post.author == user:
            return True
        if user.is_staff:
            return True
        if user.groups.filter(name__in=['Admin', 'Moderator']).exists():
            return True
        return False
    
    user1_access = can_access_post(user1, private_post)
    user2_access = can_access_post(user2, private_post)
    
    print(f"User1 (author) can access: {user1_access}")
    print(f"User2 (not author) can access: {user2_access}")
    
    if user1_access and not user2_access:
        print("✅ Access control logic is working correctly!")
    else:
        print("❌ Access control logic failed!")
        
    # Step 5: Instructions for testing in Postman
    print("\nTo test in Postman:")
    print(f"1. Test with Author: GET {{baseUrl}}/posts/posts/{private_post.id}/ with token {token1.key}")
    print(f"2. Test with Another User: GET {{baseUrl}}/posts/posts/{private_post.id}/ with token {token2.key}")
    print("The second request should fail with 404 or 403.")

if __name__ == "__main__":
    main()