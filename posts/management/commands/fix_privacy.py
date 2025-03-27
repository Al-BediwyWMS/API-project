from django.core.management.base import BaseCommand
from posts.models import Post
from django.contrib.auth.models import User, Group
from rest_framework.authtoken.models import Token

class Command(BaseCommand):
    help = 'Fixes privacy implementation in the app'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting privacy fix...'))
        
        # 1. Check that the privacy field exists and has the right choices
        self.stdout.write('Checking Post model privacy field...')
        post_fields = Post._meta.get_fields()
        privacy_field = None
        for field in post_fields:
            if field.name == 'privacy':
                privacy_field = field
                break
        
        if privacy_field:
            self.stdout.write(self.style.SUCCESS(f'✓ Privacy field exists with choices: {privacy_field.choices}'))
        else:
            self.stdout.write(self.style.ERROR('✗ Privacy field missing!'))
            return
        
        # 2. Verify all posts have a valid privacy setting
        self.stdout.write('Checking all posts for valid privacy settings...')
        all_posts = Post.objects.all()
        fixed_posts = 0
        
        for post in all_posts:
            if not hasattr(post, 'privacy') or post.privacy not in ['public', 'private']:
                post.privacy = 'public'
                post.save()
                fixed_posts += 1
        
        if fixed_posts > 0:
            self.stdout.write(self.style.SUCCESS(f'✓ Fixed {fixed_posts} posts with invalid privacy settings'))
        else:
            self.stdout.write(self.style.SUCCESS('✓ All posts have valid privacy settings'))
        
        # 3. Create test users and posts for verification
        self.stdout.write('Creating test users and posts...')
        
        # Ensure groups exist
        admin_group, _ = Group.objects.get_or_create(name='Admin')
        moderator_group, _ = Group.objects.get_or_create(name='Moderator')
        regular_group, _ = Group.objects.get_or_create(name='Regular')
        
        # Create admin user
        admin_user, created = User.objects.get_or_create(
            username='privacy_admin',
            defaults={'email': 'privacy_admin@example.com', 'is_staff': True}
        )
        if created:
            admin_user.set_password('Admin123!')
            admin_user.save()
            admin_user.groups.add(admin_group)
        
        admin_token, _ = Token.objects.get_or_create(user=admin_user)
        
        # Create regular users
        user1, created1 = User.objects.get_or_create(
            username='privacy_user1',
            defaults={'email': 'privacy_user1@example.com'}
        )
        if created1:
            user1.set_password('User123!')
            user1.save()
            user1.groups.add(regular_group)
        
        user2, created2 = User.objects.get_or_create(
            username='privacy_user2',
            defaults={'email': 'privacy_user2@example.com'}
        )
        if created2:
            user2.set_password('User123!')
            user2.save()
            user2.groups.add(regular_group)
        
        user1_token, _ = Token.objects.get_or_create(user=user1)
        user2_token, _ = Token.objects.get_or_create(user=user2)
        
        # Create test posts
        public_post = Post.objects.create(
            content="This is a public post for privacy testing",
            author=user1,
            privacy="public"
        )
        
        private_post = Post.objects.create(
            content="This is a private post for privacy testing",
            author=user1,
            privacy="private"
        )
        
        self.stdout.write(self.style.SUCCESS(f'✓ Created test users and posts'))
        self.stdout.write(self.style.SUCCESS(f'Admin token: {admin_token.key}'))
        self.stdout.write(self.style.SUCCESS(f'User1 token: {user1_token.key}'))
        self.stdout.write(self.style.SUCCESS(f'User2 token: {user2_token.key}'))
        self.stdout.write(self.style.SUCCESS(f'Public post ID: {public_post.id}'))
        self.stdout.write(self.style.SUCCESS(f'Private post ID: {private_post.id}'))
        
        self.stdout.write(self.style.SUCCESS('\nTest these in Postman:'))
        self.stdout.write(f'1. Public post as User2: GET /posts/posts/{public_post.id}/ with token {user2_token.key}')
        self.stdout.write(f'2. Private post as User2: GET /posts/posts/{private_post.id}/ with token {user2_token.key}')
        self.stdout.write(f'3. Private post as Admin: GET /posts/posts/{private_post.id}/ with token {admin_token.key}')
        self.stdout.write('\nUser2 should be able to see the public post but NOT the private post.')