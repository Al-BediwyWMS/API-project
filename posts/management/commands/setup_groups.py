from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from posts.models import Post

class Command(BaseCommand):
    help = 'Create default groups and permissions'

    def handle(self, *args, **kwargs):
        # Create groups
        groups = ['Admin', 'Moderator', 'Regular']
        created_groups = {}

        for group_name in groups:
            group, created = Group.objects.get_or_create(name=group_name)
            created_groups[group_name] = group
            if created:
                self.stdout.write(self.style.SUCCESS(f'Created group "{group_name}"'))
            else:
                self.stdout.write(self.style.WARNING(f'Group "{group_name}" already exists'))

        # Get content type for Post model
        try:
            post_content_type = ContentType.objects.get_for_model(Post)

            # Define permissions
            permissions = {
                'add_post': 'Can add post',
                'change_post': 'Can change post',
                'delete_post': 'Can delete post',
                'view_post': 'Can view post',
            }

            # Create permissions if they don't exist
            for codename, name in permissions.items():
                permission, created = Permission.objects.get_or_create(
                    codename=codename,
                    name=name,
                    content_type=post_content_type,
                )

                # Assign permissions to groups
                if codename in ['view_post', 'add_post']:
                    # All groups can view and add posts
                    for group in created_groups.values():
                        group.permissions.add(permission)
                elif codename in ['change_post', 'delete_post']:
                    # Only Admin and Moderator can edit and delete posts
                    created_groups['Admin'].permissions.add(permission)
                    created_groups['Moderator'].permissions.add(permission)

            self.stdout.write(self.style.SUCCESS('Successfully set up permissions'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error setting up permissions: {str(e)}'))