from django.contrib.auth.models import User
from posts.models import Task

class TaskFactory:
    @staticmethod
    def create_task(task_type, title, description, assigned_to, metadata=None):
        if task_type not in ["regular", "priority", "recurring"]:
            raise ValueError("Invalid task type")

        if task_type == "priority" and "priority_level" not in metadata:
            raise ValueError("Priority tasks require 'priority_level'")

        if task_type == "recurring" and "frequency" not in metadata:
            raise ValueError("Recurring tasks require 'frequency'")

        return Task.objects.create(
            title=title,
            description=description,
            assigned_to=assigned_to,
            task_type=task_type,
            metadata=metadata
        )