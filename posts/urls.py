from django.urls import path
from . import views

urlpatterns = [
    path('users/', views.get_users, name='get_users'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/login/', views.login_user, name='login_user'),
    path('users/logout/', views.logout_user, name='logout_user'),
    path('users/profile/', views.get_user_profile, name='user_profile'),
    path('users/update/<int:id>/', views.update_user, name='update_user'),
    path('users/delete/<int:id>/', views.delete_user, name='delete_user'),
    path('users/assign-role/', views.assign_role, name='assign_role'),
    path('users/update-staff-status/', views.update_staff_status, name='update_staff_status'),
    path('users/make-admin/', views.make_user_admin, name='make_user_admin'),

    path('', views.PostListCreate.as_view(), name='post-list-create'),
    path('posts/<int:pk>/', views.PostDetail.as_view(), name='post-detail'),

    path('comments/', views.CommentListCreate.as_view(), name='comment-list-create'),
    path('comments/<int:pk>/', views.CommentDetail.as_view(), name='comment-detail'),

    path('tasks/create/', views.CreateTaskView.as_view(), name='create_task'),
    path('tasks/', views.TaskListView.as_view(), name='task_list'),

  ]

