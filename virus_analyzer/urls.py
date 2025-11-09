from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from vt_analyzer import views 

urlpatterns = [
    # Admin Django
    path('admin/', admin.site.urls),
    
    # Authentification
    path('', include('django.contrib.auth.urls')),
    path('redirect_user/', views.redirect_user_view, name='user_redirect'),

    # Vues Analyste
    path('', views.analyze, name='analyze'), 
    path('report/<uuid:report_id>/', views.report_detail, name='report_detail'),
    path('report/<uuid:report_id>/send/', views.send_to_admin, name='send_to_admin'),
    path('report/<uuid:report_id>/task/create/', views.create_task, name='create_task'),

    # Vues Admin
    path('dashboard/', views.admin_dashboard, name='dashboard'), # 'dashboard' est le nom
    path('reports/', views.admin_reports, name='admin_reports'),
    path('report/<uuid:report_id>/review/', views.review_report, name='review_report'),
    path('report/<uuid:report_id>/mitigation/create/', views.create_mitigation, name='create_mitigation'),
    path('mitigations/', views.admin_mitigations_list, name='admin_mitigations_list'),
    # NOUVEAUX CHEMINS AJOUTÉS
    path('tasks/', views.admin_tasks_list, name='admin_tasks_list'),
    path('config/aws/', views.aws_config_view, name='aws_config'),

    # Vues Utilitaires
    path('report/<uuid:report_id>/download/pdf/', views.download_pdf, name='download_pdf'),
    path('export/csv/', views.export_csv, name='export_csv'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)