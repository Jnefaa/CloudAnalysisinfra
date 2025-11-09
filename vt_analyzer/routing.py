# urls.py - URL Configuration
from django.urls import path
from . import views

app_name = 'vt_analyzer'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    
    # Analyst URLs
    path('analyze/', views.analyze, name='analyze'),
    path('report/<uuid:report_id>/', views.report_detail, name='report_detail'),
    path('report/<uuid:report_id>/send-to-admin/', views.send_to_admin, name='send_to_admin'),
    path('report/<uuid:report_id>/create-task/', views.create_task, name='create_task'),
    path('report/<uuid:report_id>/download-pdf/', views.download_pdf, name='download_pdf'),
    
    # Admin URLs
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/reports/', views.admin_reports, name='admin_reports'),
    path('admin/report/<uuid:report_id>/review/', views.review_report, name='review_report'),
    path('admin/report/<uuid:report_id>/create-mitigation/', views.create_mitigation, name='create_mitigation'),
    path('admin/mitigations/', views.mitigation_list, name='mitigation_list'),
    path('admin/mitigation/<uuid:mitigation_id>/execute/', views.execute_mitigation_view, name='execute_mitigation'),
    path('admin/tasks/', views.task_list, name='task_list'),
    path('admin/task/<uuid:task_id>/', views.task_detail, name='task_detail'),
    path('admin/task/<uuid:task_id>/update-status/', views.update_task_status, name='update_task_status'),
    
    # AWS Configuration
    path('admin/aws-config/', views.aws_configuration, name='aws_configuration'),
    path('admin/aws-config/test/', views.test_aws_connection, name='test_aws_connection'),
    path('admin/blocked-ips/', views.blocked_ips_list, name='blocked_ips_list'),
    path('admin/blocked-ips/<str:ip>/unblock/', views.unblock_ip_view, name='unblock_ip'),
    
    # Notifications
    path('notifications/', views.notifications_list, name='notifications_list'),
    path('notifications/<uuid:notification_id>/mark-read/', views.mark_notification_read, name='mark_notification_read'),
    path('notifications/mark-all-read/', views.mark_all_notifications_read, name='mark_all_notifications_read'),
    
    # Export
    path('export/csv/', views.export_csv, name='export_csv'),
    path('export/reports/', views.export_reports, name='export_reports'),
    
    # API endpoints for AJAX
    path('api/report/<uuid:report_id>/status/', views.api_report_status, name='api_report_status'),
    path('api/dashboard/stats/', views.api_dashboard_stats, name='api_dashboard_stats'),
    path('api/notifications/unread-count/', views.api_unread_notifications, name='api_unread_notifications'),
]


# routing.py - WebSocket Routing
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/notifications/$', consumers.NotificationConsumer.as_asgi()),
    re_path(r'ws/dashboard/$', consumers.DashboardConsumer.as_asgi()),
]


# asgi.py - ASGI Configuration
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')

django_asgi_app = get_asgi_application()

from vt_analyzer import routing

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(
            routing.websocket_urlpatterns
        )
    ),
})


# Additional view functions referenced in URLs
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from .models import Task, MitigationAction, Notification, AWSConfiguration
from .aws_integration import AWSManager
from datetime import datetime

@login_required
def dashboard(request):
    """Main dashboard - redirect based on role"""
    if request.user.role == 'admin':
        return redirect('vt_analyzer:admin_dashboard')
    else:
        return redirect('vt_analyzer:analyze')

@login_required
def mitigation_list(request):
    """List all mitigation actions"""
    if request.user.role != 'admin':
        messages.error(request, "Admin access required")
        return redirect('vt_analyzer:dashboard')
    
    mitigations = MitigationAction.objects.all().order_by('-created_at')
    
    return render(request, 'admin/mitigation_list.html', {
        'mitigations': mitigations
    })

@login_required
def execute_mitigation_view(request, mitigation_id):
    """Execute a mitigation action"""
    if request.user.role != 'admin':
        messages.error(request, "Admin access required")
        return redirect('vt_analyzer:dashboard')
    
    mitigation = get_object_or_404(MitigationAction, id=mitigation_id)
    
    if mitigation.status == 'completed':
        messages.warning(request, "This mitigation has already been executed")
        return redirect('vt_analyzer:mitigation_list')
    
    mitigation.status = 'in_progress'
    mitigation.save()
    
    # Execute the mitigation
    from .views import execute_mitigation
    execute_mitigation(mitigation)
    
    if mitigation.status == 'completed':
        messages.success(request, "Mitigation executed successfully")
    else:
        messages.error(request, f"Mitigation failed: {mitigation.error_message}")
    
    return redirect('vt_analyzer:mitigation_list')

@login_required
def task_list(request):
    """List all tasks"""
    tasks = Task.objects.filter(assigned_to=request.user).order_by('-created_at')
    
    return render(request, 'admin/task_list.html', {
        'tasks': tasks
    })

@login_required
def task_detail(request, task_id):
    """View task details"""
    task = get_object_or_404(Task, id=task_id)
    
    # Check permissions
    if request.user != task.assigned_to and request.user != task.created_by:
        messages.error(request, "Permission denied")
        return redirect('vt_analyzer:dashboard')
    
    return render(request, 'admin/task_detail.html', {
        'task': task
    })

@login_required
def update_task_status(request, task_id):
    """Update task status"""
    task = get_object_or_404(Task, id=task_id, assigned_to=request.user)
    
    if request.method == 'POST':
        new_status = request.POST.get('status')
        notes = request.POST.get('notes', '')
        
        task.status = new_status
        if notes:
            task.description += f"\n\nUpdate: {notes}"
        
        if new_status == 'completed':
            task.completed_at = datetime.now()
        
        task.save()
        
        messages.success(request, "Task status updated")
    
    return redirect('vt_analyzer:task_detail', task_id=task.id)

@login_required
def aws_configuration(request):
    """Configure AWS settings"""
    if request.user.role != 'admin':
        messages.error(request, "Admin access required")
        return redirect('vt_analyzer:dashboard')
    
    from .forms import AWSConfigurationForm
    
    config = AWSConfiguration.objects.filter(is_active=True).first()
    
    if request.method == 'POST':
        form = AWSConfigurationForm(request.POST, instance=config)
        if form.is_valid():
            new_config = form.save(commit=False)
            
            # Deactivate other configs
            AWSConfiguration.objects.update(is_active=False)
            new_config.is_active = True
            new_config.save()
            
            messages.success(request, "AWS configuration saved")
            return redirect('vt_analyzer:aws_configuration')
    else:
        form = AWSConfigurationForm(instance=config)
    
    return render(request, 'admin/aws_configuration.html', {
        'form': form,
        'config': config
    })

@login_required
def test_aws_connection(request):
    """Test AWS connection"""
    if request.user.role != 'admin':
        return JsonResponse({'success': False, 'error': 'Permission denied'})
    
    config = AWSConfiguration.objects.filter(is_active=True).first()
    if not config:
        return JsonResponse({'success': False, 'error': 'No active AWS configuration'})
    
    aws_manager = AWSManager(config)
    result = aws_manager.test_connection()
    
    return JsonResponse(result)

@login_required
def blocked_ips_list(request):
    """List all blocked IPs"""
    if request.user.role != 'admin':
        messages.error(request, "Admin access required")
        return redirect('vt_analyzer:dashboard')
    
    config = AWSConfiguration.objects.filter(is_active=True).first()
    blocked_ips = []
    
    if config:
        aws_manager = AWSManager(config)
        blocked_ips = aws_manager.get_blocked_ips()
    
    return render(request, 'admin/blocked_ips.html', {
        'blocked_ips': blocked_ips
    })

@login_required
def unblock_ip_view(request, ip):
    """Unblock an IP address"""
    if request.user.role != 'admin':
        return JsonResponse({'success': False, 'error': 'Permission denied'})
    
    config = AWSConfiguration.objects.filter(is_active=True).first()
    if not config:
        return JsonResponse({'success': False, 'error': 'No active AWS configuration'})
    
    aws_manager = AWSManager(config)
    result = aws_manager.unblock_ip(ip)
    
    if result['success']:
        messages.success(request, f"IP {ip} unblocked successfully")
    else:
        messages.error(request, f"Failed to unblock IP: {result.get('error')}")
    
    return redirect('vt_analyzer:blocked_ips_list')

@login_required
def notifications_list(request):
    """List all notifications"""
    notifications = Notification.objects.filter(recipient=request.user).order_by('-created_at')
    
    return render(request, 'notifications/list.html', {
        'notifications': notifications
    })

@login_required
def mark_notification_read(request, notification_id):
    """Mark single notification as read"""
    notification = get_object_or_404(Notification, id=notification_id, recipient=request.user)
    notification.is_read = True
    notification.save()
    
    return JsonResponse({'success': True})

@login_required
def mark_all_notifications_read(request):
    """Mark all notifications as read"""
    Notification.objects.filter(recipient=request.user, is_read=False).update(is_read=True)
    
    return JsonResponse({'success': True})

@login_required
def api_report_status(request, report_id):
    """API endpoint for report status"""
    from .models import ThreatReport
    report = get_object_or_404(ThreatReport, id=report_id)
    
    return JsonResponse({
        'status': report.status,
        'severity': report.severity,
        'threat_score': report.threat_score
    })

@login_required
def api_dashboard_stats(request):
    """API endpoint for dashboard stats"""
    if request.user.role != 'admin':
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    from .models import ThreatReport, Task
    from django.db.models import Count
    
    stats = {
        'pending_reports': ThreatReport.objects.filter(
            assigned_to=request.user, status='pending'
        ).count(),
        'critical_reports': ThreatReport.objects.filter(
            assigned_to=request.user, severity='critical'
        ).count(),
        'open_tasks': Task.objects.filter(
            assigned_to=request.user, status='open'
        ).count()
    }
    
    return JsonResponse(stats)

@login_required
def api_unread_notifications(request):
    """API endpoint for unread notification count"""
    count = Notification.objects.filter(recipient=request.user, is_read=False).count()
    return JsonResponse({'count': count})

@login_required
def export_reports(request):
    """Export reports to CSV"""
    import csv
    from django.http import HttpResponse
    from .models import ThreatReport
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="threat_reports_export.csv"'
    
    reports = ThreatReport.objects.all().order_by('-created_at')
    
    writer = csv.writer(response)
    writer.writerow([
        'ID', 'Timestamp', 'Analyst', 'Type', 'Input Value', 'Severity',
        'Threat Score', 'Status', 'Malicious Count', 'Assigned To'
    ])
    
    for report in reports:
        writer.writerow([
            str(report.id), report.created_at, report.analyst.username,
            report.input_type, report.input_value, report.severity,
            report.threat_score, report.status, report.malicious_count,
            report.assigned_to.username if report.assigned_to else ''
        ])
    
    return response