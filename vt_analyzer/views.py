import csv
import io
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, JsonResponse, FileResponse
from django.db.models import Q, Count
from django.core.paginator import Paginator
from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from pathlib import Path

from .models import (
    ThreatReport, MitigationAction, Task, Notification, 
    ThreatIntelligenceLog, AWSConfiguration, User
)
# Assurez-vous que tous vos nouveaux formulaires sont importés
from .forms import (
    AnalysisForm, TaskForm, MitigationActionForm, AWSConfigurationForm,
    ReportStatusUpdateForm, SearchFilterForm
)
from .utils import (
    detect_input_type, vt_scan_file, vt_scan_url, vt_scan_ip, vt_scan_hash,
    otx_scan_url, otx_scan_ip, otx_scan_hash, get_ip_info
)
# ===================================================================
# 1. IMPORTER LA NOUVELLE CLASSE AWSMANAGER
# ===================================================================
from .aws_integration import AWSManager
from .notifications import send_notification

import logging
logger = logging.getLogger(__name__)

# ===================================================================
# VUE DE REDIRECTION DE CONNEXION (CORRIGÉE)
# ===================================================================
@login_required
def redirect_user_view(request):
    """
    Redirige l'utilisateur vers son tableau de bord approprié
    en fonction de son rôle.
    """
    # Votre modèle utilise 'admin' et 'analyst'
    if request.user.role == 'admin': 
        return redirect('dashboard') # Redirige vers le nom d'URL 'dashboard'
    else:
        return redirect('analyze')

# ==================== VUES ANALYSTE ====================

@login_required
def analyze(request):
    """Vue d'analyse principale pour les analystes"""
    # Empêche les admins de voir cette page
    if request.user.role == 'admin':
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = AnalysisForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                # ... (logique d'analyse inchangée) ...
                input_value = form.cleaned_data.get('input_value', '').strip()
                uploaded_file = form.cleaned_data.get('file')
                engine_choice = form.cleaned_data.get('engine_choice', 'vt')
                
                if uploaded_file:
                    input_type = 'file'
                    input_value = uploaded_file.name
                elif input_value:
                    input_type = detect_input_type(input_value)
                else:
                    messages.error(request, "Please provide input or upload a file")
                    return redirect('analyze')
                
                report = ThreatReport.objects.create(
                    analyst=request.user,
                    input_type=input_type,
                    input_value=input_value,
                    file_name=uploaded_file.name if uploaded_file else None,
                    engine_used=engine_choice,
                    status='pending' # Statut initial
                )
                
                vt_result = None
                otx_result = None
                ipinfo_result = None
                
                if engine_choice == 'vt':
                    if uploaded_file:
                        vt_result = vt_scan_file(uploaded_file)
                    elif input_type == 'url':
                        vt_result = vt_scan_url(input_value)
                    elif input_type == 'ip':
                        vt_result = vt_scan_ip(input_value)
                    elif input_type == 'hash':
                        vt_result = vt_scan_hash(input_value)
                    
                    if vt_result and 'error' not in vt_result:
                        report.vt_data = vt_result
                    else:
                        messages.error(request, f"VirusTotal error: {vt_result.get('error', 'Unknown')}")
                        report.delete()
                        return redirect('analyze')
                
                elif engine_choice == 'otx':
                    # ... (logique OTX inchangée) ...
                    if input_type == 'url':
                        otx_result = otx_scan_url(input_value)
                    elif input_type == 'ip':
                        otx_result = otx_scan_ip(input_value)
                    elif input_type == 'hash':
                        otx_result = otx_scan_hash(input_value)
                    
                    if otx_result and 'error' not in otx_result:
                         report.otx_data = otx_result
                    else:
                         messages.error(request, f"OTX error: {otx_result.get('error', 'Unknown')}")
                         report.delete()
                         return redirect('analyze')
                
                if input_type == 'ip':
                    ipinfo_result = get_ip_info(input_value)
                    if ipinfo_result:
                        report.ipinfo_data = ipinfo_result
                
                report.calculate_threat_score()
                
                # Générer le PDF (vérifiez que les dossiers media/reports/pdf existent)
                try:
                    pdf_path = generate_pdf_report(report)
                    report.pdf_report = pdf_path
                except Exception as e:
                    logger.error(f"Erreur lors de la génération du PDF : {e}")
                    messages.warning(request, f"Analyse terminée, mais le PDF n'a pas pu être généré : {e}")

                # Log to CSV
                # log_to_csv(report) # Optionnel, peut être activé
                # report.csv_logged = True
                
                report.save()
                
                messages.success(request, f"Analysis completed! Threat Score: {report.threat_score:.1f}/100")
                return redirect('report_detail', report_id=report.id)
                
            except Exception as e:
                logger.error(f"Analysis error: {str(e)}")
                messages.error(request, f"Analysis error: {str(e)}")
    else:
        form = AnalysisForm()
    
    recent_reports = ThreatReport.objects.filter(analyst=request.user).order_by('-created_at')[:5]
    
    return render(request, 'analyst/analyze.html', {
        'form': form,
        'recent_reports': recent_reports
    })

@login_required
def report_detail(request, report_id):
    """Voir le rapport détaillé (pour Analyste ET Admin)"""
    report = get_object_or_404(ThreatReport, id=report_id)
    
    # === Logique de Permission Corrigée ===
    is_owner = (report.analyst == request.user)
    is_assigned = (report.assigned_to == request.user)
    is_admin_role = (request.user.role == 'admin')

    if not (is_owner or is_assigned or is_admin_role):
        messages.error(request, "You don't have permission to view this report")
        return redirect('user_redirect') # Renvoie à la page de redirection
    
    # Logique pour le formulaire de mise à jour de statut de l'Admin
    status_form = None
    if request.user.role == 'admin':
        if request.method == 'POST' and 'update_status' in request.POST:
            # S'assure d'utiliser le bon nom de formulaire de votre forms.py
            status_form = ReportStatusUpdateForm(request.POST)
            if status_form.is_valid():
                report.status = status_form.cleaned_data['status']
                report.notes = f"{report.notes}\n\n[Admin Note]: {status_form.cleaned_data['notes']}"
                report.reviewed_at = datetime.now()
                report.save()
                messages.success(request, "Statut du rapport mis à jour.")
                return redirect('report_detail', report_id=report.id)
        
        # Prépare le formulaire pour l'affichage (méthode GET ou échec de validation)
        status_form = ReportStatusUpdateForm(initial={
            'status': report.status,
            'notes': '' 
        })

    tasks = report.tasks.all()
    mitigations = report.mitigations.all()
    
    return render(request, 'analyst/report_detail.html', {
        'report': report,
        'tasks': tasks,
        'mitigations': mitigations,
        'status_form': status_form # Ajouté pour l'admin
    })


@login_required
def send_to_admin(request, report_id):
    """Envoyer le rapport à un administrateur"""
    report = get_object_or_404(ThreatReport, id=report_id)
    
    # Seuls les analystes peuvent envoyer des rapports
    if request.user.role != 'analyst':
        messages.error(request, "Permission denied")
        return redirect('user_redirect') # Redirige vers son propre tableau de bord
    
    # Un analyste ne peut envoyer que ses propres rapports
    if report.analyst != request.user:
         messages.error(request, "You can only send your own reports")
         return redirect('analyze')

    admins = User.objects.filter(role='admin')
    
    if request.method == 'POST':
        admin_id = request.POST.get('admin_id')
        notes = request.POST.get('notes', '')
        
        if not admin_id:
            messages.error(request, "Veuillez sélectionner un administrateur.")
            return render(request, 'analyst/send_to_admin.html', {
                'report': report,
                'admins': admins
            })

        admin = get_object_or_404(User, id=admin_id, role='admin')
        
        report.assigned_to = admin
        report.notes = f"[Analyst Note]: {notes}"
        report.status = 'pending' # S'assurer que le statut est "pending"
        report.save()
        
        Notification.objects.create(
            recipient=admin,
            notification_type='new_report',
            title=f'New Threat Report: {report.input_type.upper()}',
            message=f'Analyst {request.user.username} sent you a {report.severity} severity report for review.',
            report=report
        )
        
        # send_notification(admin.id, { ... }) # Pour WebSocket
        
        messages.success(request, f"Rapport envoyé à {admin.username}")
        return redirect('report_detail', report_id=report.id)
    
    return render(request, 'analyst/send_to_admin.html', {
        'report': report,
        'admins': admins
    })

@login_required
def create_task(request, report_id):
    """Créer une tâche à partir d'un rapport"""
    report = get_object_or_404(ThreatReport, id=report_id)
    
    if request.method == 'POST':
        form = TaskForm(request.POST)
        if form.is_valid():
            task = form.save(commit=False)
            task.report = report
            task.created_by = request.user
            task.save()
            
            # Notifier l'utilisateur assigné (qui peut être un admin)
            if task.assigned_to:
                Notification.objects.create(
                    recipient=task.assigned_to,
                    notification_type='task_assigned',
                    title=f'New Task Assigned: {task.title}',
                    message=f'{request.user.username} assigned you a {task.priority} priority task.',
                    task=task,
                    report=report
                )
            
            messages.success(request, "Task created successfully")
            return redirect('report_detail', report_id=report.id)
    else:
        # Prépare le formulaire ; le __init__ du TaskForm filtre déjà les utilisateurs
        form = TaskForm()
    
    return render(request, 'analyst/create_task.html', {
        'form': form,
        'report': report
    })

# ==================== VUES ADMIN ====================

@login_required
def admin_dashboard(request):
    """Tableau de bord de l'administrateur"""
    if request.user.role != 'admin':
        messages.error(request, "Accès administrateur requis")
        return redirect('analyze')
    
    # Ne montre que les éléments assignés à CET admin
    assigned_reports = ThreatReport.objects.filter(assigned_to=request.user)
    assigned_tasks = Task.objects.filter(assigned_to=request.user)

    pending_reports = assigned_reports.filter(status='pending').count()
    critical_reports = assigned_reports.filter(severity='critical').count()
    open_tasks = assigned_tasks.filter(status='open').count()
    
    reports = assigned_reports.order_by('-created_at')[:10]
    
    notifications = Notification.objects.filter(
        recipient=request.user,
        is_read=False
    ).order_by('-created_at')[:5]
    
    severity_stats = assigned_reports.values('severity').annotate(count=Count('severity'))
    
    context = {
        'pending_reports': pending_reports,
        'critical_reports': critical_reports,
        'open_tasks': open_tasks,
        'reports': reports,
        'notifications': notifications,
        'severity_stats': severity_stats
    }
    
    return render(request, 'admin/dashboard.html', context)

@login_required
def admin_reports(request):
    """Voir tous les rapports assignés (avec filtre)"""
    if request.user.role != 'admin':
        messages.error(request, "Accès administrateur requis")
        return redirect('analyze')
    
    # Base Query: UNIQUEMENT les rapports assignés à l'utilisateur
    reports = ThreatReport.objects.filter(assigned_to=request.user)
    
    filter_form = SearchFilterForm(request.GET)
    
    if filter_form.is_valid():
        search = filter_form.cleaned_data.get('search')
        severity = filter_form.cleaned_data.get('severity')
        status = filter_form.cleaned_data.get('status')

        if severity:
            reports = reports.filter(severity=severity)
        if status:
            reports = reports.filter(status=status)
        if search:
            reports = reports.filter(
                Q(input_value__icontains=search) |
                Q(notes__icontains=search) |
                Q(analyst__username__icontains=search)
            )
            
    # Pagination
    paginator = Paginator(reports.order_by('-created_at'), 20)
    page = request.GET.get('page')
    reports_page = paginator.get_page(page)
    
    return render(request, 'admin/reports.html', {
        'reports': reports_page,
        'filter_form': filter_form
    })

@login_required
def review_report(request, report_id):
    """Examiner et prendre une décision sur un rapport"""
    if request.user.role != 'admin':
        messages.error(request, "Accès administrateur requis")
        return redirect('analyze')
    
    try:
        report = get_object_or_404(ThreatReport, id=report_id, assigned_to=request.user)
    except Exception:
        messages.error(request, "Rapport non trouvé ou non assigné à vous.")
        return redirect('dashboard')
        
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'approve':
            report.status = 'reviewed'
            report.reviewed_at = datetime.now()
            report.save()
            messages.success(request, "Rapport examiné et approuvé.")
        
        elif action == 'false_positive':
            report.status = 'false_positive'
            report.reviewed_at = datetime.now()
            report.save()
            messages.info(request, "Rapport marqué comme Faux Positif.")
        
        return redirect('report_detail', report_id=report.id)
    
    # Si ce n'est pas POST, rediriger simplement vers la page de détails
    return redirect('report_detail', report_id=report.id)

@login_required
def create_mitigation(request, report_id):
    """Créer une action de mitigation (AWS)"""
    if request.user.role != 'admin':
        messages.error(request, "Accès administrateur requis")
        return redirect('analyze')
    
    report = get_object_or_404(ThreatReport, id=report_id)
    
    if request.method == 'POST':
        form = MitigationActionForm(request.POST)
        if form.is_valid():
            mitigation = form.save(commit=False)
            mitigation.report = report
            mitigation.initiated_by = request.user
            mitigation.status = 'pending' # Statut initial
            mitigation.save()
            
            # ===================================================================
            # 2. APPEL DÉCOMMENTÉ
            # ===================================================================
            if form.cleaned_data.get('execute_now'):
                result = execute_mitigation(mitigation) # Appel de la fonction
                if result['success']:
                    messages.success(request, f"Action de mitigation exécutée : {result['message']}")
                else:
                    messages.error(request, f"Échec de la mitigation : {result['error']}")
            
            else:
                messages.success(request, "Action de mitigation créée (en attente d'exécution).")
                
            return redirect('report_detail', report_id=report.id)
    else:
        # Prépare le formulaire avec les données du rapport
        initial_data = {
            'target_value': report.input_value,
            'description': f'Mitigation pour le rapport {report.id} concernant {report.input_value}'
        }
        if report.input_type == 'ip':
            initial_data['action_type'] = 'block_ip'
        elif report.input_type == 'url':
            initial_data['action_type'] = 'block_domain'
        
        form = MitigationActionForm(initial=initial_data)
    
    return render(request, 'admin/create_mitigation.html', {
        'form': form,
        'report': report
    })

# ===================================================================
# 3. NOUVELLE FONCTION 'execute_mitigation'
# ===================================================================
def execute_mitigation(mitigation):
    """
    Exécute une action de mitigation en utilisant le AWSManager.
    """
    logger.info(f"Exécution de la mitigation ID {mitigation.id}...")
    
    # Étape 1 : Récupérer la configuration AWS active
    # Utilise la configuration nommée 'default_config' que vous avez créée
    try:
        aws_config = AWSConfiguration.objects.get(name='default_config', is_active=True)
        logger.info(f"Utilisation de la configuration AWS : {aws_config.name}")
    except AWSConfiguration.DoesNotExist:
        logger.error("Aucune configuration AWS active nommée 'default_config' trouvée.")
        mitigation.status = 'failed'
        mitigation.error_message = "Aucune configuration AWS active nommée 'default_config' trouvée."
        mitigation.save()
        return {'success': False, 'error': mitigation.error_message}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la configuration AWS : {e}")
        mitigation.status = 'failed'
        mitigation.error_message = str(e)
        mitigation.save()
        return {'success': False, 'error': str(e)}

    # Étape 2 : Initialiser le Manager AWS
    aws_manager = AWSManager(aws_config)
    
    # Étape 3 : Exécuter l'action basée sur le type
    result = {'success': False, 'error': 'Type d\'action inconnu'}
    try:
        if mitigation.action_type == 'block_ip':
            result = aws_manager.block_ip_in_security_group(
                ip_address=mitigation.target_value,
                description=mitigation.description
            )
        
        elif mitigation.action_type == 'block_domain':
            # TODO: Implémenter block_ip_in_waf (ou similaire)
            result = {'success': False, 'error': 'Le blocage de domaine (WAF) n\'est pas encore implémenté.'}
            
        # ... (Ajouter d'autres types d'action ici) ...

        # Étape 4 : Mettre à jour l'enregistrement de mitigation avec le résultat
        if result['success']:
            mitigation.status = 'completed'
            mitigation.completed_at = datetime.now()
            mitigation.report.status = 'mitigated' # Met aussi à jour le rapport
            mitigation.report.save()
        else:
            mitigation.status = 'failed'
            mitigation.error_message = result.get('error', 'Erreur inconnue')
            
        mitigation.save()
        return result

    except Exception as e:
        logger.error(f"Erreur critique lors de l'exécution de la mitigation {mitigation.id}: {e}")
        mitigation.status = 'failed'
        mitigation.error_message = f"Erreur système : {e}"
        mitigation.save()
        return {'success': False, 'error': str(e)}


# ==================== NOUVELLES VUES ADMIN ====================

@login_required
def admin_tasks_list(request):
    """Affiche une liste de toutes les tâches assignées à l'admin"""
    if request.user.role != 'admin':
        messages.error(request, "Accès administrateur requis")
        return redirect('analyze')
        
    tasks = Task.objects.filter(assigned_to=request.user).order_by('-created_at')
    
    # TODO: Ajouter un formulaire de filtre pour les tâches
    
    paginator = Paginator(tasks, 20)
    page = request.GET.get('page')
    tasks_page = paginator.get_page(page)
    
    return render(request, 'admin/tasks_list.html', {
        'tasks': tasks_page
    })

# ===================================================================
# === NOUVELLE FONCTION (La fonction manquante) ===
# ===================================================================
@login_required
def admin_mitigations_list(request):
    """Affiche une liste de toutes les actions de mitigation"""
    if request.user.role != 'admin':
        messages.error(request, "Accès administrateur requis")
        return redirect('analyze')
        
    # L'admin peut voir TOUTES les mitigations (pas seulement les siennes)
    mitigations = MitigationAction.objects.all().order_by('-created_at')
    
    paginator = Paginator(mitigations, 20)
    page = request.GET.get('page')
    mitigations_page = paginator.get_page(page)
    
    return render(request, 'admin/mitigations_list.html', {
        'mitigations': mitigations_page
    })
# ===================================================================


@login_required
def aws_config_view(request):
    """Gère la configuration AWS"""
    if request.user.role != 'admin':
        messages.error(request, "Accès administrateur requis")
        return redirect('analyze')

    # Utilise le nom 'default_config' pour obtenir ou créer la configuration
    config, created = AWSConfiguration.objects.get_or_create(
        name='default_config',
        defaults={'aws_region': 'us-east-1'} # Valeur par défaut si elle est créée
    )

    if request.method == 'POST':
        # S'assure d'utiliser le bon nom de formulaire de votre forms.py
        form = AWSConfigurationForm(request.POST, instance=config)
        if form.is_valid():
            form.save()
            messages.success(request, "Configuration AWS sauvegardée avec succès.")
            
            # Tester la connexion après la sauvegarde
            aws_manager = AWSManager(config)
            test_result = aws_manager.test_credentials()
            if test_result['success']:
                messages.success(request, f"Test de connexion AWS : {test_result['message']}")
            else:
                messages.error(request, f"Échec du test de connexion : {test_result['error']}")
                
            return redirect('aws_config')
    else:
        form = AWSConfigurationForm(instance=config)

    return render(request, 'admin/aws_config.html', {
        'form': form
    })

# ==================== FONCTIONS UTILITAIRES ====================

def generate_pdf_report(report):
    """Génère un rapport PDF"""
    # S'assurer que le dossier existe
    pdf_dir = f'{settings.MEDIA_ROOT}/reports/pdf/'
    Path(pdf_dir).mkdir(parents=True, exist_ok=True)
    
    filename = f'report_{report.id}.pdf'
    filepath_relative = f'reports/pdf/{filename}'
    filepath_absolute = f'{settings.MEDIA_ROOT}/{filepath_relative}'
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch)
    
    story = []
    styles = getSampleStyleSheet()
    
    # ... (Styles PDF inchangés) ...
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#C41E3A'),
        alignment=TA_CENTER
    )
    
    story.append(Paragraph("THREAT INTELLIGENCE REPORT", title_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Info Rapport
    info_data = [
        ['Report ID:', str(report.id)],
        ['Analyst:', report.analyst.username],
        ['Date:', report.created_at.strftime('%Y-%m-%d %H:%M:%S')],
        ['Input Type:', report.get_input_type_display()],
        ['Input Value:', report.input_value],
        ['Severity:', report.get_severity_display()],
        ['Threat Score:', f"{report.threat_score:.1f}/100"],
    ]
    
    info_table = Table(info_data, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.grey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmokey),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.3*inch))
    
    # ... (Logique d'ajout de données VT/OTX inchangée) ...
    if report.engine_used == 'vt' and report.vt_data and 'data' in report.vt_data:
        story.append(Paragraph("VirusTotal Analysis", styles['Heading2']))
        stats = report.vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        vt_data = [
            ['Malicious:', str(stats.get('malicious', 0))],
            ['Suspicious:', str(stats.get('suspicious', 0))],
            ['Undetected:', str(stats.get('undetected', 0))],
            ['Harmless:', str(stats.get('harmless', 0))],
        ]
        vt_table = Table(vt_data, colWidths=[2*inch, 4*inch])
        vt_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ]))
        story.append(vt_table)

    
    doc.build(story)
    
    # Sauvegarder le fichier sur le disque
    with open(filepath_absolute, 'wb') as f:
        f.write(buffer.getvalue())
    
    return filepath_relative # Retourne le chemin relatif pour le modèle


def log_to_csv(report):
    """Log report to CSV file"""
    # ... (Logique CSV inchangée) ...
    pass

@login_required
def download_pdf(request, report_id):
    """Download PDF report"""
    report = get_object_or_404(ThreatReport, id=report_id)
    
    # Vérification des permissions
    is_owner = (report.analyst == request.user)
    is_assigned = (report.assigned_to == request.user)
    is_admin_role = (request.user.role == 'admin')
    
    if not (is_owner or is_assigned or is_admin_role):
        messages.error(request, "Permission denied")
        return redirect('user_redirect')

    if report.pdf_report:
        try:
            # Ouvre le fichier depuis le stockage (media)
            return FileResponse(report.pdf_report.open(), as_attachment=True, filename=f'report_{report.id}.pdf')
        except FileNotFoundError:
            messages.error(request, "Le fichier PDF n'a pas été trouvé sur le serveur.")
            return redirect('report_detail', report_id=report.id)
        except Exception as e:
            messages.error(request, f"Erreur lors de l'ouverture du PDF : {e}")
            return redirect('report_detail', report_id=report.id)
    else:
        messages.error(request, "PDF non disponible pour ce rapport.")
        return redirect('report_detail', report_id=report.id)

@login_required
def export_csv(request):
    """Export threat intelligence logs to CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="threat_intelligence_export.csv"'
    
    logs = ThreatIntelligenceLog.objects.all().order_by('-timestamp')
    
    writer = csv.writer(response)
    writer.writerow([
        'Timestamp', 'Indicator', 'Type', 'Threat Score', 'Severity',
        'Malicious Count', 'Suspicious Count', 'Country', 'ASN',
        'Pulse Count', 'VT Positives', 'Analyst', 'Notes'
    ])
    
    for log in logs:
        writer.writerow([
            log.timestamp, log.indicator, log.indicator_type, log.threat_score,
            log.severity, log.malicious_count, log.suspicious_count,
            log.country, log.asn, log.pulse_count, log.vt_positives,
            log.analyst, log.notes
        ])
    
    return response