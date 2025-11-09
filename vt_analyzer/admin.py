from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User, 
    ThreatReport, 
    MitigationAction, 
    Task, 
    Notification, 
    ThreatIntelligenceLog, 
    AWSConfiguration
)

# Créez une classe d'administration personnalisée qui hérite de UserAdmin
class CustomUserAdmin(UserAdmin):
    
    # Ajoute vos champs personnalisés à la page "Ajouter un utilisateur"
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Rôle et infos personnalisées', {
            'fields': ('role', 'department', 'phone'),
        }),
    )
    
    # Ajoute vos champs personnalisés à la page "Modifier un utilisateur"
    fieldsets = UserAdmin.fieldsets + (
        ('Rôle et infos personnalisées', {
            'fields': ('role', 'department', 'phone'),
        }),
    )

# Enregistrez votre modèle User AVEC la classe personnalisée
admin.site.register(User, CustomUserAdmin)

# Enregistrez tous vos autres modèles (cette partie est la même qu'avant)
admin.site.register(ThreatReport)
admin.site.register(MitigationAction)
admin.site.register(Task)
admin.site.register(Notification)
admin.site.register(ThreatIntelligenceLog)
admin.site.register(AWSConfiguration)