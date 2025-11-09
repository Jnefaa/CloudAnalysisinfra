import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

class AWSManager:
    """
    Gère toutes les interactions avec l'API AWS (EC2, WAF, etc.)
    en utilisant les credentials de l'objet AWSConfiguration.
    """
    def __init__(self, aws_config):
        """
        Initialise les clients Boto3 avec les clés de la base de données.
        """
        self.config = aws_config
        
        # Configure le client EC2 (pour les Security Groups et NACLs)
        try:
            self.ec2 = boto3.client(
                'ec2',
                aws_access_key_id=self.config.aws_access_key,
                aws_secret_access_key=self.config.aws_secret_key,
                region_name=self.config.aws_region
            )
            logger.info(f"Client Boto3 EC2 initialisé pour la région {self.config.aws_region}")
        except Exception as e:
            logger.error(f"Échec de l'initialisation du client EC2 Boto3 : {e}")
            self.ec2 = None

        # TODO: Initialiser d'autres clients (wafv2, network-firewall) ici
        # self.wafv2 = boto3.client(...)
        # self.network_firewall = boto3.client(...)

    
    def test_credentials(self):
        """
        Tente une simple commande en lecture seule pour vérifier les identifiants.
        """
        if not self.ec2:
            return {'success': False, 'error': 'Client EC2 non initialisé.'}
        
        try:
            # Tente de décrire les régions (une commande simple)
            self.ec2.describe_regions()
            logger.info("Test de connexion AWS réussi.")
            return {'success': True, 'message': 'Connexion AWS réussie.'}
        except ClientError as e:
            logger.error(f"Test de connexion AWS échoué : {e}")
            return {'success': False, 'error': str(e)}

    # ===================================================================
    # FONCTIONNALITÉ 1 : BLOQUER UNE IP DANS UN SECURITY GROUP
    # ===================================================================
    def block_ip_in_security_group(self, ip_address, description="Bloqué par SOC Platform"):
        """
        Ajoute une règle 'deny' entrante au Security Group spécifié 
        pour bloquer une adresse IP.
        """
        if not self.ec2:
            return {'success': False, 'error': 'Client EC2 non initialisé.'}

        try:
            # Boto3 attend un format CIDR pour les IP
            if '/' not in ip_address:
                ip_cidr = f"{ip_address}/32"
            
            logger.info(f"Tentative de blocage de l'IP {ip_cidr} dans le SG {self.config.security_group_id}...")

            response = self.ec2.authorize_security_group_ingress(
                GroupId=self.config.security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': '-1', # Tous les protocoles
                        'FromPort': -1,   # Tous les ports
                        'ToPort': -1,     # Tous les ports
                        'IpRanges': [
                            {
                                'CidrIp': ip_cidr,
                                'Description': description
                            },
                        ]
                    },
                ]
            )
            
            logger.info(f"IP {ip_cidr} bloquée avec succès. Réponse : {response}")
            # Note : La réponse réelle est complexe. Nous retournons juste un succès.
            # L'ID de la règle de sécurité n'est pas facilement retourné ici.
            return {'success': True, 'message': f"IP {ip_cidr} ajoutée à la liste de blocage du Security Group {self.config.security_group_id}."}

        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                logger.warning(f"L'IP {ip_cidr} est déjà bloquée dans le SG {self.config.security_group_id}.")
                return {'success': False, 'error': f"L'IP {ip_cidr} est déjà dans la liste de blocage."}
            else:
                logger.error(f"Erreur Boto3 lors du blocage de l'IP {ip_cidr}: {e}")
                return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Erreur inattendue lors du blocage de l'IP {ip_cidr}: {e}")
            return {'success': False, 'error': str(e)}

    # ===================================================================
    # FONCTIONNALITÉ 2 : AUTORISER UNE IP (À FAIRE)
    # ===================================================================
    def allow_ip_in_security_group(self, ip_address):
        """
        Retire une règle 'deny' entrante du Security Group.
        """
        # LA LOGIQUE 'revoke_security_group_ingress' IRAIT ICI
        logger.warning("Fonction 'allow_ip' non implémentée.")
        return {'success': False, 'error': 'Fonction non implémentée.'}

    # ===================================================================
    # FONCTIONNALITÉ 3 : GÉRER LES RÈGLES WAF (À FAIRE)
    # ===================================================================
    def block_ip_in_waf(self, ip_address):
        """
        Ajoute une IP à un IPSet WAF.
        """
        logger.warning("Fonction 'block_ip_in_waf' non implémentée.")
        return {'success': False, 'error': 'Fonction non implémentée.'}

    # ... Ajoutez ici les autres fonctions de votre liste (Edit NACLs, etc.) ...