# vt_analyzer/notifications.py

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

def send_notification(user_id, notification_data):
    """
    Send real-time notification via WebSocket
    
    Args:
        user_id: ID of the user to notify
        notification_data: Dictionary containing notification details
    """
    channel_layer = get_channel_layer()
    
    if channel_layer:
        async_to_sync(channel_layer.group_send)(
            f'user_{user_id}',
            {
                'type': 'notification_message',
                'data': notification_data
            }
        ) 