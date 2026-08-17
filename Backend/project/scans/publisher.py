from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import django.utils.timezone as timezone

class ScanEventPublisher:
    @classmethod
    def publish(cls, assessment_id, event_type, data, job_id=None):
        channel_layer = get_channel_layer()
        if not channel_layer:
            return
            
        payload = {
            "event": event_type,
            "job_id": job_id,
            "assessment_id": assessment_id,
            "timestamp": timezone.now().isoformat(),
            "data": data
        }
        
        try:
            async_to_sync(channel_layer.group_send)(
                f'assessment_{assessment_id}',
                {
                    'type': 'scan_event',
                    'payload': payload
                }
            )
        except Exception as e:
            print(f"[ERROR] Failed to publish WebSocket event: {str(e)}")
