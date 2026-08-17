import json
from channels.generic.websocket import AsyncWebsocketConsumer

class AssessmentConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.assessment_id = self.scope['url_route']['kwargs']['assessment_id']
        self.group_name = f'assessment_{self.assessment_id}'

        # Join the assessment-specific room group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave the assessment room group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    # Receive messages from room group and send them down the websocket connection
    async def scan_event(self, event):
        payload = event.get('payload', {})
        await self.send(text_data=json.dumps(payload))
