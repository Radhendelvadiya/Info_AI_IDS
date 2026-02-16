import json
from channels.generic.websocket import AsyncWebsocketConsumer


class AlertConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add('alerts', self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard('alerts', self.channel_name)

    async def alert_message(self, event):
        # event['message'] expected to be JSON-serializable
        await self.send(text_data=json.dumps(event['message']))
