# pylint: disable=R0903
from abc import ABC, abstractmethod


class NotificationClient(ABC):
    @abstractmethod
    def send(self, receipients, message):
        pass


class NotificationFactory:
    @staticmethod
    def get(notification_type) -> None:
        types = {"email": EmailClient, "sms": SMSClient}
        cls = types.get(notification_type)
        if not cls:
            raise Exception(  # pylint:disable=W0719
                "Invalid notification type passed to notification factory"
            )
        return cls()


class EmailClient(NotificationClient):
    def __init__(self) -> None:
        # self.client = boto3.client("ses", region_name="ap-south-1")
        pass

    def send(self, receipients: list, message: dict):
        # response = self.client.send_email(
        #     Destination={
        #         "ToAddresses": receipients,
        #     },
        #     Message=message,
        # )
        # logger.info(response)
        pass


class SMSClient(NotificationClient):
    def __init__(self) -> None:
        # self.client = boto3.client(
        #     "sns",
        #     region_name="ap-south-1",
        # )
        pass

    def send(self, receipients: str, message: dict):
        # response = self.client.publish(
        #     PhoneNumber=receipients,
        #     Message=message,
        # )
        # logger.info(response)
        pass


email_client = NotificationFactory.get("email")
sms_client = NotificationFactory.get("sms")
