from decimal import ROUND_DOWN, Decimal
from logging import getLogger
from typing import TYPE_CHECKING, Callable, Optional, Union
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.utils.translation import gettext as _


from userinterface.models import CustomerCompany


logger = getLogger(__name__)
API_BASE_URL = "https://my.sevdesk.de/api/v1"


def _request(
    method: Callable, endpoint: str, payload: Union[dict, None], **kwargs
) -> dict:
    """Communicates with the sevdesk API."""
    if "headers" not in kwargs:
        kwargs["headers"] = {}
    kwargs["headers"]["Authorization"] = settings.SEVDESK_TOKEN

    response = method(f"{settings.SEVDESK_API_URL}/{endpoint}/", payload, **kwargs)
    response.raise_for_status()
    return response.json()


def get(endpoint: str, params: Optional[dict] = None, **kwargs) -> dict:
    """Makes a HTTP GET request to the sevdesk API."""
    return _request(requests.get, endpoint, params, **kwargs)


def getCustomerInvoices(
    customer: "CustomerCompany", params: dict, *args, **kwargs
) -> dict:
    """Loads the Organization's invoices from sevdesk."""
    if not customer._sevDeskId:
        return {}
    client = get("Contact", {"customerNumber": customer._sevDeskId})

    invoices = {}
    if client.get("objects"):
        params.update(
            {
                "contact[objectName]": "Contact",
                "contact[id]": client["objects"][0]["id"],
            }
        )
        invoices = get("Invoice", params, *args, **kwargs)
        if invoices and "objects" in invoices:
            # Need to manually filter out invoices that don't belong to `org` because sevdesk won't apply filters if the params contain `id`
            invoices["objects"] = [
                invoice
                for invoice in invoices["objects"]
                if invoice["contact"]["id"] == client["objects"][0]["id"]
            ]
    return invoices

