import re
from binascii import unhexlify
from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_shellshock import ModuleShellshock


def shellshock_callback(request: httpx.Request):
    if "user-agent" in request.headers:
        search = re.search(r"(\\x[0-9a-f]{2})+", request.headers["user-agent"])
        if search:
            hexstring = unhexlify(search.group().replace("\\x", ""))
            return httpx.Response(200, text=hexstring.decode())
    return httpx.Response(200, text="yolo")


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"] # Broaden the span here ...
    for ip in ips:
        respx.get(f"http://{ip}/").mock(return_value=httpx.Response(200))

        respx.get(url__regex=f"http://{ip}/.*").mock(side_effect=shellshock_callback)

    persister = AsyncMock()
    all_requests = []

    for ip in ips:
        request = Request(f"http://{ip}/")
        request.path_id = ips.index(ip) + 1
        all_requests.append(request)

        request = Request(f"http://{ip}/vuln/")
        request.path_id = ips.index(ip) + 1
        all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request(f"http://{ips[0]}/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleShellshock(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        for request in all_requests:
            await module.attack(request)

        assert persister.add_payload.call_count == len(ips)
        for i in range(len(ips)):
            assert persister.add_payload.call_args_list[i][1]["module"] == "shellshock"
            assert persister.add_payload.call_args_list[i][1]["category"] == "Command execution"
            assert persister.add_payload.call_args_list[i][1]["request"].url == f"http://{ips[i]}/vuln/"
