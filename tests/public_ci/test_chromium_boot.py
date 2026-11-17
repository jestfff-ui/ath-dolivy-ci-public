"""Exercise the browser runner with a synthetic document and no app fixtures."""

import asyncio
from time import perf_counter

from playwright.async_api import async_playwright


def test_chromium_context_lifecycle(tmp_path):
    async def scenario():
        async with async_playwright() as playwright:
            started = perf_counter()
            browser = await playwright.chromium.launch(headless=True)
            print(f"Chromium launched in {perf_counter() - started:.3f}s")
            try:
                for record in (True, False):
                    options = {"record_video_dir": str(tmp_path / "video")} if record else {}
                    context = await browser.new_context(offline=True, **options)
                    try:
                        page = await context.new_page()
                        await page.set_content("<main>PUBLIC_CI_SYNTHETIC_PAGE</main>")
                        await page.get_by_text("PUBLIC_CI_SYNTHETIC_PAGE", exact=True).wait_for()
                        video = page.video
                    finally:
                        closing = perf_counter()
                        await context.close()
                        print(f"Context closed in {perf_counter() - closing:.3f}s, record={record}")
                    if record:
                        assert video is not None and (await video.path()).stat().st_size > 0
            finally:
                await browser.close()

    asyncio.run(scenario())
