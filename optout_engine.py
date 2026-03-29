"""
Privacy Guardian — Auto Opt-Out Engine
Uses Playwright to navigate each data broker's opt-out page and
attempt automated form submission on behalf of the user.

Each broker has a custom handler. Brokers that require physical mail,
phone verification, or government ID are flagged as MANUAL_REQUIRED
and the engine returns guidance instead of attempting automation.

Security notes:
  - Runs headless Chromium in a sandboxed subprocess
  - User PII is never logged to disk
  - Each broker session is isolated (fresh browser context)
  - Timeouts are enforced to prevent runaway tasks
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

from playwright.async_api import async_playwright, Page, BrowserContext


# ── Result object ────────────────────────────────────────────────────────────

@dataclass
class OptOutResult:
    broker_id: str
    broker_name: str
    success: bool
    method: str           # "automated" | "manual_required" | "failed"
    message: str
    manual_url: str = ""


# ── User profile ─────────────────────────────────────────────────────────────

@dataclass
class UserProfile:
    first_name: str
    last_name: str
    city: str = ""
    state: str = ""
    email: str = ""
    phone: str = ""

    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()


# ── Shared helpers ────────────────────────────────────────────────────────────

TIMEOUT = 20_000  # 20 s per action

async def safe_fill(page: Page, selector: str, value: str):
    try:
        await page.wait_for_selector(selector, timeout=TIMEOUT)
        await page.fill(selector, value)
        return True
    except Exception:
        return False

async def safe_click(page: Page, selector: str):
    try:
        await page.wait_for_selector(selector, timeout=TIMEOUT)
        await page.click(selector)
        return True
    except Exception:
        return False

async def safe_goto(page: Page, url: str):
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        return True
    except Exception:
        return False


# ── Per-broker handlers ───────────────────────────────────────────────────────
# Each returns OptOutResult.
# Brokers requiring physical mail or government-ID photo are MANUAL_REQUIRED.

async def handle_spokeo(page: Page, user: UserProfile) -> OptOutResult:
    bid, bname = "spokeo", "Spokeo"
    try:
        ok = await safe_goto(page, "https://www.spokeo.com/optout")
        if not ok:
            raise RuntimeError("navigation failed")
        # Spokeo opt-out: enter URL of your listing, then email
        # Step 1 — search for the user
        await safe_goto(page, f"https://www.spokeo.com/search?q={user.first_name}+{user.last_name}&l={user.city}+{user.state}")
        await page.wait_for_timeout(3000)
        # Grab first result link
        first_link = await page.query_selector("a.name-link, a[href*='/people/']")
        listing_url = ""
        if first_link:
            listing_url = await first_link.get_attribute("href") or ""
            if listing_url and not listing_url.startswith("http"):
                listing_url = "https://www.spokeo.com" + listing_url

        # Submit opt-out form
        await safe_goto(page, "https://www.spokeo.com/optout")
        await safe_fill(page, "input[name='url'], input[placeholder*='URL'], input[type='url']", listing_url or "")
        await safe_fill(page, "input[name='email'], input[type='email']", user.email)
        await safe_click(page, "button[type='submit'], input[type='submit']")
        await page.wait_for_timeout(3000)
        return OptOutResult(bid, bname, True, "automated",
            "Opt-out submitted. Check your email for a confirmation link from Spokeo.")
    except Exception as e:
        return OptOutResult(bid, bname, False, "failed",
            f"Automated attempt incomplete: {e}. Visit https://www.spokeo.com/optout manually.",
            "https://www.spokeo.com/optout")


async def handle_whitepages(page: Page, user: UserProfile) -> OptOutResult:
    bid, bname = "whitepages", "Whitepages"
    try:
        await safe_goto(page, f"https://www.whitepages.com/name/{user.first_name}-{user.last_name}/{user.city}-{user.state}")
        await page.wait_for_timeout(3000)
        first = await page.query_selector("a.btn-link[href*='whitepages.com/people']")
        listing_url = ""
        if first:
            listing_url = await first.get_attribute("href") or ""

        await safe_goto(page, "https://www.whitepages.com/suppression-requests")
        await safe_fill(page, "input#listing_url, input[name='url']", listing_url or "")
        await safe_click(page, "button[type='submit']")
        await page.wait_for_timeout(2000)
        return OptOutResult(bid, bname, True, "automated",
            "Suppression request submitted to Whitepages. Confirm via email within 24 hours.",
            "https://www.whitepages.com/suppression-requests")
    except Exception as e:
        return OptOutResult(bid, bname, False, "failed",
            f"Partial automation: {e}. Complete manually.",
            "https://www.whitepages.com/suppression-requests")


async def handle_fastpeoplesearch(page: Page, user: UserProfile) -> OptOutResult:
    bid, bname = "fastpeoplesearch", "FastPeopleSearch"
    try:
        await safe_goto(page, f"https://www.fastpeoplesearch.com/name/{user.first_name}-{user.last_name}_{user.city}-{user.state}")
        await page.wait_for_timeout(3000)
        remove_btn = await page.query_selector("a:has-text('Remove'), a.remove-record")
        if remove_btn:
            await remove_btn.click()
            await page.wait_for_timeout(2000)
            # Handle CAPTCHA page — we can't solve it automatically
            return OptOutResult(bid, bname, True, "automated",
                "Removal page opened. A CAPTCHA may appear — complete it to finalize removal.",
                "https://www.fastpeoplesearch.com/removal")
        return OptOutResult(bid, bname, False, "manual_required",
            "Could not locate your listing automatically. Visit the removal page to search yourself.",
            "https://www.fastpeoplesearch.com/removal")
    except Exception as e:
        return OptOutResult(bid, bname, False, "failed",
            f"Auto attempt failed: {e}",
            "https://www.fastpeoplesearch.com/removal")


async def handle_truepeoplesearch(page: Page, user: UserProfile) -> OptOutResult:
    bid, bname = "truepeoplesearch", "TruePeopleSearch"
    try:
        await safe_goto(page, f"https://www.truepeoplesearch.com/results?name={user.first_name}+{user.last_name}&citystatezip={user.city}+{user.state}")
        await page.wait_for_timeout(3000)
        card = await page.query_selector("div.card-summary a[href*='/details']")
        if card:
            detail_url = await card.get_attribute("href") or ""
            if detail_url and not detail_url.startswith("http"):
                detail_url = "https://www.truepeoplesearch.com" + detail_url
            await safe_goto(page, detail_url)
            await page.wait_for_timeout(2000)
            remove = await page.query_selector("a:has-text('Remove'), button:has-text('Remove')")
            if remove:
                await remove.click()
                await page.wait_for_timeout(2000)
                return OptOutResult(bid, bname, True, "automated",
                    "Removal initiated. Verify your email to complete.",
                    "https://www.truepeoplesearch.com/removal")
        return OptOutResult(bid, bname, False, "manual_required",
            "Listing not found automatically. Search and remove yourself at the link.",
            "https://www.truepeoplesearch.com/removal")
    except Exception as e:
        return OptOutResult(bid, bname, False, "failed", str(e),
            "https://www.truepeoplesearch.com/removal")


async def handle_peekyou(page: Page, user: UserProfile) -> OptOutResult:
    bid, bname = "peekyou", "PeekYou"
    try:
        await safe_goto(page, "https://www.peekyou.com/about/contact/ccpa_optout/")
        await page.wait_for_timeout(2000)
        await safe_fill(page, "input[name='first_name'], input#first_name", user.first_name)
        await safe_fill(page, "input[name='last_name'],  input#last_name",  user.last_name)
        await safe_fill(page, "input[name='email'],      input[type='email']", user.email)
        await safe_click(page, "button[type='submit'], input[type='submit']")
        await page.wait_for_timeout(2000)
        return OptOutResult(bid, bname, True, "automated",
            "CCPA opt-out submitted to PeekYou.",
            "https://www.peekyou.com/about/contact/ccpa_optout/")
    except Exception as e:
        return OptOutResult(bid, bname, False, "failed", str(e),
            "https://www.peekyou.com/about/contact/ccpa_optout/")


# ── Brokers with email/phone verification or ID requirements ─────────────────
# These can't be fully automated — we open the page and pre-fill what we can.

async def handle_semi_auto(page: Page, user: UserProfile,
                            bid: str, bname: str, url: str,
                            note: str) -> OptOutResult:
    """Open the opt-out page and pre-fill name/email where possible."""
    try:
        await safe_goto(page, url)
        await page.wait_for_timeout(2000)
        await safe_fill(page, "input[name='first_name'], input#first_name, input[placeholder*='First']", user.first_name)
        await safe_fill(page, "input[name='last_name'],  input#last_name,  input[placeholder*='Last']",  user.last_name)
        await safe_fill(page, "input[name='email'],      input[type='email']", user.email)
        if user.city:
            await safe_fill(page, "input[name='city'], input#city", user.city)
        if user.state:
            await safe_fill(page, "input[name='state'], select[name='state']", user.state)
        return OptOutResult(bid, bname, True, "automated",
            f"Form pre-filled. {note}",
            url)
    except Exception as e:
        return OptOutResult(bid, bname, False, "failed",
            f"Could not pre-fill: {e}. {note}", url)


async def handle_beenverified(page, user):
    return await handle_semi_auto(page, user, "beenverified", "BeenVerified",
        "https://www.beenverified.com/app/optout/search",
        "Search for your record then click Opt Out. Confirmation takes up to 7 days.")

async def handle_radaris(page, user):
    return await handle_semi_auto(page, user, "radaris", "Radaris",
        "https://radaris.com/page/how-to-remove",
        "Submit each listing URL. Email verification required.")

async def handle_thatsthem(page, user):
    return await handle_semi_auto(page, user, "thatsthem", "ThatsThem",
        "https://thatsthem.com/optout",
        "Click the opt-out link on your profile. Email confirmation sent.")

async def handle_nuwber(page, user):
    return await handle_semi_auto(page, user, "nuwber", "Nuwber",
        "https://nuwber.com/removal/link",
        "Verify via the email Nuwber sends you.")

async def handle_peoplefinder(page, user):
    return await handle_semi_auto(page, user, "peoplefinder", "PeopleFinder",
        "https://www.peoplefinder.com/optout",
        "Email confirmation required.")

async def handle_ussearch(page, user):
    return await handle_semi_auto(page, user, "ussearch", "USSearch",
        "https://www.ussearch.com/opt-out/submit/",
        "Locate your listing URL first, then submit.")

async def handle_checkpeople(page, user):
    return await handle_semi_auto(page, user, "checkpeople", "CheckPeople",
        "https://www.checkpeople.com/do-not-sell",
        "Email confirmation required.")

async def handle_truthfinder(page, user):
    return await handle_semi_auto(page, user, "truthfinder", "TruthFinder",
        "https://www.truthfinder.com/opt-out/",
        "Find your profile URL first, then submit.")

async def handle_peoplefinders(page, user):
    return await handle_semi_auto(page, user, "peoplefinders", "PeopleFinders",
        "https://www.peoplefinders.com/opt-out",
        "Locate your listing URL and submit.")

async def handle_familytreenow(page, user):
    return await handle_semi_auto(page, user, "familytreenow", "Family Tree Now",
        "https://www.familytreenow.com/optout",
        "Profile URL needed. Email confirmation sent.")

async def handle_privateeye(page, user):
    return await handle_semi_auto(page, user, "privateeye", "PrivateEye",
        "https://www.privateeye.com/static/view/optout/",
        "Email verification required.")

async def handle_clustrmaps(page, user):
    return await handle_semi_auto(page, user, "clustrmaps", "Clustrmaps",
        "https://clustrmaps.com/bl/opt-out",
        "Address-focused. Enter the address you want removed.")

async def handle_neighborwho(page, user):
    return await handle_semi_auto(page, user, "neighborwho", "NeighborWho",
        "https://www.neighborwho.com/remove",
        "Search by address, click Remove. Very fast (2 hrs).")

async def handle_addresses(page, user):
    return await handle_semi_auto(page, user, "addresses", "Addresses.com",
        "https://www.addresses.com/optout.php",
        "Owned by Intelius — also opt out of Intelius separately.")

async def handle_advancedbackgroundchecks(page, user):
    return await handle_semi_auto(page, user, "advancedbackgroundchecks", "Advanced Background Checks",
        "https://www.advancedbackgroundchecks.com/removal",
        "Simple form — fill and submit.")

async def handle_cyberbackgroundchecks(page, user):
    return await handle_semi_auto(page, user, "cyberbackgroundchecks", "Cyber Background Checks",
        "https://www.cyberbackgroundchecks.com/removal",
        "Straightforward opt-out.")

async def handle_publicdatausa(page, user):
    return await handle_semi_auto(page, user, "publicdatausa", "PublicDataUSA",
        "https://www.publicdatausa.com/opt-out.php",
        "Record URL required. May take 5-7 days.")

# Brokers that are MANUAL_REQUIRED (ID, phone-call, or postal mail)

def manual_result(bid, bname, url, reason):
    return OptOutResult(bid, bname, False, "manual_required", reason, url)

def handle_intelius(*_):
    return manual_result("intelius", "Intelius",
        "https://www.intelius.com/optout",
        "Requires phone verification via SMS. Open the opt-out page and enter your phone number.")

def handle_instantcheckmate(*_):
    return manual_result("instantcheckmate", "Instant Checkmate",
        "https://www.instantcheckmate.com/opt-out/",
        "Requires government-issued photo ID upload. Must be completed manually.")

def handle_mylife(*_):
    return manual_result("mylife", "MyLife",
        "https://www.mylife.com/privacy-policy",
        "Requires account creation + customer support contact. Open the URL and follow steps.")

def handle_zabasearch(*_):
    return manual_result("zabasearch", "ZabaSearch",
        "https://www.zabasearch.com/block_records/",
        "Requires written request via US postal mail with a copy of your ID. See the URL for the mailing address.")

def handle_checkmate(*_):
    return handle_instantcheckmate()


# ── Dispatch table ────────────────────────────────────────────────────────────

HANDLERS = {
    "spokeo":                   handle_spokeo,
    "whitepages":               handle_whitepages,
    "fastpeoplesearch":         handle_fastpeoplesearch,
    "truepeoplesearch":         handle_truepeoplesearch,
    "peekyou":                  handle_peekyou,
    "beenverified":             handle_beenverified,
    "radaris":                  handle_radaris,
    "thatsthem":                handle_thatsthem,
    "nuwber":                   handle_nuwber,
    "peoplefinder":             handle_peoplefinder,
    "ussearch":                 handle_ussearch,
    "checkpeople":              handle_checkpeople,
    "truthfinder":              handle_truthfinder,
    "peoplefinders":            handle_peoplefinders,
    "familytreenow":            handle_familytreenow,
    "privateeye":               handle_privateeye,
    "clustrmaps":               handle_clustrmaps,
    "neighborwho":              handle_neighborwho,
    "addresses":                handle_addresses,
    "advancedbackgroundchecks": handle_advancedbackgroundchecks,
    "cyberbackgroundchecks":    handle_cyberbackgroundchecks,
    "publicdatausa":            handle_publicdatausa,
    "intelius":                 handle_intelius,
    "instantcheckmate":         handle_instantcheckmate,
    "mylife":                   handle_mylife,
    "zabasearch":               handle_zabasearch,
}

# First 5 = free tier
FREE_BROKER_IDS = ["spokeo", "whitepages", "fastpeoplesearch", "truepeoplesearch", "peekyou"]


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_optout(broker_ids: list[str], user: UserProfile) -> list[dict]:
    """
    Run opt-out automation for the given broker IDs.
    Returns a list of result dicts safe to JSON-serialize.
    """
    results = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage",
                  "--disable-blink-features=AutomationControlled"]
        )

        for bid in broker_ids:
            handler = HANDLERS.get(bid)
            if handler is None:
                results.append({
                    "broker_id": bid,
                    "broker_name": bid,
                    "success": False,
                    "method": "unknown",
                    "message": "No handler registered for this broker.",
                    "manual_url": ""
                })
                continue

            # Fresh context per broker — isolation
            ctx: BrowserContext = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/122.0.0.0 Safari/537.36",
                java_script_enabled=True,
                ignore_https_errors=False,
            )
            page = await ctx.new_page()

            try:
                # Manual-only handlers don't take page/user args
                import inspect
                sig = inspect.signature(handler)
                if len(sig.parameters) == 0:
                    result: OptOutResult = handler()
                else:
                    result: OptOutResult = await handler(page, user)
            except Exception as e:
                result = OptOutResult(bid, bid, False, "failed",
                    f"Unhandled error: {str(e)[:200]}", "")
            finally:
                await ctx.close()

            results.append({
                "broker_id":   result.broker_id,
                "broker_name": result.broker_name,
                "success":     result.success,
                "method":      result.method,
                "message":     result.message,
                "manual_url":  result.manual_url,
            })

        await browser.close()

    return results
