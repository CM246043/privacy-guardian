/**
 * Privacy Guardian — payment.js
 * Handles:
 *   1. Auto Opt-Out button logic (free tier: first 5, premium: all 26)
 *   2. PayPal smart button rendering inside the paywall modal
 *   3. Post-payment session unlock token storage and UI refresh
 *
 * Security:
 *   - Unlock token stored only in memory (AppState) — never in DOM attributes
 *   - All broker IDs sanitized before sending to /api/optout
 *   - PayPal order verified server-side before token is issued
 */

'use strict';

/* ── Free tier broker IDs (must match server FREE_BROKER_IDS) ── */
const FREE_BROKER_IDS = ['spokeo', 'whitepages', 'fastpeoplesearch', 'truepeoplesearch', 'peekyou'];

/* ── Extend AppState with payment fields ── */
// AppState is defined in app.js which loads before this file
AppState.unlockToken  = null;   // set after successful payment
AppState.isPremium    = false;

/* ── Wire Auto Opt-Out button after DOM ready ── */
document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('autoOptOutBtn');
    if (btn) btn.addEventListener('click', handleAutoOptOut);
});

/* ─────────────────────────────────────────────
   AUTO OPT-OUT FLOW
───────────────────────────────────────────── */

async function handleAutoOptOut() {
    // Must have user info
    if (!AppState.userInfo || !AppState.userInfo.firstName) {
        showToast('Enter your name in the search form first.', 'error');
        return;
    }

    // Must have scan results to know which brokers to target
    const targets = AppState.scanResults
        .filter(r => r.status === 'found' || r.status === 'pending')
        .map(r => r.id);

    if (targets.length === 0) {
        showToast('No brokers with "Found" or "Pending" status to opt out from. Run a scan first.', 'info');
        return;
    }

    // Split free vs premium
    const freePart    = targets.filter(id => FREE_BROKER_IDS.includes(id));
    const premiumPart = targets.filter(id => !FREE_BROKER_IDS.includes(id));

    if (!AppState.isPremium && premiumPart.length > 0) {
        // Run free tier immediately, then show paywall for the rest
        if (freePart.length > 0) {
            await runOptOut(freePart, 'Free Auto Opt-Out (5 brokers)');
        }
        showPaywall(premiumPart);
        return;
    }

    // Premium or all targets are in free tier
    await runOptOut(targets, AppState.isPremium
        ? 'Full Auto Opt-Out (All Brokers — Premium)'
        : 'Free Auto Opt-Out (5 Brokers)');
}

async function runOptOut(brokerIds, label) {
    openOptOutModal(label, brokerIds.length);

    try {
        const res = await fetch('/api/optout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Unlock-Token': AppState.unlockToken || ''
            },
            body: JSON.stringify({
                brokerIds:   brokerIds,
                userInfo:    AppState.userInfo,
                unlockToken: AppState.unlockToken || ''
            })
        });

        if (res.status === 402) {
            const data = await res.json();
            closeOptOutModal();
            showPaywall(data.blocked_brokers || brokerIds);
            return;
        }

        if (!res.ok) {
            showToast('Auto opt-out request failed. Try again.', 'error');
            closeOptOutModal();
            return;
        }

        const data = await res.json();
        renderOptOutResults(data.results || []);

    } catch (err) {
        showToast('Network error during auto opt-out.', 'error');
        closeOptOutModal();
    }
}

/* ── Opt-Out Modal helpers ── */

function openOptOutModal(label, total) {
    const modal    = document.getElementById('optoutModal');
    const subtitle = document.getElementById('optoutModalSubtitle');
    const fill     = document.getElementById('optoutProgressFill');
    const list     = document.getElementById('optoutResultsList');
    const done     = document.getElementById('optoutDoneMsg');

    if (subtitle) subtitle.textContent = sanitizeText(label) + ' — running on ' + total + ' broker' + (total !== 1 ? 's' : '') + '…';
    if (fill)     fill.style.width = '0%';
    if (list)     list.textContent = '';
    if (done)     done.style.display = 'none';
    if (modal)    modal.classList.add('active');
}

function closeOptOutModal() {
    const modal = document.getElementById('optoutModal');
    if (modal) modal.classList.remove('active');
}

function renderOptOutResults(results) {
    const list = document.getElementById('optoutResultsList');
    const fill = document.getElementById('optoutProgressFill');
    const done = document.getElementById('optoutDoneMsg');
    if (!list) return;

    list.textContent = '';
    const total = results.length;

    results.forEach((r, i) => {
        // Progress bar
        if (fill) fill.style.width = Math.round(((i + 1) / total) * 100) + '%';

        // Result row (DOM only — no innerHTML)
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:flex-start;gap:.75rem;padding:.75rem;border-radius:var(--radius-md);background:var(--bg-secondary)';

        const iconEl = document.createElement('span');
        iconEl.style.cssText = 'font-size:1.2rem;flex-shrink:0;margin-top:.1rem';
        const methodIcon = {
            automated:       r.success ? '✅' : '⚠️',
            manual_required: '📋',
            failed:          '❌',
            unknown:         '❓'
        };
        iconEl.textContent = methodIcon[r.method] || '❓';

        const textBlock = document.createElement('div');
        textBlock.style.flex = '1';

        const nameEl = document.createElement('strong');
        nameEl.textContent = sanitizeText(r.broker_name || r.broker_id);

        const badge = document.createElement('span');
        badge.style.cssText = 'margin-left:.5rem;font-size:.7rem;padding:.1rem .4rem;border-radius:.25rem;font-weight:600;text-transform:uppercase';
        if (r.method === 'automated' && r.success) {
            badge.textContent = 'Automated';
            badge.style.background = 'rgba(16,185,129,.15)';
            badge.style.color = '#059669';
        } else if (r.method === 'manual_required') {
            badge.textContent = 'Manual step needed';
            badge.style.background = 'rgba(245,158,11,.15)';
            badge.style.color = '#d97706';
        } else {
            badge.textContent = r.success ? 'Done' : 'Failed';
            badge.style.background = r.success ? 'rgba(16,185,129,.15)' : 'rgba(239,68,68,.15)';
            badge.style.color = r.success ? '#059669' : '#dc2626';
        }

        const msg = document.createElement('div');
        msg.style.cssText = 'font-size:.85rem;color:var(--text-secondary);margin-top:.25rem';
        msg.textContent = sanitizeText(r.message || '');

        if (r.manual_url && isSafeUrl(r.manual_url)) {
            const link = document.createElement('a');
            link.href = '#';
            link.textContent = ' Open opt-out page →';
            link.style.color = 'var(--primary-color)';
            link.addEventListener('click', (e) => { e.preventDefault(); safeOpen(r.manual_url); });
            msg.appendChild(link);
        }

        textBlock.appendChild(nameEl);
        textBlock.appendChild(badge);
        textBlock.appendChild(msg);
        row.appendChild(iconEl);
        row.appendChild(textBlock);
        list.appendChild(row);

        // Update scan result status
        const scanEntry = AppState.scanResults.find(s => s.id === r.broker_id);
        if (scanEntry && (r.success || r.method === 'automated')) {
            scanEntry.status = 'pending';
            if (!scanEntry.removalRequested) {
                scanEntry.removalRequested = new Date().toISOString();
                scanEntry.followUpDate = new Date(Date.now() + 30 * 86400000).toISOString();
            }
        }
    });

    // Save updated states
    storageSave(null, null);
    displayResults();

    if (done) done.style.display = 'block';
}

/* ─────────────────────────────────────────────
   PAYWALL + PAYPAL BUTTON
───────────────────────────────────────────── */

let _pendingPremiumBrokers = [];

function showPaywall(pendingBrokers) {
    _pendingPremiumBrokers = pendingBrokers || [];
    const modal = document.getElementById('paywallModal');
    if (!modal) return;
    modal.classList.add('active');
    renderPayPalButton();
}

function renderPayPalButton() {
    const container = document.getElementById('paypal-button-container');
    const status    = document.getElementById('paywallStatus');
    if (!container) return;

    // Clear any previously rendered button
    container.textContent = '';

    // Check if PayPal SDK is loaded
    if (typeof window.paypal === 'undefined') {
        if (status) status.textContent = 'PayPal is loading — please wait a moment and try again.';
        // Retry after 2s
        setTimeout(renderPayPalButton, 2000);
        return;
    }

    window.paypal.Buttons({
        style: {
            layout:  'vertical',
            color:   'blue',
            shape:   'rect',
            label:   'pay',
            height:  48
        },

        createOrder: function(data, actions) {
            if (status) status.textContent = 'Opening PayPal checkout…';
            return actions.order.create({
                purchase_units: [{
                    description: 'Privacy Guardian — Full Auto Opt-Out Unlock',
                    amount: {
                        currency_code: 'USD',
                        value: '5.00'
                    }
                }],
                application_context: {
                    brand_name:          'Privacy Guardian',
                    landing_page:        'BILLING',
                    user_action:         'PAY_NOW',
                    shipping_preference: 'NO_SHIPPING'
                }
            });
        },

        onApprove: async function(data, actions) {
            if (status) status.textContent = 'Processing payment…';

            try {
                // Capture the order via PayPal
                await actions.order.capture();

                // Verify on our server and get unlock token
                const res = await fetch('/api/payment/verify', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ orderID: sanitizeText(data.orderID, 128) })
                });

                if (!res.ok) {
                    if (status) status.textContent = 'Payment verification failed. Contact support.';
                    showToast('Payment could not be verified. Please contact support.', 'error');
                    return;
                }

                const result = await res.json();
                AppState.unlockToken = sanitizeText(result.unlockToken || '', 128);
                AppState.isPremium   = true;

                // Close paywall modal
                document.getElementById('paywallModal').classList.remove('active');
                showToast('Unlocked! Running full auto opt-out now…', 'success');

                // Run the remaining brokers
                if (_pendingPremiumBrokers.length > 0) {
                    await runOptOut(_pendingPremiumBrokers, 'Full Auto Opt-Out — Premium Unlock');
                }

            } catch (err) {
                if (status) status.textContent = 'Something went wrong. Please try again.';
                showToast('Payment error. Please try again or contact support.', 'error');
            }
        },

        onError: function(err) {
            if (status) status.textContent = 'PayPal encountered an error. Please try again.';
            showToast('PayPal error. Please try again.', 'error');
        },

        onCancel: function() {
            if (status) status.textContent = 'Payment cancelled.';
        }

    }).render('#paypal-button-container');
}

/* ── Patch createBrokerCard to add FREE/PRO tier badges ── */
if (typeof createBrokerCard === 'function') {
    const _original = createBrokerCard;
    const _patched = function(broker) {
        const card = _original(broker);
        const nameEl = card.querySelector('.broker-name');
        if (nameEl) {
            const isFree = FREE_BROKER_IDS.includes(broker.id);
            const tierBadge = document.createElement('span');
            tierBadge.className = 'tier-badge';
            tierBadge.textContent = isFree ? 'FREE' : 'PRO';
            tierBadge.style.cssText = [
                'margin-left:.5rem',
                'font-size:.6rem',
                'padding:.15rem .4rem',
                'border-radius:.25rem',
                'font-weight:700',
                'vertical-align:middle',
                'background:' + (isFree ? 'rgba(16,185,129,.15)' : 'rgba(37,99,235,.15)'),
                'color:' + (isFree ? '#059669' : '#2563eb')
            ].join(';');
            nameEl.appendChild(tierBadge);
        }
        return card;
    };
    // Make available both ways
    window.createBrokerCard = _patched;
    window._patchedCreateBrokerCard = _patched;
}
