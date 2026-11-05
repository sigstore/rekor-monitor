//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Rekor Watch - Main JavaScript

const MVType = Object.freeze({
    CERT_IDENTITY: 'certIdentity',
    FINGERPRINT:   'fingerprint',
    SUBJECT:       'subject',
    OID_EXTENSION: 'oidExtension',
});

const CUSTOM_OID_VALUE = '__custom__';
let knownOIDOptions = [];
let knownOIDByValue = new Map();

document.addEventListener('DOMContentLoaded', function() {
    knownOIDOptions = loadKnownOIDOptions();
    knownOIDByValue = new Map(knownOIDOptions.map((option) => [option.oid, option.name]));

    if (document.getElementById('matches-container')) {
        loadMatches();
        setInterval(loadMatches, 30000);
    }
    if (document.getElementById('subscriptions-container')) {
        loadSubscriptions();
        setInterval(loadSubscriptions, 30000);
    }
});

function loadKnownOIDOptions() {
    const el = document.getElementById('known-oids-data');
    if (!el) return [];

    try {
        const parsed = JSON.parse(el.textContent || '[]');
        if (!Array.isArray(parsed)) return [];
        return parsed
            .filter((option) => option && typeof option.name === 'string' && typeof option.oid === 'string')
            .sort((a, b) => a.name.localeCompare(b.name));
    } catch (error) {
        console.error('Error parsing known OIDs:', error);
        return [];
    }
}

async function loadMatches() {
    const container = document.getElementById('matches-container');

    try {
        const response = await fetch('/api/matches');
        if (response.status === 401) {
            window.location.href = '/login';
            return;
        }
        if (!response.ok) {
            throw new Error(`HTTP error: ${response.status}`);
        }

        const matches = await response.json();
        renderMatches(container, matches);
        updateLastUpdated();
    } catch (error) {
        console.error('Error loading matches:', error);
        const p = document.createElement('p');
        p.className = 'error';
        p.textContent = `Failed to load matches: ${error.message}`;
        container.replaceChildren(p);
    }
}

async function loadSubscriptions() {
    const container = document.getElementById('subscriptions-container');

    try {
        const response = await fetch('/api/subscriptions');
        if (response.status === 401) {
            window.location.href = '/login';
            return;
        }
        if (!response.ok) {
            throw new Error(`HTTP error: ${response.status}`);
        }

        const subs = await response.json();
        renderSubscriptions(container, subs);
    } catch (error) {
        console.error('Error loading subscriptions:', error);
        const p = document.createElement('p');
        p.className = 'error';
        p.textContent = `Failed to load subscriptions: ${error.message}`;
        container.replaceChildren(p);
    }
}

function resetNotificationChannelFields() {
    // Clear every channel-specific input so values from a previously
    // edited subscription don't leak into the next form submission.
    // Mirror this in editSubscription() before populating channel fields.
    document.getElementById('sub-webhook').value = '';
}

function toggleAddSubscriptionForm() {
    const form = document.getElementById('add-subscription-form');
    if (form.style.display === 'none') {
        document.getElementById('sub-edit-id').value = '';
        document.getElementById('sub-name').value = '';
        document.getElementById('sub-type').value = MVType.CERT_IDENTITY;
        document.getElementById('sub-notify-type').value = 'webhook';
        resetNotificationChannelFields();
        document.getElementById('sub-submit-btn').textContent = 'Create';
        document.getElementById('sub-error').style.display = 'none';
        updateFormFields();
        updateNotificationFields();
        form.style.display = 'block';
    } else {
        form.style.display = 'none';
    }
}

function updateNotificationFields() {
    const type = document.getElementById('sub-notify-type').value;
    document.getElementById('webhook-field').style.display = (type === 'webhook') ? '' : 'none';
    document.getElementById('email-field').style.display = (type === 'email') ? '' : 'none';
}

function createFormGroup(labelText, inputId, placeholder) {
    const group = document.createElement('div');
    group.className = 'form-group';
    const label = document.createElement('label');
    label.setAttribute('for', inputId);
    label.textContent = labelText;
    const input = document.createElement('input');
    input.type = 'text';
    input.id = inputId;
    input.placeholder = placeholder;
    group.appendChild(label);
    group.appendChild(input);
    return group;
}

function createSelectGroup(labelText, inputId, options) {
    const group = document.createElement('div');
    group.className = 'form-group';
    const label = document.createElement('label');
    label.setAttribute('for', inputId);
    label.textContent = labelText;

    const select = document.createElement('select');
    select.id = inputId;
    for (const option of options) {
        const optionEl = document.createElement('option');
        optionEl.value = option.value;
        optionEl.textContent = option.label;
        select.appendChild(optionEl);
    }

    group.appendChild(label);
    group.appendChild(select);
    return group;
}

function createTagInput(labelText, inputId, placeholder) {
    const group = document.createElement('div');
    group.className = 'form-group';
    const label = document.createElement('label');
    label.textContent = labelText;
    group.appendChild(label);

    const wrapper = document.createElement('div');
    wrapper.className = 'tag-input-wrapper';
    wrapper.dataset.tags = '[]';
    wrapper.id = inputId;

    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = placeholder;
    wrapper.appendChild(input);

    wrapper.addEventListener('click', () => input.focus());

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault();
            const val = input.value.trim().replace(/,+$/, '').trim();
            if (val) {
                addTag(wrapper, val);
                input.value = '';
            }
        }
        if (e.key === 'Backspace' && input.value === '') {
            const tags = JSON.parse(wrapper.dataset.tags);
            if (tags.length > 0) {
                tags.pop();
                wrapper.dataset.tags = JSON.stringify(tags);
                renderTags(wrapper);
            }
        }
    });

    input.addEventListener('blur', () => {
        const val = input.value.trim().replace(/,+$/, '').trim();
        if (val) {
            addTag(wrapper, val);
            input.value = '';
        }
    });

    group.appendChild(wrapper);
    return group;
}

function addTag(wrapper, value) {
    const tags = JSON.parse(wrapper.dataset.tags);
    if (!tags.includes(value)) {
        tags.push(value);
        wrapper.dataset.tags = JSON.stringify(tags);
        renderTags(wrapper);
    }
}

function renderTags(wrapper) {
    const tags = JSON.parse(wrapper.dataset.tags);
    const input = wrapper.querySelector('input');
    // Remove existing tag elements
    wrapper.querySelectorAll('.tag').forEach(el => el.remove());
    // Insert tags before the input
    for (const tag of tags) {
        const span = document.createElement('span');
        span.className = 'tag';
        span.textContent = tag;
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = '\u00d7';
        btn.setAttribute('aria-label', `Remove ${tag}`);
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const current = JSON.parse(wrapper.dataset.tags);
            wrapper.dataset.tags = JSON.stringify(current.filter(t => t !== tag));
            renderTags(wrapper);
        });
        span.appendChild(btn);
        wrapper.insertBefore(span, input);
    }
}

function getTagValues(inputId) {
    const wrapper = document.getElementById(inputId);
    if (!wrapper) return [];
    return JSON.parse(wrapper.dataset.tags);
}

function setTagValues(inputId, values) {
    const wrapper = document.getElementById(inputId);
    if (!wrapper) return;
    wrapper.dataset.tags = JSON.stringify(values);
    renderTags(wrapper);
}

function syncOIDField() {
    const selectEl = document.getElementById('sub-oid-select');
    const oidEl = document.getElementById('sub-oid');
    if (!selectEl || !oidEl) return;

    if (selectEl.value === CUSTOM_OID_VALUE) {
        oidEl.value = '';
        oidEl.disabled = false;
        oidEl.placeholder = '1.3.6.1.4.1.57264.1.1';
        return;
    }

    oidEl.value = selectEl.value;
    oidEl.disabled = true;
}

function setOIDFormValue(oidStr) {
    const selectEl = document.getElementById('sub-oid-select');
    const oidEl = document.getElementById('sub-oid');
    if (!selectEl || !oidEl) return;

    const isKnown = knownOIDByValue.has(oidStr);
    selectEl.value = isKnown ? oidStr : CUSTOM_OID_VALUE;
    syncOIDField();
    if (!isKnown) {
        oidEl.value = oidStr;
    }
}

function formatOIDDisplay(oid) {
    const oidStr = Array.isArray(oid) ? oid.join('.') : oid;
    if (!oidStr) return '';

    const knownName = knownOIDByValue.get(oidStr);
    if (!knownName) return oidStr;
    return `${knownName} (${oidStr})`;
}

function updateFormFields() {
    const type = document.getElementById('sub-type').value;
    const container = document.getElementById('sub-fields');
    container.replaceChildren();

    switch (type) {
        case MVType.CERT_IDENTITY:
            container.appendChild(
                createFormGroup('Certificate Subject', 'sub-cert-subject', 'user@example.com'));
            container.appendChild(
                createTagInput('Issuers (optional)', 'sub-issuers', 'Type an issuer and press Enter'));
            break;
        case MVType.FINGERPRINT:
            container.appendChild(
                createFormGroup('Fingerprint', 'sub-fingerprint', 'ABC123DEF456'));
            break;
        case MVType.SUBJECT:
            container.appendChild(
                createFormGroup('Subject', 'sub-subject', 'subject@example.com'));
            break;
        case MVType.OID_EXTENSION:
            container.appendChild(
                createSelectGroup('Known OID', 'sub-oid-select', [
                    ...knownOIDOptions.map((option) => ({
                        value: option.oid,
                        label: `${option.name} (${option.oid})`,
                    })),
                    {value: CUSTOM_OID_VALUE, label: 'Custom OID'},
                ]));
            container.appendChild(
                createFormGroup('OID (dot-separated)', 'sub-oid', '1.3.6.1.4.1.57264.1.1'));
            container.appendChild(
                createTagInput('Extension Values', 'sub-ext-values', 'Type a value and press Enter'));
            document.getElementById('sub-oid-select').addEventListener('change', syncOIDField);
            setOIDFormValue(knownOIDOptions[0]?.oid || '');
            break;
    }
}

function editSubscription(sub) {
    const form = document.getElementById('add-subscription-form');
    form.style.display = 'block';
    document.getElementById('sub-edit-id').value = sub.ID;
    document.getElementById('sub-name').value = sub.Name || '';
    document.getElementById('sub-error').style.display = 'none';
    // Clear stale channel-specific values from a prior edit before
    // repopulating, otherwise (e.g.) the previous subscription's
    // webhook URL stays in the hidden field and gets resubmitted.
    resetNotificationChannelFields();

    if (sub.MonitoredValue) {
        document.getElementById('sub-type').value = sub.MonitoredValue.type || MVType.CERT_IDENTITY;
        updateFormFields();

        const mv = sub.MonitoredValue;
        switch (mv.type) {
            case MVType.CERT_IDENTITY: {
                const el = document.getElementById('sub-cert-subject');
                if (el) el.value = mv.certSubject || '';
                if (Array.isArray(mv.issuers)) setTagValues('sub-issuers', mv.issuers);
                break;
            }
            case MVType.FINGERPRINT: {
                const el = document.getElementById('sub-fingerprint');
                if (el) el.value = mv.fingerprint || '';
                break;
            }
            case MVType.SUBJECT: {
                const el = document.getElementById('sub-subject');
                if (el) el.value = mv.subject || '';
                break;
            }
            case MVType.OID_EXTENSION: {
                const oidStr = Array.isArray(mv.oid) ? mv.oid.join('.') : mv.oid;
                if (oidStr) setOIDFormValue(oidStr);
                if (Array.isArray(mv.extensionValues)) setTagValues('sub-ext-values', mv.extensionValues);
                break;
            }
        }
    }

    const notifyType = sub.NotificationType || 'webhook';
    document.getElementById('sub-notify-type').value = notifyType;
    updateNotificationFields();

    document.getElementById('sub-webhook').value = sub.WebhookURL || '';

    document.getElementById('sub-submit-btn').textContent = 'Save';
    form.scrollIntoView({behavior: 'smooth'});
}

async function submitSubscription() {
    const errorEl = document.getElementById('sub-error');
    errorEl.style.display = 'none';

    const name = document.getElementById('sub-name').value.trim();
    const type = document.getElementById('sub-type').value;
    const webhookURL = document.getElementById('sub-webhook').value.trim();
    const editId = document.getElementById('sub-edit-id').value;

    if (!name) {
        errorEl.textContent = 'Subscription name is required';
        errorEl.style.display = 'block';
        return;
    }

    const monitoredValue = {type};

    switch (type) {
        case MVType.CERT_IDENTITY: {
            monitoredValue.certSubject = (document.getElementById('sub-cert-subject')?.value || '').trim();
            const issuers = getTagValues('sub-issuers');
            if (issuers.length > 0) {
                monitoredValue.issuers = issuers;
            }
            break;
        }
        case MVType.FINGERPRINT:
            monitoredValue.fingerprint = (document.getElementById('sub-fingerprint')?.value || '').trim();
            break;
        case MVType.SUBJECT:
            monitoredValue.subject = (document.getElementById('sub-subject')?.value || '').trim();
            break;
        case MVType.OID_EXTENSION: {
            const oidStr = (document.getElementById('sub-oid')?.value || '').trim();
            monitoredValue.oid = oidStr.split('.').map(s => parseInt(s, 10));
            monitoredValue.extensionValues = getTagValues('sub-ext-values');
            break;
        }
    }

    const notificationType = document.getElementById('sub-notify-type').value;
    const payload = {name, monitoredValue, notificationType, webhookURL};
    let method = 'POST';
    let url = '/api/subscriptions';
    if (editId) {
        method = 'PUT';
        url = `/api/subscriptions/${editId}`;
    }

    try {
        const response = await fetch(url, {
            method,
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `HTTP ${response.status}`);
        }
        document.getElementById('add-subscription-form').style.display = 'none';
        loadSubscriptions();
    } catch (error) {
        errorEl.textContent = error.message;
        errorEl.style.display = 'block';
    }
}

async function subscriptionAction(url, method, errorPrefix) {
    try {
        const response = await fetch(url, {method});
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || `HTTP ${response.status}`);
        }
        loadSubscriptions();
    } catch (error) {
        const errorEl = document.getElementById('sub-error');
        errorEl.textContent = `${errorPrefix}: ${error.message}`;
        errorEl.style.display = 'block';
    }
}

function deleteSubscription(id) {
    if (confirm('Delete this subscription?')) {
        subscriptionAction(`/api/subscriptions/${id}`, 'DELETE', 'Failed to delete');
    }
}

function enableSubscription(id) {
    subscriptionAction(`/api/subscriptions/${id}/enable`, 'POST', 'Failed to enable');
}

function disableSubscription(id) {
    if (confirm('Disable this subscription?')) {
        subscriptionAction(`/api/subscriptions/${id}/disable`, 'POST', 'Failed to disable');
    }
}

function renderSubscriptions(container, subs) {
    if (!subs || subs.length === 0) {
        const p = document.createElement('p');
        p.className = 'no-matches';
        p.textContent = 'No subscriptions configured yet.';
        container.replaceChildren(p);
        return;
    }

    const list = document.createElement('div');
    list.className = 'subscriptions-list';

    for (const sub of subs) {
        const card = document.createElement('div');
        card.className = 'subscription-card';

        if (sub.Name) {
            const title = document.createElement('h3');
            title.className = 'subscription-title';
            title.textContent = sub.Name;
            card.appendChild(title);
        }

        if (sub.MonitoredValue) {
            const mv = sub.MonitoredValue;
            const type = mv.type || 'unknown';
            appendField(card, 'Type:', formatType(type));

            switch (type) {
                case MVType.CERT_IDENTITY:
                    if (mv.certSubject) {
                        appendField(card, 'Subject:', mv.certSubject);
                    }
                    if (Array.isArray(mv.issuers) && mv.issuers.length > 0) {
                        appendFieldTags(card, 'Issuers:', mv.issuers);
                    }
                    break;
                case MVType.FINGERPRINT:
                    if (mv.fingerprint) {
                        appendField(card, 'Fingerprint:', mv.fingerprint);
                    }
                    break;
                case MVType.SUBJECT:
                    if (mv.subject) {
                        appendField(card, 'Subject:', mv.subject);
                    }
                    break;
                case MVType.OID_EXTENSION:
                    if (mv.oid) {
                        appendField(card, 'OID:', formatOIDDisplay(mv.oid));
                    }
                    if (Array.isArray(mv.extensionValues) && mv.extensionValues.length > 0) {
                        appendFieldTags(card, 'Values:', mv.extensionValues);
                    }
                    break;
            }
        }

        const notifyType = sub.NotificationType || 'webhook';
        if (notifyType === 'webhook' && sub.WebhookURL) {
            appendField(card, 'Webhook notification:', sub.WebhookURL, true);
        } else if (notifyType === 'email') {
            // Email subscriptions deliver to the account email, so there is no
            // per-subscription address to show — just label the channel.
            appendField(card, 'Email notification', '');
        }

        const nextRetryStr = sub.NextRetryAt
            ? new Date(sub.NextRetryAt).toLocaleString()
            : null;

        if (sub.DisabledAt) {
            const banner = document.createElement('div');
            banner.className = 'status-banner status-disabled';
            // If the sub was auto-disabled after failures, the backoff
            // window still applies after re-enable — surface the time
            // so users know when delivery will resume.
            banner.textContent = nextRetryStr
                ? `Disabled — on re-enable, next attempt no earlier than ${nextRetryStr}`
                : 'Disabled';
            card.appendChild(banner);
        } else if (sub.ConsecutiveFailures > 0) {
            const warning = document.createElement('div');
            warning.className = 'status-banner status-warning';
            const retrySuffix = nextRetryStr ? ` — next retry at ${nextRetryStr}` : '';
            warning.textContent = `Webhook failing — ${sub.ConsecutiveFailures} consecutive failure(s), backing off${retrySuffix}`;
            card.appendChild(warning);
        }

        const actions = document.createElement('div');
        actions.className = 'form-actions';

        if (sub.DisabledAt) {
            const enableBtn = document.createElement('button');
            enableBtn.className = 'btn btn-enable';
            enableBtn.textContent = 'Enable';
            enableBtn.onclick = () => enableSubscription(sub.ID);
            actions.appendChild(enableBtn);
        } else {
            const disableBtn = document.createElement('button');
            disableBtn.className = 'btn btn-disable';
            disableBtn.textContent = 'Disable';
            disableBtn.onclick = () => disableSubscription(sub.ID);
            actions.appendChild(disableBtn);
        }

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-edit';
        editBtn.textContent = 'Edit';
        editBtn.onclick = () => editSubscription(sub);
        actions.appendChild(editBtn);

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-delete';
        deleteBtn.textContent = 'Delete';
        deleteBtn.onclick = () => deleteSubscription(sub.ID);
        actions.appendChild(deleteBtn);

        card.appendChild(actions);

        list.appendChild(card);
    }

    container.replaceChildren(list);
}

function renderMatches(container, matches) {
    if (!matches || matches.length === 0) {
        const p = document.createElement('p');
        p.className = 'no-matches';
        p.textContent = 'No matches found yet. The monitor will record matches as they are discovered.';
        container.replaceChildren(p);
        return;
    }

    const list = document.createElement('div');
    list.className = 'matches-list';

    for (const match of matches) {
        const card = document.createElement('div');
        card.className = 'match-card';

        const identityType = match.matchedIdentity?.type || 'unknown';
        const typeClass = identityType
            .replace(/([A-Z])/g, '-$1')
            .toLowerCase()
            .replace(/[^a-z0-9-]/g, '');
        const typeDisplay = formatType(identityType);
        const timestamp = new Date(match.createdAt).toLocaleString();
        const shortUUID = match.uuid
            ? match.uuid
            : '-';

        // Header
        const header = document.createElement('div');
        header.className = 'match-header';

        const logIndex = document.createElement('span');
        logIndex.className = 'log-index';
        logIndex.textContent = `#${match.logIndex}`;

        const badge = document.createElement('span');
        badge.className = `badge ${typeClass}`;
        badge.textContent = typeDisplay;

        const ts = document.createElement('span');
        ts.className = 'timestamp';
        ts.textContent = timestamp;

        header.appendChild(logIndex);
        header.appendChild(badge);
        header.appendChild(ts);

        // Body
        const body = document.createElement('div');
        body.className = 'match-body';

        // Every subscription has a required name, so it is always the
        // primary label; the matched identity is shown as secondary detail.
        const identityDisplay = match.matchedIdentity
            ? formatMatchedIdentity(match.matchedIdentity)
            : '';
        appendField(
            body, 'Matched:', match.subscriptionName, false, null,
            identityDisplay);

        const matchedIdentityValue =
            getMatchedIdentityValue(match.matchedIdentity);
        if (match.certSubject &&
            match.certSubject !== matchedIdentityValue) {
            appendField(body, 'Cert Subject:', match.certSubject);
        }

        if (match.issuer) {
            appendField(body, 'Issuer:', match.issuer);
        }

        if (match.fingerprint) {
            appendField(
                body, 'Fingerprint:', match.fingerprint, true);
        }

        if (match.subject && match.subject !== match.certSubject) {
            appendField(body, 'Subject:', match.subject);
        }

        if (match.oidExtension) {
            let oidValue = formatOIDDisplay(match.oidExtension);
            if (match.extensionValue) {
                oidValue += ` = ${match.extensionValue}`;
            }
            appendField(body, 'OID:', oidValue, true);
        }

        if (match.uuid) {
            appendField(
                body, 'UUID:', shortUUID, true, match.uuid);
        }

        card.appendChild(header);
        card.appendChild(body);
        list.appendChild(card);
    }

    container.replaceChildren(list);
}

function appendFieldTags(parent, label, values) {
    const field = document.createElement('div');
    field.className = 'match-field';

    const labelSpan = document.createElement('span');
    labelSpan.className = 'field-label';
    labelSpan.textContent = label;
    field.appendChild(labelSpan);
    field.append(' ');

    const tagsSpan = document.createElement('span');
    tagsSpan.className = 'field-tags';
    for (const v of values) {
        const tag = document.createElement('span');
        tag.className = 'display-tag';
        tag.textContent = v;
        tagsSpan.appendChild(tag);
    }
    field.appendChild(tagsSpan);
    parent.appendChild(field);
}

function appendField(parent, label, value, mono, title, detail) {
    const field = document.createElement('div');
    field.className = 'match-field';

    const labelSpan = document.createElement('span');
    labelSpan.className = 'field-label';
    labelSpan.textContent = label;

    const valueSpan = document.createElement('span');
    valueSpan.className = mono ? 'field-value mono' : 'field-value';
    valueSpan.textContent = value;
    if (title) {
        valueSpan.title = title;
    }

    field.appendChild(labelSpan);
    field.append(' ');
    field.appendChild(valueSpan);

    // Optional secondary detail, shown muted after the primary value.
    if (detail) {
        const detailSpan = document.createElement('span');
        detailSpan.className = 'field-detail';
        detailSpan.textContent = `/ ${detail}`;
        field.appendChild(detailSpan);
    }

    parent.appendChild(field);
}

function formatType(type) {
    switch (type) {
        case MVType.CERT_IDENTITY:
            return 'Certificate';
        case MVType.FINGERPRINT:
            return 'Fingerprint';
        case MVType.SUBJECT:
            return 'Subject';
        case MVType.OID_EXTENSION:
            return 'OID';
        default:
            return type;
    }
}

function formatMatchedIdentity(identity) {
    if (!identity || !identity.type) {
        return 'Unknown';
    }

    switch (identity.type) {
        case MVType.CERT_IDENTITY:
            return identity.certSubject || 'Certificate';
        case MVType.FINGERPRINT:
            return identity.fingerprint || 'Fingerprint';
        case MVType.SUBJECT:
            return identity.subject || 'Subject';
        case MVType.OID_EXTENSION:
            return formatOIDDisplay(identity.oid) || 'OID Extension';
        default:
            return JSON.stringify(identity);
    }
}

function getMatchedIdentityValue(identity) {
    if (!identity) return '';

    switch (identity.type) {
        case MVType.CERT_IDENTITY:
            return identity.certSubject || '';
        case MVType.FINGERPRINT:
            return identity.fingerprint || '';
        case MVType.SUBJECT:
            return identity.subject || '';
        case MVType.OID_EXTENSION:
            return Array.isArray(identity.oid) ? identity.oid.join('.') : (identity.oid || '');
        default:
            return '';
    }
}

function updateLastUpdated() {
    const el = document.getElementById('last-updated');
    if (el) {
        el.textContent = '— updated ' + new Date().toLocaleTimeString();
    }
}
