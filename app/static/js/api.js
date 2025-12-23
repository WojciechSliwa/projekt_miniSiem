/**
 * Wrapper na Fetch API do komunikacji z backendem Flask
 */

// --- HOSTS (GOTOWE - WZÓR) ---
export async function fetchHosts() {
    const res = await fetch('/api/hosts');
    return await res.json();
}
export async function createHost(data) {
    const res = await fetch('/api/hosts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if(!res.ok) throw new Error((await res.json()).error);
    return await res.json();
}
export async function updateHost(id, data) {
    const res = await fetch(`/api/hosts/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if(!res.ok) throw new Error('Błąd edycji hosta');
    return await res.json();
}
export async function removeHost(id) {
    await fetch(`/api/hosts/${id}`, { method: 'DELETE' });
}

// --- MONITORING / LOGI (GOTOWE) ---
export async function checkHostStatus(id, osType) {
    const endpoint = (osType === 'LINUX') 
        ? `/api/hosts/${id}/ssh-info` 
        : `/api/hosts/${id}/windows-info`;
        
    const res = await fetch(endpoint);
    if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || `Błąd HTTP ${res.status}`);
    }
    return await res.json();
}

export async function triggerLogFetch(hostId) {
    const res = await fetch(`/api/hosts/${hostId}/logs`, {
        method: 'POST'
    });
    if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Błąd pobierania logów');
    }
    return await res.json();
}

// ===============================================================
// TODO: ZADANIE 4 - KOMUNIKACJA FRONTEND-BACKEND
// ===============================================================
// Brakuje funkcji do obsługi Rejestru IP oraz Alertów.
// Panel Admina i Dashboard będą rzucać błędy, dopóki tego nie uzupełnisz.
// Wzoruj się na funkcjach z sekcji HOSTS powyżej.

/*
export async function fetchIPs() {
    // 1. Wykonaj fetch GET na '/api/ips'
    // 2. Zwróć json
}

export async function createIP(data) {
    // 1. Wykonaj fetch POST na '/api/ips' z danymi (body)
    // 2. Obsłuż błędy (!res.ok)
}

export async function updateIP(id, data) {
    // PUT na /api/ips/<id>
}

export async function removeIP(id) {
    // DELETE na /api/ips/<id>
}

export async function fetchAlerts() {
    // GET na /api/alerts
}
*/