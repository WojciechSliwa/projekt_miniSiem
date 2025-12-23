import { createEl, clearContainer } from './dom.js';
// Zauważ: Usuwamy importy fetchIPs itp., bo ich nie ma w api.js (student musi je dodać po napisaniu)
import { fetchHosts, createHost, updateHost, removeHost } from './api.js'; 
// TODO: Odkomentuj poniższy import, gdy uzupełnisz api.js
// import { fetchIPs, createIP, updateIP, removeIP } from './api.js';

// --- SEKCJA HOSTÓW ---
const hostsContainer = document.getElementById('hostsListAdmin');
const hostForm = document.getElementById('hostForm');

// --- SEKCJA IP (Ukryta) ---
const ipContainer = document.getElementById('ipListAdmin');
const ipForm = document.getElementById('ipForm');
const refreshIPsBtn = document.getElementById('refreshIPsBtn');

// --- MODALE ---
let hostModal = null;
let ipModal = null;

export async function initAdmin() {
    // Inicjalizacja Bootstrap Modals
    const hostModalEl = document.getElementById('editHostModal');
    if (hostModalEl) hostModal = new bootstrap.Modal(hostModalEl);
    
    const ipModalEl = document.getElementById('editIPModal');
    if (ipModalEl) ipModal = new bootstrap.Modal(ipModalEl);

    // Event Listeners - Hosty
    if (hostForm) hostForm.addEventListener('submit', handleAddHost);
    if (document.getElementById('saveHostBtn')) {
        document.getElementById('saveHostBtn').addEventListener('click', handleSaveHost);
    }

    /* 
    // TODO: ZADANIE 3 (Frontend) - THREAT INTEL
    // Odkomentuj obsługę zdarzeń dla Rejestru IP, gdy odblokujesz HTML w config.html
    
    if (ipForm) ipForm.addEventListener('submit', handleAddIP);
    if (refreshIPsBtn) refreshIPsBtn.addEventListener('click', refreshIPs);
    if (document.getElementById('saveIPBtn')) {
        document.getElementById('saveIPBtn').addEventListener('click', handleSaveIP);
    }
    
    if (ipContainer) await refreshIPs();
    */

    // Start Hosty
    if (hostsContainer) await refreshHosts();
}

// ======================= LOGIKA HOSTÓW (GOTOWA) =======================

async function refreshHosts() {
    clearContainer(hostsContainer);
    try {
        const hosts = await fetchHosts();
        hosts.forEach(renderHostRow);
    } catch(e) { console.error(e); }
}

function renderHostRow(host) {
    const item = createEl('div', ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', hostsContainer);
    
    const info = createEl('div', [], '', item);
    const icon = host.os_type === 'LINUX' ? '🐧' : '🪟';
    createEl('span', ['me-2'], icon, info);
    createEl('span', ['fw-bold', 'me-2'], host.hostname, info);
    createEl('small', ['text-muted'], host.ip_address, info);

    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm'], '', item);
    
    const editBtn = createEl('button', ['btn', 'btn-outline-secondary'], '✏️', btnGroup);
    editBtn.addEventListener('click', () => openHostModal(host));

    const delBtn = createEl('button', ['btn', 'btn-outline-danger'], '🗑️', btnGroup);
    delBtn.addEventListener('click', async () => {
        if(confirm(`Usunąć hosta ${host.hostname}?`)) {
            await removeHost(host.id);
            await refreshHosts();
        }
    });
}

async function handleAddHost(e) {
    e.preventDefault();
    const data = {
        hostname: document.getElementById('hostName').value,
        ip_address: document.getElementById('hostIP').value,
        os_type: document.getElementById('hostOS').value
    };
    try {
        await createHost(data);
        e.target.reset();
        await refreshHosts();
    } catch(err) { alert(err.message); }
}

function openHostModal(host) {
    document.getElementById('editHostId').value = host.id;
    document.getElementById('editHostName').value = host.hostname;
    document.getElementById('editHostIP').value = host.ip_address;
    document.getElementById('editHostOS').value = host.os_type;
    hostModal.show();
}

async function handleSaveHost() {
    const id = document.getElementById('editHostId').value;
    const data = {
        hostname: document.getElementById('editHostName').value,
        ip_address: document.getElementById('editHostIP').value,
        os_type: document.getElementById('editHostOS').value
    };
    try {
        await updateHost(id, data);
        hostModal.hide();
        await refreshHosts();
    } catch(err) { alert(err.message); }
}


// ======================= LOGIKA IP REGISTRY (DO ODBLOKOWANIA) =======================

/*
// TODO: ZADANIE 3 (Frontend) - Odkomentuj całą poniższą sekcję
// Uwaga: Funkcje fetchIPs, createIP itd. muszą zostać zaimplementowane w api.js!

async function refreshIPs() {
    clearContainer(ipContainer);
    try {
        const ips = await fetchIPs(); // <-- To musi działać w api.js
        if(ips.length === 0) createEl('div', ['p-2', 'text-muted', 'small'], 'Pusto.', ipContainer);
        ips.forEach(renderIPRow);
    } catch(e) { console.error("Błąd IP:", e); }
}

function renderIPRow(ip) {
    const item = createEl('div', ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', ipContainer);

    const info = createEl('div', [], '', item);
    let color = 'bg-secondary';
    if(ip.status === 'TRUSTED') color = 'bg-success';
    if(ip.status === 'BANNED') color = 'bg-danger';
    createEl('span', ['badge', color, 'me-2'], ip.status[0], info);
    
    createEl('span', ['fw-bold', 'font-monospace', 'me-2'], ip.ip_address, info);

    let timeStr = '-';
    if (ip.last_seen && ip.last_seen !== '-') {
        const utcDate = new Date(ip.last_seen.replace(" ", "T") + "Z");
        timeStr = utcDate.toLocaleString();
    }
    createEl('small', ['text-muted'], timeStr, info);

    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm'], '', item);
    
    const editBtn = createEl('button', ['btn', 'btn-outline-secondary'], '✏️', btnGroup);
    editBtn.addEventListener('click', () => openIPModal(ip));

    const delBtn = createEl('button', ['btn', 'btn-outline-danger'], '🗑️', btnGroup);
    delBtn.addEventListener('click', async () => {
        if(confirm(`Usunąć adres IP ${ip.ip_address} z rejestru?`)) {
            try {
                await removeIP(ip.id);
                await refreshIPs();
            } catch (err) { alert("Błąd usuwania: " + err.message); }
        }
    });
}

async function handleAddIP(e) {
    e.preventDefault();
    const data = {
        ip_address: document.getElementById('regIP').value,
        status: document.getElementById('regStatus').value
    };
    try {
        await createIP(data);
        e.target.reset();
        await refreshIPs();
    } catch(err) { alert(err.message); }
}

function openIPModal(ip) {
    document.getElementById('editIPId').value = ip.id;
    document.getElementById('editIPVal').value = ip.ip_address;
    document.getElementById('editIPStatus').value = ip.status;
    ipModal.show();
}

async function handleSaveIP() {
    const id = document.getElementById('editIPId').value;
    const data = {
        ip_address: document.getElementById('editIPVal').value,
        status: document.getElementById('editIPStatus').value
    };
    try {
        await updateIP(id, data);
        ipModal.hide();
        await refreshIPs();
    } catch(err) { alert(err.message); }
}
*/