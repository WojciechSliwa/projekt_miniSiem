import { createEl, clearContainer } from './dom.js';
import { fetchHosts, checkHostStatus, triggerLogFetch } from './api.js'; 
// TODO: Po uzupełnieniu api.js odkomentuj import poniżej:
// import { fetchAlerts } from './api.js';

const hostsContainer = document.getElementById('hostsContainer');
const alertsBody = document.getElementById('alertsBody');

export async function initDashboard() {
    if (!hostsContainer) return;

    await refreshHostsList();

    if (alertsBody) {
        await refreshAlertsTable();
    }
}

async function refreshHostsList() {
    clearContainer(hostsContainer);
    try {
        const hosts = await fetchHosts();
        if (hosts.length === 0) {
            createEl('div', ['p-4', 'text-center', 'text-muted'], 'Brak hostów. Skonfiguruj system w panelu admina.', hostsContainer);
            return;
        }
        hosts.forEach(renderDashboardRow);
    } catch (err) {
        console.error(err);
        createEl('div', ['alert', 'alert-danger'], 'Błąd API Hostów', hostsContainer);
    }
}

function renderDashboardRow(host) {
    const item = createEl('div', ['list-group-item', 'py-3', 'border-bottom'], '', hostsContainer);
    const row = createEl('div', ['row', 'align-items-center', 'flex-nowrap', 'g-0'], '', item);
    
    // KOLUMNA 1: INFO
    const colInfo = createEl('div', ['col-4', 'd-flex', 'align-items-center', 'overflow-hidden'], '', row);
    const iconChar = host.os_type === 'LINUX' ? '🐧' : '🪟';
    createEl('span', ['fs-2', 'me-2'], iconChar, colInfo);
    const details = createEl('div', ['d-flex', 'flex-column', 'w-100'], '', colInfo);
    createEl('div', ['fw-bold', 'text-truncate'], host.hostname, details); 
    createEl('small', ['text-muted', 'text-truncate'], host.ip_address, details);
    
    // KOLUMNA 2: STATUS
    const colStatus = createEl('div', ['col-5', 'px-2'], '', row);
    createEl('div', ['text-muted', 'small', 'text-center', 'fst-italic'], 'Kliknij Status...', colStatus);

    // KOLUMNA 3: AKCJE
    const colActions = createEl('div', ['col-3', 'text-end'], '', row);
    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm'], '', colActions);
    
    const checkBtn = createEl('button', ['btn', 'btn-outline-primary'], 'Status', btnGroup);
    checkBtn.addEventListener('click', () => handleCheckStatusFancy(host, colStatus, checkBtn));

    const logsBtn = createEl('button', ['btn', 'btn-outline-dark'], 'Logi', btnGroup);
    logsBtn.title = "Pobierz i przeanalizuj logi (SIEM)";
    logsBtn.addEventListener('click', () => handleFetchLogs(host, logsBtn));
}

async function handleCheckStatusFancy(host, container, btn) {
    if(btn.disabled) return;
    const originalText = btn.textContent;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
    btn.disabled = true;
    clearContainer(container);
    createEl('div', ['text-muted', 'small', 'text-center'], 'Łączenie...', container);

    try {
        const data = await checkHostStatus(host.id, host.os_type);
        clearContainer(container);
        const badgesRow = createEl('div', ['d-flex', 'justify-content-between', 'align-items-center', 'w-100'], '', container);
        addBadge(badgesRow, 'RAM', `${data.free_ram_mb} MB`, 'text-success');
        addBadge(badgesRow, 'HDD', data.disk_info, 'text-warning');
        addBadge(badgesRow, 'CPU', data.cpu_load, 'text-info');
        addBadge(badgesRow, 'Uptime', data.uptime_hours, 'text-secondary');
        btn.innerHTML = '🔄'; 
    } catch (err) {
        clearContainer(container);
        createEl('div', ['text-danger', 'small', 'fw-bold', 'text-center'], 'Błąd', container);
        btn.innerHTML = 'Ponów';
    } finally {
        btn.disabled = false;
    }
}

async function handleFetchLogs(host, btn) {
    if(btn.disabled) return;
    const originalText = btn.textContent;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
    btn.disabled = true;

    try {
        const result = await triggerLogFetch(host.id);
        if (result.alerts_generated > 0) {
            btn.innerHTML = '⚠️ ' + result.alerts_generated;
            btn.classList.remove('btn-outline-dark');
            btn.classList.add('btn-danger');
        } else {
            btn.innerHTML = '✅';
            btn.classList.remove('btn-outline-dark');
            btn.classList.add('btn-success');
        }
        setTimeout(() => {
            btn.textContent = originalText;
            btn.disabled = false;
            btn.classList.remove('btn-danger', 'btn-success');
            btn.classList.add('btn-outline-dark');
        }, 3000);

        await refreshAlertsTable();

    } catch (err) {
        alert("Błąd pobierania logów: " + err.message);
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

function addBadge(parent, label, value, colorClass) {
    const box = createEl('div', ['text-center', 'border', 'rounded', 'bg-light', 'py-1'], '', parent);
    box.style.width = '24%'; 
    const lbl = createEl('div', ['text-muted', 'text-uppercase'], label, box);
    lbl.style.fontSize = '0.65rem';
    const val = createEl('div', ['fw-bold', 'text-nowrap', colorClass], value || '?', box);
    val.style.fontSize = '0.8rem';
}

/**
 * Renderowanie tabeli alertów
 */
async function refreshAlertsTable() {
    if (!alertsBody) return;
    clearContainer(alertsBody);

    try {
        // TODO: ZADANIE 4 - ODKOMENTUJ POBIERANIE ALERTÓW
        // Obecnie funkcja fetchAlerts nie istnieje w api.js.
        // Dopóki jej nie napiszesz, poniższa linia będzie rzucać błąd (Uncaught ReferenceError).
        
        // const alerts = await fetchAlerts(); 
        
        // TYMCZASOWO: Pusta lista, żeby Dashboard się ładował
        const alerts = []; 

        if (alerts.length === 0) {
            const row = createEl('tr', [], '', alertsBody);
            const cell = createEl('td', ['text-center', 'text-muted', 'py-3'], 'Brak alertów (lub brak połączenia z API).', row);
            cell.colSpan = 6;
            return;
        }

        alerts.forEach(alert => {
            const row = createEl('tr', [], '', alertsBody);
            if (alert.severity === 'CRITICAL') row.classList.add('table-danger');
            else if (alert.severity === 'WARNING') row.classList.add('table-warning');
            
            const utcDate = new Date(alert.timestamp.replace(" ", "T") + "Z");
            createEl('td', [], utcDate.toLocaleString(), row);
            createEl('td', ['fw-bold'], alert.host_name, row);
            createEl('td', [], alert.alert_type, row); 
            createEl('td', ['font-monospace'], alert.source_ip || '-', row);
            createEl('td', [], alert.message, row);
            
            const badgeCell = createEl('td', [], '', row);
            const badgeClasses = ['badge'];
            if (alert.severity === 'CRITICAL') badgeClasses.push('bg-danger');
            else badgeClasses.push('bg-warning', 'text-dark');
            createEl('span', badgeClasses, alert.severity, badgeCell);
        });
    } catch (err) {
        console.error("Błąd tabeli alertów:", err);
    }
}