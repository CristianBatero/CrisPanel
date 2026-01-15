const API_BASE = "";
let authToken = localStorage.getItem("crispanel_token");
let charts = {};

// --- Utilities ---
const $ = (id) => document.getElementById(id);

function show(id, visible = true) {
  const el = $(id);
  if (!el) return;
  if (visible) el.classList.remove("hidden");
  else el.classList.add("hidden");
}

function debounce(fn, delay) {
  let timeout;
  return function (...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn.apply(this, args), delay);
  };
}

async function apiRequest(path, options = {}) {
  const headers = options.headers || {};
  headers["Content-Type"] = "application/json";
  if (authToken) {
    headers["Authorization"] = "Bearer " + authToken;
  }
  
  try {
    const response = await fetch(API_BASE + path, { ...options, headers });
    
    if (response.status === 401) {
      logout();
      throw new Error("Sesión expirada");
    }

    if (!response.ok) {
      const text = await response.text();
      try {
        const data = JSON.parse(text);
        throw new Error(data.error || text || "Error en la petición");
      } catch {
        throw new Error(text || "Error en la petición");
      }
    }
    
    if (response.status === 204) return null;
    return await response.json();
  } catch (err) {
    console.error("API Error:", err);
    throw err;
  }
}

// --- Auth & Navigation ---
function initAuth() {
  $("login-btn").addEventListener("click", handleLogin);
  $("logout-btn").addEventListener("click", logout);
  
  // Auto login check
  if (authToken) {
    show("login-view", false);
    show("panel-view", true);
    loadDashboard();
  } else {
    show("login-view", true);
    show("panel-view", false);
  }
}

async function handleLogin() {
  const username = $("username").value.trim();
  const password = $("password").value.trim();
  const errorEl = $("login-error");
  
  if (!username || !password) {
    errorEl.textContent = "Ingrese usuario y contraseña";
    return;
  }
  
  try {
    const data = await apiRequest("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });
    
    authToken = data.token;
    localStorage.setItem("crispanel_token", authToken);
    errorEl.textContent = "";
    
    show("login-view", false);
    show("panel-view", true);
    loadDashboard();
  } catch (err) {
    errorEl.textContent = err.message;
  }
}

function logout() {
  authToken = null;
  localStorage.removeItem("crispanel_token");
  show("login-view", true);
  show("panel-view", false);
  // Reset views
  document.querySelectorAll(".view-section").forEach(el => el.classList.add("hidden"));
  $("view-dashboard").classList.remove("hidden");
  document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
  document.querySelector('[data-target="dashboard"]').classList.add("active");
}

function initNavigation() {
  document.querySelectorAll(".nav-item").forEach(btn => {
    btn.addEventListener("click", () => {
      // Sidebar active state
      document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      
      // View switching
      const target = btn.dataset.target;
      document.querySelectorAll(".view-section").forEach(v => v.classList.add("hidden"));
      $(`view-${target}`).classList.remove("hidden");
      
      // Update Title
      $("page-title").textContent = btn.innerText.trim();
      
      // Load data based on view
      if (target === "dashboard") loadDashboard();
      if (target === "servers") loadServers();
      if (target === "users") loadUsers();
      if (target === "config") loadConfig();
      if (target === "ads") loadAds();
      if (target === "security") loadSecurity();
      if (target === "plans") loadPlans();
      // Notifications (Firebase) - No special data load needed initially besides auth check (handled in config)
    });
  });

  // Theme Toggle
  const themeToggle = $("theme-toggle");
  const body = document.body;
  
  // Load saved theme
  if (localStorage.getItem("theme") === "dark") {
    body.classList.add("dark-theme");
    themeToggle.innerHTML = '<i class="fa-solid fa-sun"></i>';
  }

  themeToggle.addEventListener("click", () => {
    body.classList.toggle("dark-theme");
    const isDark = body.classList.contains("dark-theme");
    localStorage.setItem("theme", isDark ? "dark" : "light");
    themeToggle.innerHTML = isDark ? '<i class="fa-solid fa-sun"></i>' : '<i class="fa-solid fa-moon"></i>';
    updateChartsTheme(isDark);
  });
}

// --- Dashboard ---
async function loadDashboard() {
  try {
    // Parallel fetch if possible, for now just sequential to ensure data
    const servers = await apiRequest("/api/servers");
    const users = await apiRequest("/api/users");
    const meta = await apiRequest("/api/meta");
    
    $("stat-total-servers").textContent = servers.length;
    $("stat-active-users").textContent = users.length; // Assuming all users returned are 'active' or valid
    $("stat-version").textContent = meta.version || "v1.0";
    
    initCharts(servers);
  } catch (err) {
    console.error("Dashboard error:", err);
  }
}

function initCharts(servers) {
  const ctxTraffic = $("trafficChart").getContext("2d");
  const ctxProtocols = $("protocolsChart").getContext("2d");
  const isDark = document.body.classList.contains("dark-theme");
  const textColor = isDark ? '#94A3B8' : '#64748B';

  // Dispose existing
  if (charts.traffic) charts.traffic.destroy();
  if (charts.protocols) charts.protocols.destroy();

  // Traffic Chart (Mock data)
  charts.traffic = new Chart(ctxTraffic, {
    type: 'line',
    data: {
      labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
      datasets: [{
        label: 'Tráfico (GB)',
        data: [12, 19, 35, 25, 42, 30],
        borderColor: '#4F46E5',
        tension: 0.4,
        fill: true,
        backgroundColor: 'rgba(79, 70, 229, 0.1)'
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: textColor } } },
      scales: {
        y: { ticks: { color: textColor }, grid: { color: isDark ? '#334155' : '#E5E7EB' } },
        x: { ticks: { color: textColor }, grid: { display: false } }
      }
    }
  });

  // Protocols Chart (Real data aggregation)
  const protocols = {
    'SSH/SSL': 0, 'SSL/PAYLOAD': 0, 'DIRECT': 0, 
    'SSH/PROXY': 0, 'SLOWDNS': 0, 'UDP': 0, 'V2RAY': 0
  };

  servers.forEach(s => {
    if (s.isSSL) protocols['SSH/SSL']++;
    else if (s.isPayloadSSL) protocols['SSL/PAYLOAD']++;
    else if (s.isDirect) protocols['DIRECT']++;
    else if (s.isInject) protocols['SSH/PROXY']++;
    else if (s.isSlow) protocols['SLOWDNS']++;
    else if (s.isUdp) protocols['UDP']++;
    else if (s.isTcp) protocols['V2RAY']++;
  });

  charts.protocols = new Chart(ctxProtocols, {
    type: 'doughnut',
    data: {
      labels: Object.keys(protocols),
      datasets: [{
        data: Object.values(protocols),
        backgroundColor: [
          '#4F46E5', '#10B981', '#F59E0B', '#EF4444', 
          '#3B82F6', '#8B5CF6', '#EC4899'
        ],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { position: 'right', labels: { color: textColor } } }
    }
  });
}

function updateChartsTheme(isDark) {
  if (charts.traffic || charts.protocols) {
    // Simple re-render for color update (could be optimized)
    loadDashboard(); 
  }
}

// --- Server Management ---
async function loadServers() {
  try {
    const servers = await apiRequest("/api/servers");
    window.allServers = servers;
    renderServerList(servers);
    
    const searchInput = $("server-search");
    if (searchInput) {
      const handler = debounce((e) => {
        const term = e.target.value.toLowerCase();
        const source = window.allServers || [];
        const filtered = source.filter(s => 
          (s.name && s.name.toLowerCase().includes(term)) || 
          (s.host && s.host.toLowerCase().includes(term)) ||
          (s.info && s.info.toLowerCase().includes(term))
        );
        renderServerList(filtered);
      }, 200);
      searchInput.onkeyup = handler;
    }
  } catch (err) {
    console.error("Load servers error:", err);
  }
}

function renderServerList(servers) {
  const listContainer = $("servers-list");
  listContainer.innerHTML = "";
  const fragment = document.createDocumentFragment();

  servers.forEach((s, index) => {
    let method = "Desconocido";
    if (s.isSSL) method = "SSH/SSL";
    else if (s.isPayloadSSL) method = "SSL/PAYLOAD";
    else if (s.isDirect) method = "DIRECT";
    else if (s.isInject) method = "SSH/PROXY";
    else if (s.isSlow) method = "SLOW DNS";
    else if (s.isUdp) method = "UDP";
    else if (s.isTcp) method = "v2ray";

    const item = document.createElement("div");
    item.className = "server-item card-item";
    item.dataset.id = index; // Using index for reordering logic
    
    item.innerHTML = `
      <div class="drag-handle"><i class="fa-solid fa-grip-vertical"></i></div>
      <div class="server-info-compact">
        <div class="server-main">
          <span class="flag">${s.flag || '🌐'}</span>
          <div class="name-group">
            <span class="name">${s.name || 'Sin Nombre'}</span>
            ${s.groupName ? `<span class="group-badge">${s.groupName}</span>` : ''}
          </div>
          <span class="tag ${s.isPremium ? 'premium' : 'free'}">${s.isPremium ? 'PREMIUM' : 'FREE'}</span>
        </div>
        <div class="server-meta">
          <span><i class="fa-solid fa-network-wired"></i> ${method}</span>
          <span><i class="fa-solid fa-server"></i> ${s.host || 'No Host'}</span>
        </div>
      </div>
      <div class="server-actions">
        <button class="icon-btn edit-server-btn" data-id="${s.id}"><i class="fa-solid fa-pen"></i></button>
      </div>
    `;
    fragment.appendChild(item);
  });

  listContainer.appendChild(fragment);

  // Re-attach event listeners
  document.querySelectorAll(".edit-server-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      openServerEditor(btn.dataset.id, servers);
    });
  });

  // Initialize Sortable
  if (!listContainer.sortableInstance) {
    listContainer.sortableInstance = new Sortable(listContainer, {
      handle: '.drag-handle',
      animation: 150,
      onEnd: async function (evt) {
        await handleServerReorder();
      },
    });
  }
}

async function handleServerReorder() {
  const listContainer = $("servers-list");
  const items = Array.from(listContainer.children);
  // Get original indices from dataset.id
  const newOrder = items.map(item => item.dataset.id);
  
  try {
    const updatedServers = await apiRequest("/api/servers/reorder", {
      method: "POST",
      body: JSON.stringify({ newOrder })
    });
    // Re-render to sync state
    renderServerList(updatedServers);
  } catch (err) {
    alert("Error al reordenar: " + err.message);
    loadServers(); // Revert on error
  }
}

// Server Editor Logic
const editor = $("server-editor");
const btnAddServer = $("btn-add-server");
const btnCloseEditor = $("close-editor");
const btnSaveServer = $("save-server-btn");
const btnDeleteServer = $("delete-server-btn");

btnAddServer.addEventListener("click", () => openServerEditor());
btnCloseEditor.addEventListener("click", closeServerEditor);
btnSaveServer.addEventListener("click", saveServer);
btnDeleteServer.addEventListener("click", deleteServer);

function closeServerEditor() {
  editor.classList.add("hidden");
  $("servers-list").parentElement.classList.remove("shrink"); // Optional layout adjustment
}

function openServerEditor(id = null, servers = []) {
  editor.classList.remove("hidden");
  $("form-error").textContent = "";
  
  // Clear form first
  clearServerForm();

  if (id) {
    const s = servers.find(x => x.id === id);
    if (!s) return;
    
    $("editor-title").textContent = "Editar Servidor";
    $("delete-server-btn").classList.remove("hidden");
    
    // Populate fields
    $("server-id").value = s.id;
    $("server-name").value = s.name || "";
    $("server-group").value = s.groupName || "";
    $("server-flag").value = s.flag || "";
    $("server-host").value = s.host || "";
    $("server-port").value = s.port || "";
    $("server-sslport").value = s.sslPort || "";
    $("server-proxy-host").value = s.proxyHost || "";
    $("server-proxy-port").value = s.proxyPort || "";
    $("server-username").value = s.username || "";
    $("server-password").value = s.password || "";
    $("server-payload").value = s.payload || "";
    $("server-sni").value = s.sni || "";
    $("server-slowkey").value = s.slowKey || "";
    $("server-slowdns").value = s.slowDns || "";
    $("server-slownameserver").value = s.slowNameserver || "";
    $("server-udpbuffer").value = s.udpBuffer || "";
    $("server-udpup").value = s.udpUp || "";
    $("server-udpdown").value = s.udpDown || "";
    $("server-v2ray").value = s.v2rayConfig || "";
    $("server-info").value = s.info || "";
    $("server-apitoken").value = s.apiToken || "";
    $("server-apicheckuser").value = s.apiCheckUser || "";
    $("server-premium").checked = !!s.isPremium;
    $("server-solodatos").checked = !!s.soloDatos;

    // Determine method
    let method = "sshssl";
    if (s.isSSL) method = "sshssl";
    else if (s.isPayloadSSL) method = "sslpay";
    else if (s.isDirect) method = "direct";
    else if (s.isInject) method = "sshproxy";
    else if (s.isSlow) method = "slowdns";
    else if (s.isUdp) method = "udp";
    else if (s.isTcp) method = "v2ray";
    
    $("server-method").value = method;
    applyMethodUi(method);

  } else {
    $("editor-title").textContent = "Nuevo Servidor";
    $("delete-server-btn").classList.add("hidden");
    applyMethodUi("sshssl");
  }
}

function clearServerForm() {
  const inputs = editor.querySelectorAll("input, textarea");
  inputs.forEach(i => {
    if (i.type === "checkbox") i.checked = false;
    else i.value = "";
  });
  $("server-method").value = "sshssl";
}

// Protocol UI Logic
$("server-method").addEventListener("change", (e) => applyMethodUi(e.target.value));
$("server-premium").addEventListener("change", () => applyMethodUi($("server-method").value));

function applyMethodUi(method) {
  const showField = (id, visible) => {
    const el = $(id);
    if (el) el.style.display = visible ? "block" : "none";
  };
  const setDisplay = (id, display) => {
      const el = $(id);
      if(el) el.style.display = display;
  }

  // Common groups
  const groups = [
    "group-host", "group-port", "group-ssl", "group-proxy", 
    "group-userpass", "group-payload", "group-sni", 
    "group-slowdns", "group-udp", "group-v2ray"
  ];
  
  // Hide all first
  groups.forEach(g => setDisplay(g, "none"));

  // Premium check
  const isPremium = $("server-premium").checked;
  if (!isPremium) setDisplay("group-userpass", "flex"); // Using flex for row

  // Logic map
  switch(method) {
    case "sshssl":
      setDisplay("group-host", "flex");
      showField("group-ssl", true);
      showField("group-sni", true);
      break;
    case "sslpay":
      setDisplay("group-host", "flex");
      showField("group-ssl", true);
      showField("group-payload", true);
      showField("group-sni", true);
      break;
    case "direct":
      setDisplay("group-host", "flex");
      showField("group-port", true);
      showField("group-payload", true);
      break;
    case "sshproxy":
      setDisplay("group-host", "flex");
      showField("group-port", true);
      setDisplay("group-proxy", "flex");
      showField("group-payload", true);
      break;
    case "slowdns":
      setDisplay("group-host", "flex");
      showField("group-port", true);
      showField("group-slowdns", true);
      break;
    case "udp":
      setDisplay("group-host", "flex");
      showField("group-udp", true);
      break;
    case "v2ray":
      showField("group-v2ray", true);
      break;
  }
}

async function saveServer() {
  const id = $("server-id").value;
  const payload = {
    name: $("server-name").value.trim(),
    groupName: $("server-group").value.trim(),
    flag: $("server-flag").value.trim(),
    host: $("server-host").value.trim(),
    port: $("server-port").value.trim(),
    sslPort: $("server-sslport").value.trim(),
    proxyHost: $("server-proxy-host").value.trim(),
    proxyPort: $("server-proxy-port").value.trim(),
    username: $("server-username").value.trim(),
    password: $("server-password").value.trim(),
    payload: $("server-payload").value.trim(),
    sni: $("server-sni").value.trim(),
    slowKey: $("server-slowkey").value.trim(),
    slowDns: $("server-slowdns").value.trim(),
    slowNameserver: $("server-slownameserver").value.trim(),
    udpBuffer: $("server-udpbuffer").value.trim(),
    udpUp: $("server-udpup").value.trim(),
    udpDown: $("server-udpdown").value.trim(),
    v2rayConfig: $("server-v2ray").value.trim(),
    info: $("server-info").value.trim(),
    apiToken: $("server-apitoken").value.trim(),
    apiCheckUser: $("server-apicheckuser").value.trim(),
    isPremium: $("server-premium").checked,
    soloDatos: $("server-solodatos").checked,
    // Reset flags
    isSSL: false, isPayloadSSL: false, isDirect: false, 
    isInject: false, isSlow: false, isUdp: false, isTcp: false
  };

  const method = $("server-method").value;
  if (method === "sshssl") payload.isSSL = true;
  else if (method === "sslpay") payload.isPayloadSSL = true;
  else if (method === "direct") payload.isDirect = true;
  else if (method === "sshproxy") payload.isInject = true;
  else if (method === "slowdns") payload.isSlow = true;
  else if (method === "udp") payload.isUdp = true;
  else if (method === "v2ray") payload.isTcp = true;

  try {
    if (id) {
      await apiRequest("/api/servers/" + id, { method: "PUT", body: JSON.stringify(payload) });
    } else {
      await apiRequest("/api/servers", { method: "POST", body: JSON.stringify(payload) });
    }
    closeServerEditor();
    loadServers();
  } catch (err) {
    $("form-error").textContent = err.message;
  }
}

async function deleteServer() {
  const id = $("server-id").value;
  if (!id || !confirm("¿Eliminar servidor?")) return;
  try {
    await apiRequest("/api/servers/" + id, { method: "DELETE" });
    closeServerEditor();
    loadServers();
  } catch (err) {
    $("form-error").textContent = err.message;
  }
}

// --- User Management ---
async function loadUsers() {
  try {
    const [localUsers, firebaseUsers] = await Promise.all([
      apiRequest("/api/users"),
      apiRequest("/api/firebase/users").catch(() => [])
    ]);
    const users = [
      ...localUsers.map(u => ({ ...u, source: u.source || "local" })),
      ...firebaseUsers
    ];
    const tbody = $("users-table-body");
    tbody.innerHTML = "";
    
    users.forEach(u => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>
          <div class="user-cell">
            <div class="avatar-sm">${(u.username || (u.email || "?")).charAt(0).toUpperCase()}</div>
            <span>${u.username || u.email || "Sin nombre"}</span>
          </div>
        </td>
        <td>${u.source === 'firebase' ? 'Firebase (Google)' : 'Panel'}</td>
        <td><span class="badge ${u.source === 'firebase' ? 'admin' : (u.role === 'admin' ? 'admin' : 'user')}">${u.source === 'firebase' ? 'Firebase' : (u.role || 'user')}</span></td>
        <td><span class="status-dot ${u.status === 'active' ? 'active' : 'inactive'}"></span> ${u.status || 'active'}</td>
        <td>${u.lastLogin || 'Nunca'}</td>
        <td>
          ${u.source === 'firebase' ? '' : `
            <button class="icon-btn edit-user-btn" data-id="${u.id}"><i class="fa-solid fa-pen"></i></button>
            <button class="icon-btn delete-user-btn" data-id="${u.id}"><i class="fa-solid fa-trash"></i></button>
          `}
        </td>
      `;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".edit-user-btn").forEach(btn => 
      btn.addEventListener("click", () => openUserModal(btn.dataset.id, users))
    );
    tbody.querySelectorAll(".delete-user-btn").forEach(btn => 
      btn.addEventListener("click", () => deleteUser(btn.dataset.id))
    );

  } catch (err) {
    console.error("Load users error:", err);
  }
}

const userModal = $("user-modal");
$("btn-add-user").addEventListener("click", () => openUserModal());
userModal.querySelector(".close-modal").addEventListener("click", () => userModal.classList.add("hidden"));
$("save-user-btn").addEventListener("click", saveUser);

function openUserModal(id = null, users = []) {
  userModal.classList.remove("hidden");
  $("user-error").textContent = "";
  $("user-id").value = "";
  $("user-username").value = "";
  $("user-password").value = "";
  $("user-role").value = "user";
  $("user-status").value = "active";

  if (id) {
    const u = users.find(x => x.id === id);
    if (!u) return;
    if (u.source === "firebase") return;
    $("user-id").value = u.id;
    $("user-username").value = u.username;
    // Password usually blank on edit unless changing
    $("user-role").value = u.role || "user";
    $("user-status").value = u.status || "active";
  }
}

async function saveUser() {
  const id = $("user-id").value;
  const username = $("user-username").value.trim();
  const password = $("user-password").value.trim();
  const role = $("user-role").value;
  const status = $("user-status").value;

  if (!username) {
    $("user-error").textContent = "Nombre de usuario requerido";
    return;
  }
  
  const payload = { username, role, status };
  if (password) payload.password = password; // Only send if changed

  try {
    if (id) {
      await apiRequest("/api/users/" + id, { method: "PUT", body: JSON.stringify(payload) });
    } else {
      if (!password) {
        $("user-error").textContent = "Contraseña requerida para nuevo usuario";
        return;
      }
      payload.password = password;
      await apiRequest("/api/users", { method: "POST", body: JSON.stringify(payload) });
    }
    userModal.classList.add("hidden");
    loadUsers();
  } catch (err) {
    $("user-error").textContent = err.message;
  }
}

async function deleteUser(id) {
  if (!confirm("¿Eliminar usuario?")) return;
  try {
    await apiRequest("/api/users/" + id, { method: "DELETE" });
    loadUsers();
  } catch (err) {
    alert("Error: " + err.message);
  }
}

// --- Plans Management ---
async function loadPlans() {
  try {
    const plans = await apiRequest("/api/plans");
    const tbody = $("plans-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    plans.forEach(p => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${p.name}</td>
        <td>${p.blockAds ? "Sí" : "No"}</td>
        <td>${p.premiumCatalog ? "Sí" : "No"}</td>
        <td>${p.price.toFixed(2)} ${p.currency}</td>
        <td>${p.durationDays} días</td>
        <td>${p.isActive ? "Sí" : "No"}</td>
        <td>
          <button class="icon-btn edit-plan-btn" data-id="${p.id}"><i class="fa-solid fa-pen"></i></button>
          <button class="icon-btn delete-plan-btn" data-id="${p.id}"><i class="fa-solid fa-trash"></i></button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".edit-plan-btn").forEach(btn => 
      btn.addEventListener("click", () => openPlanForm(btn.dataset.id, plans))
    );
    tbody.querySelectorAll(".delete-plan-btn").forEach(btn => 
      btn.addEventListener("click", () => deletePlan(btn.dataset.id))
    );
  } catch (err) {
    console.error("Load plans error:", err);
  }
}

const planModal = $("plan-modal");

function openPlanForm(id = null, plans = []) {
  if (planModal) {
    planModal.classList.remove("hidden");
  }
  $("plan-error").textContent = "";
  $("plan-name").value = "";
  $("plan-price").value = "";
  $("plan-currency").value = "USD";
  $("plan-duration").value = "30";
  $("plan-description").value = "";
  $("plan-features").value = "";
  $("plan-payments").value = "";
  $("plan-active").value = "true";
   const blockAdsEl = $("plan-block-ads");
   const premiumCatalogEl = $("plan-premium-catalog");
   if (blockAdsEl) blockAdsEl.checked = false;
   if (premiumCatalogEl) premiumCatalogEl.checked = false;
  $("btn-save-plan").dataset.id = "";

  if (id) {
    const p = plans.find(x => x.id === id);
    if (!p) return;
    $("btn-save-plan").dataset.id = p.id;
    $("plan-name").value = p.name || "";
    $("plan-price").value = p.price != null ? p.price : "";
    $("plan-currency").value = p.currency || "USD";
    $("plan-duration").value = p.durationDays != null ? p.durationDays : 30;
    $("plan-description").value = p.description || "";
    $("plan-features").value = (p.features || []).join("\n");
    $("plan-payments").value = (p.paymentMethods || []).join("\n");
    $("plan-active").value = p.isActive ? "true" : "false";
    if (blockAdsEl) blockAdsEl.checked = !!p.blockAds;
    if (premiumCatalogEl) premiumCatalogEl.checked = !!p.premiumCatalog;
  }
}

if (planModal) {
  planModal.querySelectorAll(".plan-close").forEach(btn =>
    btn.addEventListener("click", () => {
      planModal.classList.add("hidden");
    })
  );
}

$("btn-add-plan").addEventListener("click", () => openPlanForm());

$("btn-save-plan").addEventListener("click", async () => {
  const id = $("btn-save-plan").dataset.id;
  const name = $("plan-name").value.trim();
  const price = parseFloat($("plan-price").value || "0");
  const currency = $("plan-currency").value.trim() || "USD";
  const durationDays = parseInt($("plan-duration").value || "30", 10);
  const description = $("plan-description").value;
  const featuresText = $("plan-features").value;
  const paymentsText = $("plan-payments").value;
  const isActive = $("plan-active").value === "true";
  const blockAdsEl = $("plan-block-ads");
  const premiumCatalogEl = $("plan-premium-catalog");
  const blockAds = blockAdsEl ? blockAdsEl.checked : false;
  const premiumCatalog = premiumCatalogEl ? premiumCatalogEl.checked : false;

  if (!name) {
    $("plan-error").textContent = "Nombre del plan requerido";
    return;
  }

  const features = featuresText.split("\n").map(f => f.trim()).filter(Boolean);
  const paymentMethods = paymentsText.split("\n").map(p => p.trim()).filter(Boolean);

  const payload = { name, price, currency, durationDays, description, features, isActive, paymentMethods, blockAds, premiumCatalog };

  try {
    if (id) {
      await apiRequest("/api/plans/" + id, { method: "PUT", body: JSON.stringify(payload) });
    } else {
      await apiRequest("/api/plans", { method: "POST", body: JSON.stringify(payload) });
    }
    if (planModal) {
      planModal.classList.add("hidden");
    }
    loadPlans();
  } catch (err) {
    $("plan-error").textContent = err.message;
  }
});

async function deletePlan(id) {
  if (!confirm("¿Eliminar plan?")) return;
  try {
    await apiRequest("/api/plans/" + id, { method: "DELETE" });
    loadPlans();
  } catch (err) {
    alert("Error: " + err.message);
  }
}

// --- Configuration Management ---
async function loadConfig() {
  try {
    const meta = await apiRequest("/api/meta");
    $("config-version").value = meta.version || "";
    $("config-notes").value = meta.releaseNotes || "";
    $("config-password").value = meta.password || "";
    $("config-apikey").value = meta.apiKey || "";

    // Check Firebase Status (by trying to fetch remote config or a status endpoint)
    // We reuse the remote-config endpoint to check connectivity
    try {
      await apiRequest("/api/firebase/remote-config");
      // If success
      const statusEl = $("config-firebase-status");
      if(statusEl) {
        statusEl.className = "alert-banner success";
        statusEl.innerHTML = '<i class="fa-solid fa-check-circle"></i> Conectado';
      }
    } catch (err) {
      // If failed
      const statusEl = $("config-firebase-status");
      if(statusEl) {
        statusEl.className = "alert-banner warning";
        statusEl.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> No conectado';
      }
    }

  } catch (err) {
    console.error("Load config error:", err);
  }
}

$("save-meta-btn").addEventListener("click", async () => {
  const version = $("config-version").value.trim();
  const releaseNotes = $("config-notes").value;
  const password = $("config-password").value.trim();
  const apiKey = $("config-apikey").value.trim();
  
  try {
    await apiRequest("/api/meta", {
      method: "PUT",
      body: JSON.stringify({ version, releaseNotes, password, apiKey })
    });
    alert("Configuración guardada");
  } catch (err) {
    $("meta-error").textContent = err.message;
  }
});

$("btn-gen-key").addEventListener("click", () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = 'crisdev_';
  for (let i = 0; i < 24; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  $("config-apikey").value = key;
});

$("btn-copy-key").addEventListener("click", () => {
  const key = $("config-apikey").value;
  if(!key) return;
  navigator.clipboard.writeText(key).then(() => {
    const btn = $("btn-copy-key");
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-check"></i>';
    setTimeout(() => btn.innerHTML = original, 1500);
  });
});

// --- Ads Management ---
async function loadAds() {
  try {
    const meta = await apiRequest("/api/meta");
    const ads = meta.ads || {};
    
    $("ads-banner").value = (ads.BannerIds || []).join("\n");
    $("ads-interstitial").value = (ads.InterstitialIds || []).join("\n");
    $("ads-rewarded").value = (ads.RewardedIds || []).join("\n");
    $("ads-appopen").value = (ads.AppOpenIds || []).join("\n");
  } catch (err) {
    console.error("Load ads error:", err);
    $("ads-error").textContent = "Error cargando anuncios: " + err.message;
  }
}

$("save-ads-btn").addEventListener("click", async () => {
  const bannerIds = $("ads-banner").value.split("\n").map(s => s.trim()).filter(Boolean);
  const interstitialIds = $("ads-interstitial").value.split("\n").map(s => s.trim()).filter(Boolean);
  const rewardedIds = $("ads-rewarded").value.split("\n").map(s => s.trim()).filter(Boolean);
  const appOpenIds = $("ads-appopen").value.split("\n").map(s => s.trim()).filter(Boolean);
  
  try {
    await apiRequest("/api/meta", {
      method: "PUT",
      body: JSON.stringify({
        ads: {
          BannerIds: bannerIds,
          InterstitialIds: interstitialIds,
          RewardedIds: rewardedIds,
          AppOpenIds: appOpenIds
        }
      })
    });
    alert("Anuncios guardados correctamente");
  } catch (err) {
    $("ads-error").textContent = err.message;
  }
});

// --- Remote Config (Security) ---
async function loadSecurity() {
    try {
        const remoteConfig = await apiRequest("/api/firebase/remote-config");
        loadRemoteConfigUI(remoteConfig);
    } catch(err) {
        // Handle error, maybe show not configured message in security view if needed
        // For now, the fields will just be empty or defaults
    }
}

// Tab Logic
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    // Remove active
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    
    // Add active
    btn.classList.add("active");
    const target = btn.dataset.tab;
    $(`tab-${target}`).classList.add("active");
  });
});

// Upload Service Account (Config View)
$("btn-upload-firebase").addEventListener("click", async () => {
  const fileInput = $("firebase-file");
  if (!fileInput.files[0]) {
    alert("Selecciona un archivo JSON");
    return;
  }
  
  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  
  try {
    const res = await fetch(API_BASE + "/api/firebase/setup", {
      method: "POST",
      headers: { "Authorization": "Bearer " + authToken },
      body: formData
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Error subiendo archivo");
    
    alert(data.message);
    loadConfig(); // Reload to verify status
  } catch (err) {
    alert("Error: " + err.message);
  }
});

// Remote Config
function loadRemoteConfigUI(params) {
  if (!params) return;
  
  // Helper to safely get value
  const getVal = (key) => params[key] ? params[key].defaultValue : "";
  
  $("rc-app-version").value = getVal("app_version") || "";
  $("rc-force-update").value = getVal("force_update") || "false";
  $("rc-update-url").value = getVal("update_url") || "";
  $("rc-block-ads").value = getVal("block_ads") || "false";
  $("rc-check-signature").value = getVal("check_signature") || "true";
  $("rc-allowed-packages").value = getVal("allowed_packages") || "";
  $("rc-blacklisted-apps").value = getVal("blacklisted_apps") || "";
}

$("btn-save-remote").addEventListener("click", async () => {
  const parameters = {
    app_version: $("rc-app-version").value,
    force_update: $("rc-force-update").value,
    update_url: $("rc-update-url").value,
    block_ads: $("rc-block-ads").value,
    check_signature: $("rc-check-signature").value,
    allowed_packages: $("rc-allowed-packages").value,
    blacklisted_apps: $("rc-blacklisted-apps").value
  };
  
  try {
    await apiRequest("/api/firebase/remote-config", {
      method: "POST",
      body: JSON.stringify({ parameters })
    });
    alert("Remote Config actualizado y publicado");
  } catch (err) {
    alert("Error: " + err.message);
  }
});

// Notifications
$("btn-send-notify").addEventListener("click", async () => {
  const title = $("notify-title").value;
  const body = $("notify-body").value;
  const imageUrl = $("notify-image").value;
  const largeIcon = $("notify-large-icon").value;
  const type = $("notify-target-type").value;
  const value = $("notify-target-value").value;
  
  const payload = { title, body, imageUrl, largeIcon };
  if (type === "topic") payload.topic = value;
  else payload.token = value;
  
  try {
    await apiRequest("/api/firebase/notify", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    alert("Notificación enviada");
  } catch (err) {
    alert("Error enviando notificación: " + err.message);
  }
});

// Initialize
window.addEventListener("DOMContentLoaded", () => {
  initAuth();
  initNavigation();
});
