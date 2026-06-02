(() => {
  const STORAGE_KEYS = {
    workspaceId: "ctgptm.workspaceId",
  };

  const authQueryToken = new URLSearchParams(window.location.search).get("token") || "";
  if (authQueryToken) {
    localStorage.setItem("ctgptm.admin.toolToken", authQueryToken);
  }
  let lastDashboardData = null;

  const els = {
    days: document.querySelector("#dashboardDays"),
    reload: document.querySelector("#reloadDashboard"),
    meta: document.querySelector("#dashboardMeta"),
    banToday: document.querySelector("#banToday"),
    banWeek: document.querySelector("#banWeek"),
    banTotal: document.querySelector("#banTotal"),
    banRecipients: document.querySelector("#banRecipients"),
    banRangeText: document.querySelector("#banRangeText"),
    banDailyBars: document.querySelector("#banDailyBars"),
    banDomainRank: document.querySelector("#banDomainRank"),
    banRecipientRank: document.querySelector("#banRecipientRank"),
    banMessageRows: document.querySelector("#banMessageRows"),
    mailboxTotal: document.querySelector("#mailboxTotal"),
    mailboxMicrosoft: document.querySelector("#mailboxMicrosoft"),
    mailboxTemp: document.querySelector("#mailboxTemp"),
    mailboxGeneric: document.querySelector("#mailboxGeneric"),
    mailboxError: document.querySelector("#mailboxError"),
    messageTotal: document.querySelector("#messageTotal"),
    refreshTotal: document.querySelector("#refreshTotal"),
    refreshToday: document.querySelector("#refreshToday"),
    refreshWeek: document.querySelector("#refreshWeek"),
    planRank: document.querySelector("#planRank"),
  };

  function getWorkspaceId() {
    const existing = localStorage.getItem(STORAGE_KEYS.workspaceId) || "";
    if (/^[A-Za-z0-9][A-Za-z0-9_.-]{5,63}$/.test(existing)) return existing;
    const next = `ws_${crypto.randomUUID().replace(/-/g, "")}`;
    localStorage.setItem(STORAGE_KEYS.workspaceId, next);
    return next;
  }

  const workspaceId = getWorkspaceId();

  function rememberedAdminToken() {
    return authQueryToken || localStorage.getItem("ctgptm.admin.toolToken") || "";
  }

  function apiHeaders() {
    const headers = {
      "Content-Type": "application/json",
      "X-Workspace-Id": workspaceId,
    };
    const token = rememberedAdminToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }

  async function readJsonResponse(response, label) {
    const text = await response.text();
    try {
      return text ? JSON.parse(text) : {};
    } catch {
      throw new Error(`${label} 返回了非 JSON：${text.replace(/\s+/g, " ").slice(0, 180)}`);
    }
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;",
      "'": "&#039;",
    }[char]));
  }

  function numberText(value) {
    const number = Number(value || 0);
    return Number.isFinite(number) ? number.toLocaleString("zh-CN") : "0";
  }

  function safeClassName(value) {
    return String(value || "other").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "other";
  }

  function compactDate(value) {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value).slice(0, 16);
    return date.toLocaleString("zh-CN", {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  }

  function setText(element, value) {
    if (element) element.textContent = String(value);
  }

  function currentLanguage() {
    return window.GptAccountManagerI18n?.getLanguage?.() === "en" ? "en" : "zh";
  }

  function text(zh, en) {
    return currentLanguage() === "en" ? en : zh;
  }

  function rankLabel(row, key) {
    const value = row?.[key] || "unknown";
    if (key === "plan_type") return String(value).toUpperCase();
    return value;
  }

  function renderRank(element, rows, key, emptyText) {
    if (!element) return;
    const list = Array.isArray(rows) ? rows.filter((row) => Number(row?.count || 0) > 0) : [];
    if (!list.length) {
      element.classList.add("empty");
      element.textContent = emptyText;
      return;
    }
    const max = Math.max(...list.map((row) => Number(row.count || 0)), 1);
    element.classList.remove("empty");
    element.innerHTML = list.slice(0, 8).map((row) => {
      const count = Number(row.count || 0);
      const width = Math.max(6, Math.round((count / max) * 100));
      return `
        <div class="dashboard-rank-row">
          <div>
            <strong>${escapeHtml(rankLabel(row, key))}</strong>
            <span>${numberText(count)}</span>
          </div>
          <i style="width:${width}%"></i>
        </div>
      `;
    }).join("");
  }

  function renderBars(rows) {
    const list = Array.isArray(rows) ? rows : [];
    if (!els.banDailyBars) return;
    if (!list.length) {
      els.banDailyBars.classList.add("empty");
      els.banDailyBars.textContent = text("暂无趋势数据", "No trend data");
      return;
    }
    const max = Math.max(...list.map((row) => Number(row.count || 0)), 1);
    els.banDailyBars.classList.remove("empty");
    els.banDailyBars.innerHTML = list.map((row) => {
      const count = Number(row.count || 0);
      const height = Math.max(count ? 10 : 2, Math.round((count / max) * 86));
      const label = String(row.date || "").slice(5);
      return `
        <div class="dashboard-bar" title="${escapeHtml(row.date)}：${numberText(count)}">
          <span>${numberText(count)}</span>
          <i style="height:${height}%"></i>
          <em>${escapeHtml(label)}</em>
        </div>
      `;
    }).join("");
  }

  function renderMessages(rows) {
    const list = Array.isArray(rows) ? rows : [];
    if (!els.banMessageRows) return;
    if (!list.length) {
      els.banMessageRows.innerHTML = `<tr><td colspan="4" class="empty-cell">${escapeHtml(text("暂无封禁邮件", "No banned mail"))}</td></tr>`;
      return;
    }
    els.banMessageRows.innerHTML = list.slice(0, 80).map((row) => `
      <tr>
        <td>${escapeHtml(compactDate(row.received_at))}</td>
        <td><strong>${escapeHtml(row.recipient || "-")}</strong><em>${escapeHtml(row.sender || "")}</em></td>
        <td><strong>${escapeHtml(row.subject || text("无主题", "No subject"))}</strong><em>${escapeHtml(row.preview || "")}</em></td>
        <td><span class="source-badge ${safeClassName(row.source)}">${escapeHtml(row.source || "unknown")}</span></td>
      </tr>
    `).join("");
  }

  function applyI18n() {
    window.GptAccountManagerI18n?.apply?.();
  }

  function render(data) {
    lastDashboardData = data;
    const banned = data.banned_mail || {};
    const mailboxes = data.mailboxes || {};
    const refresh = data.refresh || {};
    const messages = data.messages || {};
    const days = Number(data.days || els.days?.value || 30);

    setText(els.banToday, numberText(banned.today));
    setText(els.banWeek, numberText(banned.last_7_days));
    setText(els.banTotal, numberText(banned.total));
    setText(els.banRecipients, numberText(banned.unique_recipients));
    setText(els.banRangeText, text(`近 ${days} 天`, `Last ${days} days`));

    setText(els.mailboxTotal, numberText(mailboxes.total));
    setText(els.mailboxMicrosoft, numberText(mailboxes.microsoft));
    setText(els.mailboxTemp, numberText(mailboxes.temp));
    setText(els.mailboxGeneric, numberText(mailboxes.generic));
    setText(els.mailboxError, numberText(mailboxes.error));
    setText(els.messageTotal, numberText(messages.cached_total));

    setText(els.refreshTotal, numberText(refresh.saved_total));
    setText(els.refreshToday, numberText(refresh.today));
    setText(els.refreshWeek, numberText(refresh.last_7_days));

    renderBars(banned.daily);
    renderRank(els.banDomainRank, banned.domains, "domain", text("暂无封禁域名统计", "No banned domain stats"));
    renderRank(els.banRecipientRank, banned.recipients, "recipient", text("暂无收件邮箱统计", "No recipient stats"));
    renderRank(els.planRank, refresh.plans, "plan_type", text("暂无账号类型统计", "No plan stats"));
    renderMessages(banned.messages);

    const generated = compactDate(data.generated_at);
    setText(
      els.meta,
      text(
        `工作区 ${data.workspace_id || workspaceId} · ${generated} 更新 · 版本 ${data.version || "-"}`,
        `Workspace ${data.workspace_id || workspaceId} · updated ${generated} · version ${data.version || "-"}`
      )
    );
    applyI18n();
  }

  async function loadDashboard() {
    const days = Number(els.days?.value || 30);
    const tzOffset = -new Date().getTimezoneOffset();
    els.reload.disabled = true;
    setText(els.meta, text("正在读取当前工作区缓存数据。", "Reading cached data for the current workspace."));
    try {
      const params = new URLSearchParams({
        days: String(days),
        limit: "500",
        tz_offset: String(tzOffset),
      });
      const response = await fetch(`/client-api/dashboard-stats?${params.toString()}`, {
        headers: apiHeaders(),
        cache: "no-store",
      });
      const data = await readJsonResponse(response, text("仪表盘数据", "Dashboard data"));
      if (!response.ok || !data.success) throw new Error(data.error || text("仪表盘数据读取失败", "Failed to load dashboard data"));
      render(data);
    } catch (error) {
      setText(els.meta, error.message || text("仪表盘数据读取失败", "Failed to load dashboard data"));
    } finally {
      els.reload.disabled = false;
      applyI18n();
    }
  }

  els.reload.addEventListener("click", loadDashboard);
  els.days.addEventListener("change", loadDashboard);
  document.addEventListener("click", (event) => {
    if (!event.target?.closest?.(".language-switch") || !lastDashboardData) return;
    window.setTimeout(() => render(lastDashboardData), 80);
  });
  loadDashboard();
})();
