(() => {
  const TOPBAR_HIDDEN_KEY = "ctgptm.layout.topbarHidden.v1";
  const runtime = window.GptAccountManagerRuntime || {};
  runtime.afterFirstPaint = runtime.afterFirstPaint || ((callback, timeout = 700) => {
    const run = () => {
      if ("requestIdleCallback" in window) {
        window.requestIdleCallback(callback, { timeout });
      } else {
        window.setTimeout(callback, Math.min(timeout, 120));
      }
    };
    if ("requestAnimationFrame" in window) {
      window.requestAnimationFrame(() => window.setTimeout(run, 0));
    } else {
      run();
    }
  });
  window.GptAccountManagerRuntime = runtime;

  const ensureTopbarToggleStyle = () => {
    if (document.querySelector("#topbar-toggle-style")) return;
    const style = document.createElement("style");
    style.id = "topbar-toggle-style";
    style.textContent = `
      body.topbar-hidden .topbar.app-header,
      body.topbar-hidden > .topbar,
      body.topbar-hidden .shell > .topbar,
      body.topbar-hidden .app > .topbar {
        display: none !important;
      }
      .topbar-toggle,
      .topbar-restore {
        min-height: 28px;
        border: 1px solid rgba(142, 165, 199, 0.32);
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.9);
        color: #49617f;
        font-size: 11px;
        font-weight: 850;
        line-height: 1;
        padding: 4px 8px;
        cursor: pointer;
      }
      .topbar-toggle:hover,
      .topbar-restore:hover {
        border-color: rgba(37, 99, 235, 0.36);
        background: rgba(37, 99, 235, 0.1);
        color: #2563eb;
      }
      .topbar-restore {
        position: fixed;
        top: 10px;
        right: 14px;
        z-index: 80;
        box-shadow: 0 4px 14px rgba(30, 41, 59, 0.12);
      }
      body:not(.topbar-hidden) .topbar-restore {
        display: none !important;
      }
    `;
    document.head.appendChild(style);
  };

  const topbarHidden = () => localStorage.getItem(TOPBAR_HIDDEN_KEY) === "1";

  const applyTopbarVisibility = () => {
    document.body?.classList.toggle("topbar-hidden", topbarHidden());
    window.requestAnimationFrame?.(() => window.dispatchEvent(new Event("resize")));
  };

  const setupTopbarToggle = () => {
    ensureTopbarToggleStyle();
    applyTopbarVisibility();

    const nav = document.querySelector(".topnav");
    if (nav && !nav.querySelector(".topbar-toggle")) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "topbar-toggle";
      button.dataset.i18nSkip = "true";
      button.textContent = "隐藏顶部";
      button.title = "隐藏顶部标题栏";
      button.addEventListener("click", () => {
        localStorage.setItem(TOPBAR_HIDDEN_KEY, "1");
        applyTopbarVisibility();
      });
      nav.appendChild(button);
    }

    if (!document.querySelector(".topbar-restore")) {
      const restore = document.createElement("button");
      restore.type = "button";
      restore.className = "topbar-restore";
      restore.dataset.i18nSkip = "true";
      restore.textContent = "显示顶部";
      restore.title = "显示顶部标题栏";
      restore.addEventListener("click", () => {
        localStorage.setItem(TOPBAR_HIDDEN_KEY, "0");
        applyTopbarVisibility();
      });
      document.body.appendChild(restore);
    }
  };

  const appendTopLinks = async () => {
    const nav = document.querySelector(".topnav");
    if (!nav || nav.dataset.runtimeLinks === "loaded") return;
    try {
      const response = await fetch("/public-config", { cache: "no-store" });
      if (!response.ok) return;
      const config = await response.json();
      const links = Array.isArray(config.top_links) ? config.top_links : [];
      const beforeNode = nav.querySelector(".github-link");
      links
        .filter((item) => item && item.url && item.label)
        .forEach((item) => {
          const link = document.createElement("a");
          link.className = "runtime-top-link";
          link.href = item.url;
          link.target = "_blank";
          link.rel = "noreferrer";
          link.textContent = item.label;
          nav.insertBefore(link, beforeNode);
        });
      nav.dataset.runtimeLinks = "loaded";
    } catch {
      // Public links are optional; keep the page usable if config cannot load.
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      setupTopbarToggle();
      appendTopLinks();
    }, { once: true });
  } else {
    setupTopbarToggle();
    appendTopLinks();
  }
})();
