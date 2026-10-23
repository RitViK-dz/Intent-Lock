/**
 * IntentLock - Store & Orders Ledger Controller (Vanilla JavaScript)
 *
 * CRITICAL SECURITY & DATA RULES:
 * 1. Safe DOM updates: ALWAYS use `textContent`, NEVER `innerHTML`.
 * 2. Currency: Money is strictly formatted from integer cents in dollars (price_cents / 100 with 2 decimals).
 * 3. Schema Accuracy: Catalog items from GET /store/catalog use fields: `name`, `price_cents`, `payee_id`, `id`.
 */

document.addEventListener("DOMContentLoaded", async () => {
    if (typeof initSystemStatus === "function") {
        initSystemStatus();
    }
    await loadCatalog();
    await loadOrders();

    const refreshBtn = document.getElementById("refresh-orders-btn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", async () => {
            await loadOrders();
            if (typeof showToast === "function") {
                showToast("Orders ledger refreshed", "info");
            }
        });
    }
});

// Helper for formatting integer cents to dollar string with 2 decimals
function formatPriceDollars(priceCents) {
    if (typeof priceCents !== "number" || isNaN(priceCents)) {
        return "$0.00";
    }
    return `$${(priceCents / 100).toFixed(2)}`;
}

// Load merchant product catalog from GET /store/catalog
async function loadCatalog() {
    const container = document.getElementById("catalog-container");
    if (!container) return;

    try {
        const catalog = typeof IntentLockAPI !== "undefined" && IntentLockAPI.getStoreCatalog
            ? await IntentLockAPI.getStoreCatalog()
            : await (await fetch("/store/catalog")).json();

        // Clear existing children safely
        while (container.firstChild) {
            container.removeChild(container.firstChild);
        }

        if (!catalog || catalog.length === 0) {
            const emptyEl = document.createElement("div");
            emptyEl.textContent = "Catalog is currently empty.";
            emptyEl.style.color = "var(--text-muted)";
            emptyEl.style.fontSize = "0.85rem";
            container.appendChild(emptyEl);
            return;
        }

        catalog.forEach((product) => {
            const itemCard = document.createElement("div");
            itemCard.className = "card";
            itemCard.style.padding = "0.85rem 1rem";
            itemCard.style.display = "flex";
            itemCard.style.justifyContent = "space-between";
            itemCard.style.alignItems = "center";
            itemCard.style.border = "1px solid var(--border-subtle)";

            // Left column: item name and authentic payee account
            const left = document.createElement("div");
            
            // Real field name from GET /store/catalog: product.name (with fallback to product.item/product.id)
            const itemName = product.name || product.item || product.id || "Unknown Product";
            const nameEl = document.createElement("div");
            nameEl.className = "item-name";
            nameEl.style.fontWeight = "600";
            nameEl.style.color = "var(--text-primary)";
            nameEl.textContent = itemName;
            left.appendChild(nameEl);

            const payeeEl = document.createElement("div");
            payeeEl.className = "item-payee";
            payeeEl.style.fontSize = "0.75rem";
            payeeEl.style.color = "var(--text-muted)";
            payeeEl.textContent = `Payee: ${product.payee_id || "STORE-ACCT-001"}`;
            left.appendChild(payeeEl);

            // Right column: Price in dollars from integer cents / 100 formatted with 2 decimals
            const right = document.createElement("div");
            const cents = typeof product.price_cents === "number" 
                ? product.price_cents 
                : (typeof product.amount_cents === "number" ? product.amount_cents : 0);
            
            const priceBadge = document.createElement("span");
            priceBadge.className = "badge";
            priceBadge.style.fontSize = "0.85rem";
            priceBadge.style.background = "rgba(56, 189, 248, 0.15)";
            priceBadge.style.color = "var(--accent)";
            priceBadge.textContent = formatPriceDollars(cents);
            right.appendChild(priceBadge);

            itemCard.appendChild(left);
            itemCard.appendChild(right);
            container.appendChild(itemCard);
        });
    } catch (err) {
        container.textContent = "Error loading store catalog.";
    }
}

// Load completed store settlement orders safely using textContent
async function loadOrders() {
    const tbody = document.getElementById("orders-table-body");
    const statTotal = document.getElementById("stat-total-orders");
    const statProtected = document.getElementById("stat-protected-orders");
    const statUnprotected = document.getElementById("stat-unprotected-orders");

    if (!tbody) return;

    try {
        const orders = typeof IntentLockAPI !== "undefined" && IntentLockAPI.getStoreOrders
            ? await IntentLockAPI.getStoreOrders()
            : await (await fetch("/store/orders")).json();

        // Compute metrics
        if (statTotal) statTotal.textContent = orders.length.toString();
        const protCount = orders.filter((o) => o.endpoint === "protected").length;
        const unprotCount = orders.filter((o) => o.endpoint === "unprotected").length;
        if (statProtected) statProtected.textContent = protCount.toString();
        if (statUnprotected) statUnprotected.textContent = unprotCount.toString();

        while (tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
        }

        if (!orders || orders.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 5;
            td.style.textAlign = "center";
            td.style.color = "var(--text-muted)";
            td.style.padding = "2rem";
            td.textContent = "No orders recorded yet. Run a scenario in the Attack Demo.";
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        // Render newest orders first
        orders.slice().reverse().forEach((order) => {
            const tr = document.createElement("tr");

            // Col 1: Order ID - truncated with ellipsis, full ID in title for hover tooltip
            const idTd = document.createElement("td");
            idTd.className = "col-order-id cell-order-id";
            idTd.title = order.id;
            idTd.textContent = order.id;
            tr.appendChild(idTd);

            // Col 2: Item - keep on one line
            const itemTd = document.createElement("td");
            itemTd.className = "col-item cell-item";
            itemTd.textContent = order.item;
            tr.appendChild(itemTd);

            // Col 3: Amount - integer cents formatted in dollars with 2 decimals on one line
            const amtTd = document.createElement("td");
            amtTd.className = "col-amount cell-amount";
            amtTd.style.fontWeight = "600";
            const orderCents = typeof order.amount_cents === "number" ? order.amount_cents : 0;
            amtTd.textContent = formatPriceDollars(orderCents);
            tr.appendChild(amtTd);

            // Col 4: Payee Account with security alert tag if hijacked
            const payeeTd = document.createElement("td");
            payeeTd.className = "col-payee cell-payee";
            const isAttacker = order.payee_id && order.payee_id.includes("ATTACKER");
            
            const payeeBadge = document.createElement("span");
            payeeBadge.className = isAttacker ? "badge badge-blocked" : "badge badge-approved";
            payeeBadge.textContent = order.payee_id;
            payeeTd.appendChild(payeeBadge);

            if (isAttacker) {
                const warnTag = document.createElement("div");
                warnTag.style.fontSize = "0.7rem";
                warnTag.style.color = "var(--danger)";
                warnTag.style.fontWeight = "bold";
                warnTag.textContent = "🚨 Hijacked!";
                payeeTd.appendChild(warnTag);
            }
            tr.appendChild(payeeTd);

            // Col 5: Endpoint type - keep on one line
            const epTd = document.createElement("td");
            epTd.className = "col-endpoint cell-endpoint";
            const isProt = order.endpoint === "protected";
            const epBadge = document.createElement("span");
            epBadge.className = isProt ? "badge badge-protected" : "badge badge-unprotected";
            epBadge.textContent = isProt ? "🛡️ Protected" : "⚠️ Unprotected";
            epTd.appendChild(epBadge);
            tr.appendChild(epTd);

            tbody.appendChild(tr);
        });
    } catch (err) {
        tbody.textContent = "Error loading store orders.";
    }
}
