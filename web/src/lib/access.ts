// Role-based page access. The backend enforces the same boundary on the API
// (server/users.go adminGate); this gates navigation and route rendering so a
// non-admin never sees or lands on an admin-only page.
//
// Policy (confirmed with the operator): role "user" reaches every operator
// ("Functions") page plus the approval queue; role "admin" additionally reaches
// the System configuration pages and user management.

import type { NavGroup, NavMainItem } from "@/navigation/sidebar/sidebar-items";

export type Role = "admin" | "user";

// Pages only an admin may open, matched as a path prefix. Longest match wins, so
// an explicit user-allowed path under one of these (below) still opens.
const ADMIN_ONLY_PREFIXES = [
  "/system/llm",
  "/system/agents",
  "/system/mcp",
  "/system/skills",
  "/system/tools",
  "/system/notify",
  "/system/intercept", // global rules + asset interception
  "/system/logs",
  "/system/settings",
  "/system/users",
];

// Admin-prefixed paths that a "user" may still open. The approval queue lives
// under /system/intercept but is operator work.
const USER_ALLOWED = ["/system/intercept/approvals"];

function underPrefix(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(prefix + "/");
}

// canAccess reports whether role may open pathname.
export function canAccess(role: Role, pathname: string): boolean {
  if (role === "admin") return true;
  if (USER_ALLOWED.some((p) => underPrefix(pathname, p))) return true;
  return !ADMIN_ONLY_PREFIXES.some((p) => underPrefix(pathname, p));
}

// isAdminRole normalizes any stored role string to the admin boolean.
export function isAdmin(role: string | undefined): boolean {
  return role === "admin";
}

function itemVisible(role: Role, item: NavMainItem): boolean {
  if ("url" in item && item.url) return canAccess(role, item.url);
  return true;
}

// filterNavGroups drops nav entries the role cannot open, and any group left
// empty. Parent items keep only their accessible sub-items.
export function filterNavGroups(groups: readonly NavGroup[], role: Role): NavGroup[] {
  const out: NavGroup[] = [];
  for (const group of groups) {
    const items = group.items
      .map((item): NavMainItem | null => {
        if ("subItems" in item && item.subItems) {
          const subItems = item.subItems.filter((sub) => canAccess(role, sub.url));
          if (subItems.length === 0) return null;
          return { ...item, subItems };
        }
        return itemVisible(role, item) ? item : null;
      })
      .filter((item): item is NavMainItem => item !== null);
    if (items.length > 0) out.push({ ...group, items });
  }
  return out;
}
