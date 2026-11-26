const TOKEN_KEY = "artex_token";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 days (seconds)

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo: no real login; return a fake token so the route guard allows going straight into the main UI.
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // Also write a cookie for the Next.js middleware to read server-side
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
  },

  // Parse the current user from the JWT payload's sub/role claims; display and
  // navigation only. The backend re-derives the role from its own record on
  // every request, so a tampered token cannot reach an admin API.
  getCurrentUser(): CurrentUser | null {
    const token = this.getToken();
    if (!token) return null;
    // Mock demo has no real JWT; show everything.
    if (token === "mock-demo") {
      return { id: "1", name: "ARTEX", username: "ARTEX", email: "", avatar: "", role: "admin" };
    }
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      // base64url → base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      const username: string = payload.sub ?? "ARTEX";
      // ARTEX is the bootstrap admin; otherwise trust the claim, defaulting to
      // the least-privileged role when it is missing or unexpected.
      const role: "admin" | "user" = username === "ARTEX" || payload.role === "admin" ? "admin" : "user";
      return { id: "1", name: username, username, email: "", avatar: "", role };
    } catch {
      return null;
    }
  },
};
